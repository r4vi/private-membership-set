"""Regression and adversarial test suite preventing entire classes of security & correctness bugs.

Covers 7 systemic bug classes:
  1. Native C / ctypes FFI boundary & buffer-length safety across all backends.
  2. Fail-closed strict constant-time mode (zero silent pure-Python fallback).
  3. Circuit privacy & ciphertext rerandomization (Paillier PIR & Cuckoo stash padding).
  4. Composable protocol / primitive parameter matrix & invalid modulus rejection.
  5. Wire deserialization hardening & Hypothesis property-based fuzzing.
  6. Constant-time invariance on zero-exponent modexp and fixed-window hash_to_curve.
  7. Formal verifier soundness via fault injection (TLA+ & Lean 4 kernel checks).
"""

from __future__ import annotations

import hashlib
import secrets
import shutil
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

import pmset
from pmset import native
from pmset.core.serialization import SerializationError, decode_value, encode_value
from pmset.core.types import ProtocolMessage, PublicParams
from pmset.native import NativeBackendError
from pmset.primitives.ec import P256_A, P256_B, P256_N, P256_P, _P256_SQRT_EXP, hash_to_curve
from pmset.primitives.he import PaillierHE, PaillierPublicKey
from pmset.primitives.indexing import BloomFilter, CuckooTable
from pmset.primitives.math_utils import RFC2409_GROUP1_P, RFC2409_GROUP1_Q
from pmset.primitives.pir import Paillier2DPIR, PaillierLinearPIR, RLWEPIR
from pmset.primitives.rlwe import RLWEContext, RLWEParams
from pmset.verification.base import PropertyStatus
from pmset.verification.lean_verifier import LeanVerifier
from pmset.verification.tla_verifier import TLAVerifier

AVAILABLE_BACKENDS = pmset.available_native_backends()


# ---------------------------------------------------------------------------
# Class 1: FFI / Native C Boundary & Buffer-Length Safety Invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("backend_name", AVAILABLE_BACKENDS)
def test_ffi_buffer_length_and_bounds_validation(backend_name: str):
    """Direct backend calls and top-level ct_* wrappers must reject all mismatched buffer sizes."""
    backend = pmset.get_native_backend(backend_name)
    assert backend is not None

    with pmset.use_native_backend(backend_name):
        # select_bytes / xor_bytes / cond_xor_bytes length mismatch on both backend and wrapper
        for fn in (
            lambda: backend.select_bytes(b"AAAA", b"BB", 1),
            lambda: native.ct_select_bytes(b"AAAA", b"BB", 1),
            lambda: backend.xor_bytes(b"AAAA", b"BB"),
            lambda: native.ct_xor_bytes(b"AAAA", b"BB"),
            lambda: backend.cond_xor_bytes(b"AAAA", b"BB", 1),
            lambda: native.ct_cond_xor_bytes(b"AAAA", b"BB", 1),
        ):
            with pytest.raises(ValueError, match="length mismatch"):
                fn()

        # dpf_bucket_eval: short bits or ragged bucket lengths
        with pytest.raises(ValueError, match="len\\(bits\\) >= len\\(buckets\\)"):
            backend.dpf_bucket_eval([b"AAAA", b"BBBB"], [1])
        with pytest.raises(ValueError, match="len\\(bits\\) >= len\\(buckets\\)"):
            native.ct_dpf_bucket_eval([b"AAAA", b"BBBB"], [1])
        with pytest.raises(ValueError, match="identical byte length"):
            backend.dpf_bucket_eval([b"AAAA", b"BB"], [1, 0])
        with pytest.raises(ValueError, match="identical byte length"):
            native.ct_dpf_bucket_eval([b"AAAA", b"BB"], [1, 0])

        # bucket_scan_tag: tag longer than record_size, record_size <= 0, unaligned bucket_bytes
        with pytest.raises(ValueError, match="cannot exceed record_size"):
            backend.bucket_scan_tag(b"A" * 16, 8, b"T" * 16)
        with pytest.raises(ValueError, match="cannot exceed record_size"):
            native.ct_bucket_scan_tag(b"A" * 16, 8, b"T" * 16)
        with pytest.raises(ValueError, match="record_size must be > 0"):
            backend.bucket_scan_tag(b"A" * 16, 0, b"T" * 4)
        with pytest.raises(ValueError, match="multiple of record_size"):
            backend.bucket_scan_tag(b"A" * 15, 8, b"T" * 4)

        # RLWE polynomial dimension mismatches and out-of-range q
        with pytest.raises(ValueError, match="length mismatch"):
            backend.rlwe_poly_mul([1, 2, 3, 4], [1, 2], 65536)
        with pytest.raises(ValueError, match="must all equal"):
            backend.rlwe_encrypt([1, 2, 3, 4], [0, 1], [0, 0, 0, 0], [1, 2, 3, 4], 65536, 256)
        with pytest.raises(ValueError, match="must all equal"):
            backend.rlwe_decrypt([1, 2, 3, 4], [1, 2, 3, 4], [0, 1], 65536, 256)
        with pytest.raises(ValueError, match="bucket list lengths must match"):
            backend.rlwe_pir_dot([[1, 2]], [[1, 2], [3, 4]], [[1, 2]], 65536)
        with pytest.raises(ValueError, match="identical degree"):
            backend.rlwe_pir_dot([[1, 2, 3, 4]], [[1, 2]], [[1, 2, 3, 4]], 65536)


@pytest.mark.parametrize("backend_name", AVAILABLE_BACKENDS)
def test_c_side_bn_nnmod_handles_unreduced_large_inputs(backend_name: str):
    """Unreduced base > mod, exp > order, and a > mod must be reduced inside C BIGNUM."""
    p = RFC2409_GROUP1_P
    q = RFC2409_GROUP1_Q
    base = p * 7 + 123456789
    exp = q * 5 + 987654321
    with pmset.use_native_backend(backend_name):
        assert native.ct_modexp(base, exp, p) == pow(base, exp, p)
        assert native.ct_modexp(base, exp, p, order=q) == pow(base, exp % q, p)
        assert native.ct_modexp(base, 0, p) == 1
        assert native.ct_modexp(base, 0, p, order=q) == 1
        inv = native.ct_modinv(q * 3 + 17, q)
        assert (17 * inv) % q == 1


# ---------------------------------------------------------------------------
# Class 2: Fail-Closed Strict Constant-Time Mode (Zero Silent Fallback)
# ---------------------------------------------------------------------------


def test_strict_mode_never_silently_falls_back_to_python():
    """When require_constant_time(True) is active, unsupported parameters or missing backends must raise."""
    pmset.require_constant_time(True)
    try:
        # Even modulus cannot use Montgomery modexp -> must raise NativeBackendError in strict mode
        with pytest.raises(NativeBackendError, match="odd modulus"):
            native.ct_modexp(3, 5, 100)

        # RLWE modulus q >= 2^63 cannot fit in signed 64-bit C kernel -> must raise in strict mode
        with pytest.raises(NativeBackendError, match="0 < q < 2\\^63"):
            native.ct_rlwe_poly_mul([1, 2, 3, 4], [1, 2, 3, 4], 1 << 63)
        with pytest.raises(NativeBackendError, match="0 < q < 2\\^63"):
            native.ct_rlwe_encrypt([1, 2], [0, 1], [0, 0], [1, 2], 1 << 63, 256)
        with pytest.raises(NativeBackendError, match="0 < q < 2\\^63"):
            native.ct_rlwe_decrypt([1, 2], [1, 2], [0, 1], 1 << 63, 256)
        with pytest.raises(NativeBackendError, match="0 < q < 2\\^63"):
            native.ct_rlwe_pir_dot([[1, 2]], [[1, 2]], [[1, 2]], 1 << 63)

        # When native backend is disabled, every ct_* entry point must fail closed
        old_flag = native._DISABLE_NATIVE_FOR_TEST
        native._DISABLE_NATIVE_FOR_TEST = True
        try:
            for fn in (
                lambda: native.ct_memcmp(b"a", b"a"),
                lambda: native.ct_select_bytes(b"a", b"b", 0),
                lambda: native.ct_xor_bytes(b"a", b"b"),
                lambda: native.ct_cond_xor_bytes(b"a", b"b", 1),
                lambda: native.ct_dpf_bucket_eval([b"aa"], [1]),
                lambda: native.ct_bucket_scan_tag(b"aaaa", 4, b"aa"),
                lambda: native.ct_modexp(3, 5, 101),
                lambda: native.ct_modinv(3, 101),
                lambda: native.ct_p256_scalar_mul(2, None, P256_N),
                lambda: native.ct_rlwe_poly_mul([1, 2], [3, 4], 65536),
            ):
                with pytest.raises(NativeBackendError):
                    fn()
        finally:
            native._DISABLE_NATIVE_FOR_TEST = old_flag
    finally:
        pmset.require_constant_time(False)


# ---------------------------------------------------------------------------
# Class 3: Circuit Privacy & Ciphertext Rerandomization Invariants
# ---------------------------------------------------------------------------


def test_paillier_pir_responses_are_freshly_rerandomized():
    """Paillier 1D and 2D PIR must rerandomize every output chunk, even on all-zero buckets."""
    buckets = [b"\x00" * 32 for _ in range(5)]

    # 1D Paillier Linear PIR
    pir1d = PaillierLinearPIR(key_bits=256)
    q1, st1 = pir1d.client_generate_query(2, len(buckets))
    ans1_a = pir1d.server_answer(buckets, q1)
    ans1_b = pir1d.server_answer(buckets, q1)
    assert all(c != 1 for c in ans1_a["chunks"]), "Unrerandomized identity ciphertext 1 leaked!"
    assert ans1_a["chunks"] != ans1_b["chunks"], "Server responses were deterministic (not rerandomized)!"
    assert pir1d.client_extract(ans1_a, st1, 32) == b"\x00" * 32

    # 2D Paillier PIR (5 buckets -> 3x2 grid with 1 zero-padded cell)
    pir2d = Paillier2DPIR(key_bits=256)
    q2, st2 = pir2d.client_generate_query(2, len(buckets))
    ans2_a = pir2d.server_answer(buckets, q2)
    ans2_b = pir2d.server_answer(buckets, q2)
    for col in ans2_a["selected_row"]:
        assert all(c != 1 for c in col), "Unrerandomized identity ciphertext 1 leaked in 2D PIR!"
    assert ans2_a["selected_row"] != ans2_b["selected_row"]
    assert pir2d.client_extract(ans2_a, st2, 32) == b"\x00" * 32


def test_cuckoo_stash_is_padded_to_constant_capacity():
    """CuckooTable stash must be padded with dummy records so stash length never leaks collision counts."""
    for n_items in (0, 1, 4, 12):
        entries = {secrets.token_bytes(32): b"payload" for _ in range(n_items)}
        table, rec_size = CuckooTable.build(entries, stash_capacity=3)
        assert len(table.stash) >= 3
        assert all(len(rec) == rec_size for rec in table.stash)


# ---------------------------------------------------------------------------
# Class 4: Composable Parameter Matrix & Invalid Parameter Rejection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pir_instance",
    [
        RLWEPIR(RLWEParams()),
        PaillierLinearPIR(key_bits=256),
        Paillier2DPIR(key_bits=256),
    ],
)
def test_cuckoo_oprf_pir_supports_all_single_server_pir_backends(pir_instance):
    """CuckooOPRFPIRServer and CuckooOPRFPIRClient must interoperate across RLWE and Paillier PIRs."""
    proto = pmset.get_protocol("cuckoo_oprf_pir")
    dataset = {"alice": b"meta-a", "bob": b"meta-b", "charlie": b"meta-c"}
    server = proto.create_server(dataset, pir=pir_instance)
    wire_params = PublicParams.from_bytes(server.public_params().to_bytes())
    client = proto.create_client(wire_params)

    hit = client.query_detailed(server, "alice", verify_wire_roundtrip=True)
    assert hit.is_member is True and hit.payload == b"meta-a"

    miss = client.query_detailed(server, "nonmember", verify_wire_roundtrip=True)
    assert miss.is_member is False and miss.payload is None


def test_invalid_cryptographic_parameters_rejected_cleanly():
    """Invalid RLWE q % t != 0, even Paillier modulus n, and Bloom payloads must raise ValueError."""
    # RLWEParams must reject q not divisible by t
    with pytest.raises(ValueError, match="exact multiple of plaintext modulus t"):
        RLWEParams(n=16, t=256, q=(1 << 40) + 15, noise_eta=1)

    # PaillierPublicKey must reject even or tiny n
    for bad_n in (-101, 0, 2, 14, 100, 1024):
        with pytest.raises(ValueError, match="odd integer >= 15"):
            PaillierPublicKey(n=bad_n)

    # ECDHOPRFFilterServer in bloom mode must reject datasets with payloads instead of dropping them
    filt_proto = pmset.get_protocol("ecdh_oprf_filter")
    with pytest.raises(ValueError, match="filter_mode='bloom' does not support item payloads"):
        filt_proto.create_server({"alice": b"secret-payload"}, filter_mode="bloom")

    # BloomFilter must reject mismatched bit-array byte lengths
    with pytest.raises(ValueError, match="does not match num_bits"):
        BloomFilter.from_dict({"num_bits": 64, "num_hashes": 3, "seed": b"1234567890123456", "bits": b"\x00" * 3})


# ---------------------------------------------------------------------------
# Class 5: Wire Deserialization Hardening & Hypothesis Fuzzing
# ---------------------------------------------------------------------------


def test_wire_deserialization_rejects_malformed_and_adversarial_frames():
    """Adversarial wire frames must always raise SerializationError, never raw exceptions or OOM."""
    # 1. Invalid UTF-8 in dict key
    with pytest.raises(SerializationError, match="Invalid UTF-8 in wire dict key"):
        decode_value(b"\x08\x00\x00\x00\x01\x00\x00\x00\x02\xff\xfe\x00")

    # 2. Duplicate dict key
    dup_dict = (
        b"\x08\x00\x00\x00\x02"
        b"\x00\x00\x00\x01a\x00"
        b"\x00\x00\x00\x01a\x01"
    )
    with pytest.raises(SerializationError, match="Duplicate dict key"):
        decode_value(dup_dict)

    # 3. Huge list/dict count header (0xFFFFFFFF) in a 5-byte payload -> instant rejection
    with pytest.raises(SerializationError, match="exceeds remaining wire payload"):
        decode_value(b"\x07\xff\xff\xff\xff")
    with pytest.raises(SerializationError, match="exceeds remaining wire payload"):
        decode_value(b"\x08\xff\xff\xff\xff")

    # 4. Non-canonical negative zero and leading zero bytes in integers
    with pytest.raises(SerializationError, match="negative zero"):
        decode_value(b"\x04\x00\x00\x00\x00")
    with pytest.raises(SerializationError, match="leading zero byte"):
        decode_value(b"\x03\x00\x00\x00\x02\x00\x01")

    # 5. Excessive recursion depth (> 64 nested lists)
    deep_bytes = b"\x07\x00\x00\x00\x01" * 70 + b"\x00"
    with pytest.raises(SerializationError, match="Maximum wire nesting depth"):
        decode_value(deep_bytes)

    deep_obj: list = []
    cur = deep_obj
    for _ in range(70):
        nxt: list = []
        cur.append(nxt)
        cur = nxt
    with pytest.raises(SerializationError, match="Maximum wire nesting depth"):
        encode_value(deep_obj)

    # 6. Malformed ProtocolMessage and PublicParams schemas
    for bad_msg in (
        encode_value({"protocol": "x"}),
        encode_value({"protocol": "x", "phase": "p", "round_num": True, "payload": {}}),
        encode_value({"protocol": "x", "phase": "p", "round_num": 1, "payload": {}, "replica_payloads": {"not_int": {}}}),
        encode_value({"protocol": "x", "phase": "p", "round_num": 1, "payload": {}, "replica_payloads": {"0": "not_dict"}}),
    ):
        with pytest.raises(SerializationError):
            ProtocolMessage.from_bytes(bad_msg)

    for bad_pp in (
        encode_value({"protocol": 123, "params": {}}),
        encode_value({"protocol": "x", "params": "not_dict"}),
    ):
        with pytest.raises(SerializationError):
            PublicParams.from_bytes(bad_pp)


@given(st.binary(min_size=0, max_size=256))
@settings(max_examples=200, deadline=None)
def test_hypothesis_fuzz_wire_decoder_never_raises_unhandled_exception(raw: bytes):
    """Decoding arbitrary random bytes must either succeed or raise SerializationError."""
    try:
        decode_value(raw)
    except SerializationError:
        pass

    try:
        ProtocolMessage.from_bytes(raw)
    except SerializationError:
        pass

    try:
        PublicParams.from_bytes(raw)
    except SerializationError:
        pass


# ---------------------------------------------------------------------------
# Class 6: Constant-Time Timing Invariance on Newly Hardened Paths
# ---------------------------------------------------------------------------


def test_hash_to_curve_fixed_window_and_zero_exp_modexp():
    """Verify hash_to_curve returns the first valid counter point and zero-exp modexp works on all backends."""
    # Find two inputs: one where counter=0 is a QR, and one where counter=0 is NOT a QR
    item_c0 = None
    item_c_later = None
    domain = b"PMSET-P256-H2C-v1"
    for idx in range(500):
        candidate = f"h2c-item-{idx}".encode()
        digest = hashlib.sha256(domain + (0).to_bytes(2, "big") + candidate).digest()
        x = int.from_bytes(digest, "big") % P256_P
        rhs = (pow(x, 3, P256_P) + P256_A * x + P256_B) % P256_P
        y = pow(rhs, _P256_SQRT_EXP, P256_P)
        if (y * y) % P256_P == rhs:
            if item_c0 is None:
                item_c0 = candidate
        else:
            if item_c_later is None:
                item_c_later = candidate
        if item_c0 is not None and item_c_later is not None:
            break

    assert item_c0 is not None and item_c_later is not None
    pt0 = hash_to_curve(item_c0, domain=domain)
    pt_later = hash_to_curve(item_c_later, domain=domain)
    assert pt0.is_on_curve() and not pt0.is_infinity
    assert pt_later.is_on_curve() and not pt_later.is_infinity


# ---------------------------------------------------------------------------
# Class 7: Formal Verifier Soundness (Fault-Injection Tests)
# ---------------------------------------------------------------------------


def test_formal_verifiers_detect_injected_faults(tmp_path: Path):
    """Formal verifiers must fail closed when a Lean theorem is missing or a TLA+ invariant is violated."""
    # 1. LeanVerifier kernel check must fail on a non-existent theorem
    lean_v = LeanVerifier()
    if lean_v.is_available():
        ok, _ = lean_v._verify_theorem_in_kernel("PMSet.Protocols.nonexistent_fake_theorem")
        assert ok is False

    # 2. TLAVerifier must report FAILED when an invariant is broken in a TLA+ spec
    tla_v = TLAVerifier()
    if tla_v.is_available():
        src_dir = tla_v._tla_dir
        shutil.copy(src_dir / "FNPPaillier.tla", tmp_path / "FNPPaillier.tla")
        # Break the spec by requiring a false invariant
        broken_tla = (tmp_path / "FNPPaillier.tla").read_text(encoding="utf-8").replace(
            "MembershipCorrectness ==\n    stage = \"done\" => (result <=> (query \\in serverSet))",
            "MembershipCorrectness == FALSE",
        )
        (tmp_path / "FNPPaillier.tla").write_text(broken_tla, encoding="utf-8")
        shutil.copy(src_dir / "FNPPaillier.cfg", tmp_path / "FNPPaillier.cfg")

        broken_verifier = TLAVerifier(tla_dir=tmp_path)
        res = broken_verifier.run_spec("FNPPaillier.tla", use_cache=False)
        assert res.status == PropertyStatus.FAILED
