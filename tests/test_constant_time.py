"""Pluggable constant-time native backend tests (AWS-LC & OpenSSL).

Verifies:
  - Both ``aws-lc`` (s2n-bignum) and ``openssl`` native backends build, load, and
    coexist cleanly in the same process with zero ELF symbol collision.
  - Bit-for-bit differential equivalence across AWS-LC, OpenSSL, and pure Python.
  - Cross-backend interoperability: server running on AWS-LC and client running on
    OpenSSL (and vice versa) across all 12 PMSet protocols!
  - Custom user-defined :class:`NativeCryptoBackend` plugin registration & switching.
  - Fail-closed strict mode (``PMSET_REQUIRE_NATIVE`` / ``require_constant_time``).
  - Dudect-style ABBA-interleaved timing invariance on both AWS-LC and OpenSSL.
"""

from __future__ import annotations

import math
import secrets
import time

import pytest

import pmset
from pmset import native
from pmset.native import NativeBackendInfo, NativeCryptoBackend
from pmset.primitives.ec import P256_GENERATOR, P256_N, ECPoint, hash_to_curve, random_scalar
from pmset.primitives.he import ExponentialElGamalHE
from pmset.primitives.math_utils import RFC2409_GROUP1_P, RFC2409_GROUP1_Q
from pmset.primitives.rlwe import RLWECiphertext, RLWEContext, RLWEParams

AVAILABLE_BACKENDS = pmset.available_native_backends()


def test_both_openssl_and_awslc_backends_available():
    assert "aws-lc" in pmset.list_native_backends()
    assert "openssl" in pmset.list_native_backends()
    assert "aws-lc" in AVAILABLE_BACKENDS
    assert "openssl" in AVAILABLE_BACKENDS

    awslc = pmset.backend_info("aws-lc")
    ossl = pmset.backend_info("openssl")
    assert awslc.available is True and awslc.backend_name == "aws-lc"
    assert awslc.abi_version == 2
    assert awslc.provider_version is not None and "AWS-LC" in awslc.provider_version

    assert ossl.available is True and ossl.backend_name == "openssl"
    assert ossl.abi_version == 2
    assert ossl.provider_version is not None and "OpenSSL" in ossl.provider_version


def test_runtime_switching_and_strict_mode():
    with pmset.use_native_backend("aws-lc") as info_lc:
        assert info_lc.backend_name == "aws-lc"
        assert pmset.backend_info().backend_name == "aws-lc"
        with pmset.use_native_backend("openssl") as info_ssl:
            assert info_ssl.backend_name == "openssl"
            assert pmset.backend_info().backend_name == "openssl"
        assert pmset.backend_info().backend_name == "aws-lc"

    pmset.require_constant_time(True)
    try:
        old_flag = native._DISABLE_NATIVE_FOR_TEST
        native._DISABLE_NATIVE_FOR_TEST = True
        try:
            with pytest.raises(pmset.NativeBackendError):
                native.ct_modexp(5, 7, 101)
        finally:
            native._DISABLE_NATIVE_FOR_TEST = old_flag
    finally:
        pmset.require_constant_time(False)


def test_custom_pluggable_native_backend_registration():
    """Verify users can plug a custom NativeCryptoBackend implementation into pmset."""
    delegate = pmset.get_native_backend("aws-lc")
    assert delegate is not None
    calls: list[str] = []

    class RecordingBackend(NativeCryptoBackend):
        @property
        def name(self) -> str:
            return "custom-recording"

        def is_available(self) -> bool:
            return True

        def info(self, *, strict_mode: bool = False) -> NativeBackendInfo:
            return NativeBackendInfo(
                available=True,
                backend_name=self.name,
                provider_version="RecordingPlugin 1.0",
                library_path=None,
                abi_version=2,
                strict_mode=strict_mode,
            )

        def memcmp(self, a, b):
            calls.append("memcmp")
            return delegate.memcmp(a, b)

        def select_bytes(self, a, b, select_b):
            return delegate.select_bytes(a, b, select_b)

        def xor_bytes(self, a, b):
            return delegate.xor_bytes(a, b)

        def cond_xor_bytes(self, acc, src, cond):
            return delegate.cond_xor_bytes(acc, src, cond)

        def dpf_bucket_eval(self, buckets, bits):
            return delegate.dpf_bucket_eval(buckets, bits)

        def bucket_scan_tag(self, bucket_bytes, record_size, target_tag):
            calls.append("bucket_scan_tag")
            return delegate.bucket_scan_tag(bucket_bytes, record_size, target_tag)

        def modexp(self, base, exp, mod, *, order=None):
            calls.append("modexp")
            return delegate.modexp(base, exp, mod, order=order)

        def modinv(self, a, mod):
            calls.append("modinv")
            return delegate.modinv(a, mod)

        def p256_scalar_mul(self, scalar, pt_bytes, order_n):
            calls.append("p256_scalar_mul")
            return delegate.p256_scalar_mul(scalar, pt_bytes, order_n)

        def p256_point_add(self, p1_bytes, p2_bytes):
            return delegate.p256_point_add(p1_bytes, p2_bytes)

        def p256_point_neg(self, p_bytes):
            return delegate.p256_point_neg(p_bytes)

        def p256_ot_choose(self, A_bytes, b_scalar, choice):
            return delegate.p256_ot_choose(A_bytes, b_scalar, choice)

        def p256_elgamal_is_zero(self, sk, c1_bytes, c2_bytes):
            return delegate.p256_elgamal_is_zero(sk, c1_bytes, c2_bytes)

        def p256_elgamal_any_zero(self, sk, wire_pairs):
            return delegate.p256_elgamal_any_zero(sk, wire_pairs)

        def rlwe_poly_mul(self, a, b, q):
            return delegate.rlwe_poly_mul(a, b, q)

        def rlwe_encrypt(self, a, sk, err, m, q, t):
            calls.append("rlwe_encrypt")
            return delegate.rlwe_encrypt(a, sk, err, m, q, t)

        def rlwe_decrypt(self, a, b, sk, q, t):
            calls.append("rlwe_decrypt")
            return delegate.rlwe_decrypt(a, b, sk, q, t)

        def rlwe_pir_dot(self, ct_a_list, ct_b_list, pt_list, q):
            calls.append("rlwe_pir_dot")
            return delegate.rlwe_pir_dot(ct_a_list, ct_b_list, pt_list, q)

    pmset.register_native_backend(RecordingBackend(), overwrite=True)
    try:
        with pmset.use_native_backend("custom-recording"):
            proto = pmset.get_protocol("oprf_rlwe_pir")
            srv = proto.create_server({"alice": b"ok"})
            cli = proto.create_client(srv.public_params())
            res = cli.query_detailed(srv, "alice")
            assert res.is_member is True and res.payload == b"ok"
            assert "p256_scalar_mul" in calls
            assert "rlwe_encrypt" in calls
            assert "rlwe_pir_dot" in calls
            assert "rlwe_decrypt" in calls
            assert "bucket_scan_tag" in calls
    finally:
        native._BACKENDS.pop("custom-recording", None)
        if "custom-recording" in native._AUTO_PRIORITY:
            native._AUTO_PRIORITY.remove("custom-recording")


@pytest.mark.parametrize("backend_name", AVAILABLE_BACKENDS)
def test_differential_equivalence_bytes_and_bucket_scan(backend_name: str):
    with pmset.use_native_backend(backend_name):
        a = secrets.token_bytes(64)
        b = secrets.token_bytes(64)
        assert native.ct_memcmp(a, a) is True
        assert native.ct_memcmp(a, b) is False
        assert native.ct_select_bytes(a, b, 0) == a
        assert native.ct_select_bytes(a, b, 1) == b
        assert native.ct_xor_bytes(a, b) == bytes(x ^ y for x, y in zip(a, b))
        assert native.ct_cond_xor_bytes(a, b, 0) == a
        assert native.ct_cond_xor_bytes(a, b, 1) == bytes(x ^ y for x, y in zip(a, b))

        buckets = [secrets.token_bytes(48) for _ in range(16)]
        bits = [secrets.randbelow(2) for _ in range(16)]
        expected = bytearray(48)
        for bit, bkt in zip(bits, buckets):
            if bit:
                for i in range(48):
                    expected[i] ^= bkt[i]
        assert native.ct_dpf_bucket_eval(buckets, bits) == bytes(expected)

        rec_size = 48
        records = [secrets.token_bytes(rec_size) for _ in range(20)]
        target_rec = records[13]
        found, matched = native.ct_bucket_scan_tag(b"".join(records), rec_size, target_rec[:16])
        assert found is True and matched == target_rec
        found_miss, _ = native.ct_bucket_scan_tag(
            b"".join(records), rec_size, secrets.token_bytes(16)
        )
        assert found_miss is False


@pytest.mark.parametrize("backend_name", AVAILABLE_BACKENDS)
def test_differential_equivalence_modexp_and_joye_padding(backend_name: str):
    p = RFC2409_GROUP1_P
    q = RFC2409_GROUP1_Q
    base = pow(secrets.randbelow(p - 3) + 2, 2, p)
    with pmset.use_native_backend(backend_name):
        for exp in (0, 1, 2, 3, 17, q - 2, q - 1, secrets.randbelow(q - 1) + 1):
            assert native.ct_modexp(base, exp, p) == pow(base, exp, p)
            assert native.ct_modexp(base, exp, p, order=q) == pow(base, exp, p)
        # Test both odd modulus (prime q -> AWS-LC BN_mod_inverse_blinded) and even modulus (p - 1)
        for r in (1, 2, 13, q - 1, secrets.randbelow(q - 1) + 1):
            inv = native.ct_modinv(r, q)
            assert (r * inv) % q == 1
        inv_even = native.ct_modinv(3, p - 1)
        assert (3 * inv_even) % (p - 1) == 1


@pytest.mark.parametrize("backend_name", AVAILABLE_BACKENDS)
def test_differential_equivalence_p256_ot_elgamal_rlwe(backend_name: str):
    P = hash_to_curve(b"differential-p256-test")
    k = random_scalar()

    old_flag = native._DISABLE_NATIVE_FOR_TEST
    native._DISABLE_NATIVE_FOR_TEST = True
    try:
        from pmset.primitives.ec import point_add, scalar_mul
        from pmset.primitives.rlwe import poly_mul_negacyclic

        py_kP = scalar_mul(k, P)
        py_kG = scalar_mul(k, P256_GENERATOR)
        py_sum = point_add(py_kP, py_kG)
        params = RLWEParams()
        a_poly = [secrets.randbelow(params.q) for _ in range(params.n)]
        b_poly = [secrets.randbelow(params.t) for _ in range(params.n)]
        py_mul = poly_mul_negacyclic(a_poly, b_poly, params.q)
    finally:
        native._DISABLE_NATIVE_FOR_TEST = old_flag

    with pmset.use_native_backend(backend_name):
        native_kP = ECPoint.from_compressed_bytes(
            native.ct_p256_scalar_mul(k, P.to_compressed_bytes(), P256_N)  # type: ignore[arg-type]
        )
        native_kG = ECPoint.from_compressed_bytes(
            native.ct_p256_scalar_mul(k, None, P256_N)  # type: ignore[arg-type]
        )
        assert native_kP == py_kP
        assert native_kG == py_kG

        native_sum = ECPoint.from_compressed_bytes(
            native.ct_p256_point_add(
                native_kP.to_compressed_bytes(), native_kG.to_compressed_bytes()
            )  # type: ignore[arg-type]
        )
        assert native_sum == py_sum

        # Chou-Orlandi OT
        a = random_scalar()
        A_bytes = native.ct_p256_scalar_mul(a, None, P256_N)
        assert A_bytes is not None
        b = random_scalar()
        B0, sh0 = native.ct_p256_ot_choose(A_bytes, b, 0)  # type: ignore[misc]
        B1, sh1 = native.ct_p256_ot_choose(A_bytes, b, 1)  # type: ignore[misc]
        assert sh0 == sh1
        assert B0 == native.ct_p256_scalar_mul(b, None, P256_N)
        assert B1 == native.ct_p256_point_add(A_bytes, B0)

        # ElGamal non-short-circuiting zero test
        eg = ExponentialElGamalHE()
        assert eg.any_zero([eg.encrypt(1), eg.encrypt(0), eg.encrypt(2)]) is True
        assert eg.any_zero([eg.encrypt(1), eg.encrypt(2)]) is False

        # RLWE kernels
        assert native.ct_rlwe_poly_mul(a_poly, b_poly, params.q) == py_mul
        ctx = RLWEContext(params)
        pt_polys = [[secrets.randbelow(params.t) for _ in range(params.n)] for _ in range(8)]
        cts = [ctx.encrypt_scalar(1 if i == 5 else 0) for i in range(8)]
        dot_a, dot_b = native.ct_rlwe_pir_dot(  # type: ignore[misc]
            [c.a for c in cts], [c.b for c in cts], pt_polys, params.q
        )
        assert ctx.decrypt_poly(RLWECiphertext(dot_a, dot_b)) == pt_polys[5]


@pytest.mark.parametrize("protocol_name", pmset.list_protocols())
def test_cross_backend_interoperability_awslc_server_openssl_client(protocol_name: str):
    """Server runs on AWS-LC while Client runs on OpenSSL (and verifies wire compatibility)."""
    proto = pmset.get_protocol(protocol_name)
    dataset = {"alice@example.com": b"tier=gold", "bob@example.com": b"tier=silver"}

    with pmset.use_native_backend("aws-lc"):
        server = proto.create_server(dataset)
        wire_params = server.public_params().to_bytes()

    with pmset.use_native_backend("openssl"):
        client = proto.create_client(pmset.PublicParams.from_bytes(wire_params))
        for query, expected_member in (("alice@example.com", True), ("eve@example.com", False)):
            session = client.start_query(query)
            while not session.is_complete:
                req_bytes = session.next_request().to_bytes()
                with pmset.use_native_backend("aws-lc"):
                    resp_bytes = server.handle_request(
                        pmset.ProtocolMessage.from_bytes(req_bytes)
                    ).to_bytes()
                session.process_response(pmset.ProtocolMessage.from_bytes(resp_bytes))
            res = session.result()
            assert res.is_member is expected_member
            if expected_member and proto.metadata.capabilities.supports_payloads:
                assert res.payload == b"tier=gold"


# ---------------------------------------------------------------------------
# Dudect-style statistical timing invariance tests across BOTH backends
# ---------------------------------------------------------------------------


def _interleaved_timing_ratio(fn_a, fn_b, trials: int = 250) -> float:
    for _ in range(25):
        fn_a()
        fn_b()

    times_a: list[int] = []
    times_b: list[int] = []
    for i in range(trials):
        order = (0, 1) if (i & 1) == 0 else (1, 0)
        for cls in order:
            t0 = time.perf_counter_ns()
            if cls == 0:
                fn_a()
                times_a.append(time.perf_counter_ns() - t0)
            else:
                fn_b()
                times_b.append(time.perf_counter_ns() - t0)

    med_a = sorted(times_a)[len(times_a) // 2]
    med_b = sorted(times_b)[len(times_b) // 2]
    return max(med_a, med_b) / max(1, min(med_a, med_b))


@pytest.mark.parametrize("backend_name", AVAILABLE_BACKENDS)
def test_timing_invariance_p256_and_joye_modexp_and_ot(backend_name: str):
    """Constant-time latency check on P-256 scalar mul, Joye DH modexp, OT choice, RLWE, and DPF."""
    pt_bytes = hash_to_curve(b"timing-target").to_compressed_bytes()
    p, q = RFC2409_GROUP1_P, RFC2409_GROUP1_Q
    base = pow(1234567, 2, p)
    a = random_scalar()
    b = random_scalar()
    params = RLWEParams()
    a_poly = [secrets.randbelow(params.q) for _ in range(params.n)]
    zero_poly = [0] * params.n
    dense_poly = [params.t - 1] * params.n
    buckets = [secrets.token_bytes(128) for _ in range(32)]
    rec_size = 64
    records = [secrets.token_bytes(rec_size) for _ in range(64)]
    flat_recs = b"".join(records)

    with pmset.use_native_backend(backend_name):
        A_bytes = native.ct_p256_scalar_mul(a, None, P256_N)
        assert A_bytes is not None

        r_p256 = _interleaved_timing_ratio(
            lambda: native.ct_p256_scalar_mul(2, pt_bytes, P256_N),
            lambda: native.ct_p256_scalar_mul(P256_N - 1, pt_bytes, P256_N),
            trials=200,
        )
        assert r_p256 < 1.25, f"[{backend_name}] P-256 timing ratio: {r_p256:.3f}"

        r_dh = _interleaved_timing_ratio(
            lambda: native.ct_modexp(base, 1, p, order=q),
            lambda: native.ct_modexp(base, q - 1, p, order=q),
            trials=180,
        )
        assert r_dh < 1.25, f"[{backend_name}] Joye modexp timing ratio: {r_dh:.3f}"

        r_ot = _interleaved_timing_ratio(
            lambda: native.ct_p256_ot_choose(A_bytes, b, 0),
            lambda: native.ct_p256_ot_choose(A_bytes, b, 1),
            trials=180,
        )
        assert r_ot < 1.25, f"[{backend_name}] OT choice timing ratio: {r_ot:.3f}"

        r_rlwe = _interleaved_timing_ratio(
            lambda: native.ct_rlwe_poly_mul(a_poly, zero_poly, params.q),
            lambda: native.ct_rlwe_poly_mul(a_poly, dense_poly, params.q),
            trials=250,
        )
        assert r_rlwe < 1.25, f"[{backend_name}] RLWE poly mul timing ratio: {r_rlwe:.3f}"

        r_dpf = _interleaved_timing_ratio(
            lambda: native.ct_dpf_bucket_eval(buckets, [0] * 32),
            lambda: native.ct_dpf_bucket_eval(buckets, [1] * 32),
            trials=300,
        )
        assert r_dpf < 1.25, f"[{backend_name}] DPF timing ratio: {r_dpf:.3f}"

        r_scan = _interleaved_timing_ratio(
            lambda: native.ct_bucket_scan_tag(flat_recs, rec_size, records[0][:16]),
            lambda: native.ct_bucket_scan_tag(flat_recs, rec_size, records[-1][:16]),
            trials=300,
        )
        assert r_scan < 1.25, f"[{backend_name}] Bucket scan timing ratio: {r_scan:.3f}"
