"""Unit and algebraic tests for all pmset cryptographic primitives."""

from __future__ import annotations

import secrets
import pytest

from pmset.core.serialization import SerializationError, decode_value, encode_value
from pmset.primitives.aead import DecryptionError, aead_decrypt, aead_encrypt
from pmset.primitives.ec import (
    P256_GENERATOR,
    P256_INFINITY,
    P256_N,
    ECPoint,
    hash_to_curve,
    point_add,
    random_scalar,
    scalar_mul,
)
from pmset.primitives.he import ExponentialElGamalHE, PaillierHE
from pmset.primitives.indexing import (
    BloomFilter,
    CuckooTable,
    GarbledBloomFilter,
    ModuloBucketizer,
    PrefixBucketizer,
)
from pmset.primitives.math_utils import (
    RFC2409_GROUP1_P,
    RFC3526_GROUP14_P,
    eval_polynomial,
    is_prime,
    is_safe_prime,
    polynomial_from_roots,
    shamir_reconstruct,
    shamir_share,
)
from pmset.primitives.oprf import DHOPRF, ECDHOPRF, RSAOPRF
from pmset.primitives.ot import ChouOrlandiOT, ChouOrlandiSenderKey
from pmset.primitives.pir import (
    Paillier2DPIR,
    PaillierLinearPIR,
    RLWEPIR,
    ShamirMultiServerPIR,
    TwoServerDPFPIR,
    dpf_eval_full,
    dpf_gen,
)
from pmset.primitives.rlwe import RLWEContext, RLWEParams


def test_canonical_wire_serialization_roundtrip():
    obj = {
        "none": None,
        "t": True,
        "f": False,
        "zero": 0,
        "neg": -98765432101234567890,
        "big": (1 << 2048) - 159,
        "bytes": b"\x00\x01\xffhello",
        "str": "unicode-λ-π-🔐",
        "nested": [1, {"k": [b"ab", "cd"]}],
    }
    encoded = encode_value(obj)
    assert decode_value(encoded) == obj
    with pytest.raises(SerializationError):
        decode_value(encoded + b"\x00")
    with pytest.raises(SerializationError):
        decode_value(b"\xff")


def test_primality_and_safe_primes():
    for carmichael in (561, 1105, 1729, 2465, 2821, 6601, 8911):
        assert is_prime(carmichael) is False
    assert is_safe_prime(RFC2409_GROUP1_P) is True
    assert is_safe_prime(RFC3526_GROUP14_P) is True
    assert is_safe_prime(15) is False


def test_p256_elliptic_curve_group_laws():
    assert P256_GENERATOR.is_on_curve()
    assert scalar_mul(P256_N, P256_GENERATOR).is_infinity
    a = random_scalar()
    b = random_scalar()
    P = hash_to_curve(b"alice@example.com")
    assert P.is_on_curve()
    # Commutativity of scalar action: a*(b*P) == b*(a*P)
    assert scalar_mul(a, scalar_mul(b, P)) == scalar_mul(b, scalar_mul(a, P))
    # Distributivity: (a + b)*P == a*P + b*P
    assert scalar_mul((a + b) % P256_N, P) == point_add(scalar_mul(a, P), scalar_mul(b, P))
    # SEC1 compressed serialization round-trip
    raw = P.to_compressed_bytes()
    assert len(raw) == 33
    assert ECPoint.from_compressed_bytes(raw) == P
    with pytest.raises(ValueError):
        ECPoint.from_compressed_bytes(b"\x04" + b"\x00" * 32)


def test_aead_roundtrip_and_tamper_detection():
    key = secrets.token_bytes(32)
    ct = aead_encrypt(key, b"secret payload", aad=b"tag-123")
    assert aead_decrypt(key, ct, aad=b"tag-123") == b"secret payload"
    with pytest.raises(DecryptionError):
        aead_decrypt(key, ct, aad=b"wrong-aad")
    tampered = bytearray(ct)
    tampered[-1] ^= 0x01
    with pytest.raises(DecryptionError):
        aead_decrypt(key, bytes(tampered), aad=b"tag-123")


@pytest.mark.parametrize("oprf", [ECDHOPRF(), DHOPRF(), RSAOPRF(bits=512)])
def test_all_oprf_constructions(oprf):
    key = oprf.keygen()
    client_oprf = oprf.from_public_params(oprf.public_params())
    for item in (b"alice", b"bob", b""):
        b1, st1 = client_oprf.client_blind(item)
        b2, st2 = client_oprf.client_blind(item)
        assert b1 != b2  # randomized blinding
        e1 = oprf.server_evaluate(b1, key)
        e2 = oprf.server_evaluate(b2, key)
        out1 = client_oprf.client_finalize(item, e1, st1)
        out2 = client_oprf.client_finalize(item, e2, st2)
        direct = oprf.server_evaluate_direct(item, key)
        assert out1 == out2 == direct
        assert len(out1) == 32


def test_paillier_and_exponential_elgamal_he():
    paillier = PaillierHE(bits=512)
    c1 = paillier.encrypt(42)
    c2 = paillier.encrypt(100)
    assert paillier.decrypt(paillier.add(c1, c2)) == 142
    assert paillier.decrypt(paillier.mul_scalar(c1, 7)) == 294
    assert paillier.decrypt(paillier.rerandomize(c1)) == 42

    eg = ExponentialElGamalHE()
    ct = eg.encrypt(12345)
    zero_ct = eg.public_key.rerandomize(eg.public_key.mul_scalar(eg.public_key.sub_plaintext(ct, 12345), 99))
    nonzero_ct = eg.public_key.rerandomize(eg.public_key.mul_scalar(eg.public_key.sub_plaintext(ct, 12346), 99))
    assert eg.is_zero(zero_ct) is True
    assert eg.is_zero(nonzero_ct) is False


def test_rlwe_encryption_packing_and_noise_budget():
    params = RLWEParams()
    assert params.can_decrypt_exact(num_buckets=256)
    assert params.noise_budget_bits(num_buckets=64) > 20.0

    ctx = RLWEContext(params)
    msg = secrets.token_bytes(100)
    polys = ctx.encode_bytes_to_polys(msg)
    cts = [ctx.encrypt_poly(p) for p in polys]
    dec_polys = [ctx.decrypt_poly(c) for c in cts]
    assert ctx.decode_polys_to_bytes(dec_polys, len(msg)) == msg


@pytest.mark.parametrize(
    "pir",
    [PaillierLinearPIR(key_bits=512), Paillier2DPIR(key_bits=512), RLWEPIR()],
)
def test_single_server_pir_primitives(pir):
    buckets = [secrets.token_bytes(48) for _ in range(9)]
    for target in (0, 4, 8):
        q, st = pir.client_generate_query(target, len(buckets))
        resp = pir.server_answer(buckets, q)
        recovered = pir.client_extract(resp, st, len(buckets[0]))
        assert recovered == buckets[target]


def test_bgi15_dpf_point_function_and_two_server_pir():
    depth = 5  # 32 buckets
    for alpha in (0, 1, 17, 31):
        k0, k1 = dpf_gen(alpha, depth)
        v0 = dpf_eval_full(k0)
        v1 = dpf_eval_full(k1)
        assert [a ^ b for a, b in zip(v0, v1)] == [1 if i == alpha else 0 for i in range(1 << depth)]

    pir = TwoServerDPFPIR()
    buckets = [secrets.token_bytes(64) for _ in range(13)]
    for target in (0, 6, 12):
        queries, st = pir.client_generate_queries(target, len(buckets))
        resps = {sid: pir.server_answer(sid, buckets, queries[sid]) for sid in (0, 1)}
        assert pir.client_combine(resps, st, len(buckets[0])) == buckets[target]


@pytest.mark.parametrize("k,t", [(2, 1), (3, 1), (5, 2)])
def test_shamir_multiserver_it_pir(k, t):
    pir = ShamirMultiServerPIR(num_servers=k, privacy_threshold=t)
    buckets = [secrets.token_bytes(50) for _ in range(7)]
    for target in (0, 3, 6):
        queries, st = pir.client_generate_queries(target, len(buckets))
        resps = {sid: pir.server_answer(sid, buckets, queries[sid]) for sid in range(k)}
        assert pir.client_combine(resps, st, len(buckets[0])) == buckets[target]


def test_chou_orlandi_1_out_of_2_ot():
    sk = ChouOrlandiSenderKey.generate()
    sender = ChouOrlandiOT(sk.A, sender_secret_a=sk.a)
    receiver = ChouOrlandiOT(sk.A)

    choices = [0, 1, 1, 0, 1, 0]
    pairs = [(secrets.token_bytes(16), secrets.token_bytes(16)) for _ in choices]
    wire_B, keys = receiver.receiver_choose(choices)
    enc = sender.sender_respond(wire_B, pairs)
    got = receiver.receiver_decrypt(choices, keys, enc)
    assert got == [p[c] for p, c in zip(pairs, choices)]


def test_polynomial_and_shamir_math():
    p = 1000003
    roots = [5, 19, 42, 999]
    coeffs = polynomial_from_roots(roots, p)
    for r in roots:
        assert eval_polynomial(coeffs, r, p) == 0
    assert eval_polynomial(coeffs, 7, p) != 0

    shares = shamir_share(123456, num_shares=5, threshold=3, prime=p)
    assert shamir_reconstruct(shares[:3], p) == 123456
    assert shamir_reconstruct(shares[2:], p) == 123456


def test_indexing_structures():
    entries = {secrets.token_bytes(32): f"val-{i}".encode() for i in range(10)}
    for bkt in (PrefixBucketizer(), ModuloBucketizer()):
        built = bkt.build(entries, bucket_count=4, use_aead=True)
        assert len({len(b) for b in built.buckets}) == 1
        for k, v in entries.items():
            idx = bkt.bucket_index(k, 4)
            ok, payload = bkt.lookup_in_bucket(
                built.buckets[idx], k, record_size=built.record_size, use_aead=True
            )
            assert ok is True and payload == v

    table, rec_size = CuckooTable.build(entries, use_aead=True)
    assert len(table.slots) == table.num_bins

    bf = BloomFilter.for_capacity(20, 1e-4)
    bf.add(b"alpha")
    assert bf.contains(b"alpha") is True
    assert BloomFilter.from_dict(bf.to_dict()).contains(b"alpha") is True

    gbf = GarbledBloomFilter.build([b"k1", b"k2", b"k3"])
    for item in (b"k1", b"k2", b"k3"):
        pos = GarbledBloomFilter.positions(item, gbf.num_slots, gbf.num_hashes, gbf.seed)
        assert gbf.verify_shares(item, {p: gbf.slots[p] for p in pos}) is True
    pos_miss = GarbledBloomFilter.positions(b"absent", gbf.num_slots, gbf.num_hashes, gbf.seed)
    assert gbf.verify_shares(b"absent", {p: gbf.slots[p] for p in pos_miss}) is False
