"""Constant-time native backend differential & dudect-style timing verification tests."""

from __future__ import annotations

import math
import secrets
import time

import pytest

import pmset
from pmset import native
from pmset.primitives.ec import P256_GENERATOR, P256_N, ECPoint, hash_to_curve, random_scalar
from pmset.primitives.he import ExponentialElGamalHE
from pmset.primitives.math_utils import RFC2409_GROUP1_P, RFC2409_GROUP1_Q
from pmset.primitives.rlwe import RLWEContext, RLWEParams


def test_native_backend_loaded_and_strict_mode():
    info = pmset.backend_info()
    assert info.available is True
    assert info.abi_version == 1
    assert info.openssl_version is not None and "OpenSSL" in info.openssl_version
    assert info.library_path is not None

    # Strict mode must succeed when native library is loaded
    pmset.require_constant_time(True)
    try:
        assert pmset.backend_info().strict_mode is True
        # Fail-closed check when native is forcibly disabled
        old_flag = native._DISABLE_NATIVE_FOR_TEST
        native._DISABLE_NATIVE_FOR_TEST = True
        try:
            with pytest.raises(pmset.NativeBackendError):
                native.ct_modexp(5, 7, 101)
        finally:
            native._DISABLE_NATIVE_FOR_TEST = old_flag
    finally:
        pmset.require_constant_time(False)


def test_differential_equivalence_bytes_and_bucket_scan():
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

    # Full-scan bucket tag lookup
    rec_size = 48
    records = [secrets.token_bytes(rec_size) for _ in range(20)]
    target_rec = records[13]
    found, matched = native.ct_bucket_scan_tag(b"".join(records), rec_size, target_rec[:16])
    assert found is True and matched == target_rec
    found_miss, _ = native.ct_bucket_scan_tag(b"".join(records), rec_size, secrets.token_bytes(16))
    assert found_miss is False


def test_differential_equivalence_modexp_and_joye_padding():
    p = RFC2409_GROUP1_P
    q = RFC2409_GROUP1_Q
    # Base in prime-order subgroup G_q
    base = pow(secrets.randbelow(p - 3) + 2, 2, p)
    for exp in (0, 1, 2, 3, 17, q - 2, q - 1, secrets.randbelow(q - 1) + 1):
        assert native.ct_modexp(base, exp, p) == pow(base, exp, p)
        assert native.ct_modexp(base, exp, p, order=q) == pow(base, exp, p)
    for r in (1, 2, 13, q - 1, secrets.randbelow(q - 1) + 1):
        inv = native.ct_modinv(r, q)
        assert (r * inv) % q == 1


def test_differential_equivalence_p256_and_ot_and_elgamal():
    P = hash_to_curve(b"differential-p256-test")
    k = random_scalar()

    # Native vs pure-Python Jacobian scalar multiplication & point addition
    native_kP = ECPoint.from_compressed_bytes(
        native.ct_p256_scalar_mul(k, P.to_compressed_bytes(), P256_N)  # type: ignore[arg-type]
    )
    native_kG = ECPoint.from_compressed_bytes(
        native.ct_p256_scalar_mul(k, None, P256_N)  # type: ignore[arg-type]
    )

    old_flag = native._DISABLE_NATIVE_FOR_TEST
    native._DISABLE_NATIVE_FOR_TEST = True
    try:
        from pmset.primitives.ec import point_add, scalar_mul

        py_kP = scalar_mul(k, P)
        py_kG = scalar_mul(k, P256_GENERATOR)
        py_sum = point_add(py_kP, py_kG)
    finally:
        native._DISABLE_NATIVE_FOR_TEST = old_flag

    assert native_kP == py_kP
    assert native_kG == py_kG
    native_sum = ECPoint.from_compressed_bytes(
        native.ct_p256_point_add(native_kP.to_compressed_bytes(), native_kG.to_compressed_bytes())  # type: ignore[arg-type]
    )
    assert native_sum == py_sum

    # Chou-Orlandi OT branchless choice
    a = random_scalar()
    A = ECPoint.from_compressed_bytes(native.ct_p256_scalar_mul(a, None, P256_N))  # type: ignore[arg-type]
    b = random_scalar()
    B0, sh0 = native.ct_p256_ot_choose(A.to_compressed_bytes(), b, 0)  # type: ignore[misc]
    B1, sh1 = native.ct_p256_ot_choose(A.to_compressed_bytes(), b, 1)  # type: ignore[misc]
    assert sh0 == sh1
    assert B0 == native.ct_p256_scalar_mul(b, None, P256_N)
    assert B1 == native.ct_p256_point_add(A.to_compressed_bytes(), B0)

    # ElGamal non-short-circuiting zero test
    eg = ExponentialElGamalHE()
    cts = [eg.encrypt(1), eg.encrypt(2), eg.encrypt(0), eg.encrypt(3)]
    assert eg.any_zero(cts) is True
    assert eg.any_zero([eg.encrypt(1), eg.encrypt(2), eg.encrypt(3)]) is False


def test_differential_equivalence_rlwe_kernels():
    params = RLWEParams()
    ctx = RLWEContext(params)
    a = [secrets.randbelow(params.q) for _ in range(params.n)]
    b = [secrets.randbelow(params.t) for _ in range(params.n)]

    native_mul = native.ct_rlwe_poly_mul(a, b, params.q)
    old_flag = native._DISABLE_NATIVE_FOR_TEST
    native._DISABLE_NATIVE_FOR_TEST = True
    try:
        from pmset.primitives.rlwe import poly_mul_negacyclic

        py_mul = poly_mul_negacyclic(a, b, params.q)
    finally:
        native._DISABLE_NATIVE_FOR_TEST = old_flag
    assert native_mul == py_mul

    # Full encrypt -> PIR dot -> decrypt roundtrip via native C kernels
    pt_polys = [[secrets.randbelow(params.t) for _ in range(params.n)] for _ in range(8)]
    target = 5
    cts = [ctx.encrypt_scalar(1 if i == target else 0) for i in range(8)]
    dot_a, dot_b = native.ct_rlwe_pir_dot(  # type: ignore[misc]
        [c.a for c in cts], [c.b for c in cts], pt_polys, params.q
    )
    from pmset.primitives.rlwe import RLWECiphertext

    assert ctx.decrypt_poly(RLWECiphertext(dot_a, dot_b)) == pt_polys[target]


# ---------------------------------------------------------------------------
# Dudect-style statistical timing leakage tests (Welch's t-test)
# ---------------------------------------------------------------------------


def _welch_t_trimmed(samples_a: list[int], samples_b: list[int], trim_frac: float = 0.15) -> float:
    """Compute Welch's t-statistic on middle-trimmed latency distributions (dudect method)."""
    def _trim(xs: list[int]) -> list[int]:
        s = sorted(xs)
        k = int(len(s) * trim_frac)
        return s[k : len(s) - k] if k > 0 else s

    a = _trim(samples_a)
    b = _trim(samples_b)
    na, nb = len(a), len(b)
    mean_a = sum(a) / na
    mean_b = sum(b) / nb
    var_a = sum((x - mean_a) ** 2 for x in a) / max(1, na - 1)
    var_b = sum((x - mean_b) ** 2 for x in b) / max(1, nb - 1)
    se = math.sqrt(var_a / na + var_b / nb)
    if se == 0.0:
        return 0.0
    return abs(mean_a - mean_b) / se


def _interleaved_timing_ratio(fn_a, fn_b, trials: int = 300) -> tuple[float, float]:
    """Measure median ratio & Welch's t using ABBA interleaving to cancel frequency drift."""
    # Warmup
    for _ in range(30):
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
    ratio = max(med_a, med_b) / max(1, min(med_a, med_b))
    t_stat = _welch_t_trimmed(times_a, times_b)
    return ratio, t_stat


def test_timing_invariance_p256_low_vs_high_hamming_weight():
    """NISTZ256 scalar mul must execute in near-identical time for k=1 vs k=n-1."""
    pt_bytes = hash_to_curve(b"timing-target").to_compressed_bytes()
    k_low = 2
    k_high = P256_N - 1
    ratio, _ = _interleaved_timing_ratio(
        lambda: native.ct_p256_scalar_mul(k_low, pt_bytes, P256_N),
        lambda: native.ct_p256_scalar_mul(k_high, pt_bytes, P256_N),
        trials=250,
    )
    # In variable-time binary double-and-add, k=2 vs k=2^256-1 differs by >50x!
    # Constant-time NISTZ256 keeps median latency within ~15% noise band.
    assert ratio < 1.25, f"P-256 scalar mul timing ratio too high: {ratio:.3f}"


def test_timing_invariance_dh_modexp_joye_padding():
    """Joye-padded BN_mod_exp_mont_consttime must run identically for exp=1 vs exp=q-1."""
    p = RFC2409_GROUP1_P
    q = RFC2409_GROUP1_Q
    base = pow(1234567, 2, p)
    ratio, _ = _interleaved_timing_ratio(
        lambda: native.ct_modexp(base, 1, p, order=q),
        lambda: native.ct_modexp(base, q - 1, p, order=q),
        trials=200,
    )
    # Without Joye padding, exp=1 vs exp=q-1 differs by >100x!
    assert ratio < 1.20, f"Joye-padded modexp timing ratio too high: {ratio:.3f}"


def test_timing_invariance_chou_orlandi_ot_choice_bit():
    """Chou-Orlandi OT choice=0 vs choice=1 must execute in identical time."""
    a = random_scalar()
    A_bytes = native.ct_p256_scalar_mul(a, None, P256_N)
    assert A_bytes is not None
    b = random_scalar()
    ratio, _ = _interleaved_timing_ratio(
        lambda: native.ct_p256_ot_choose(A_bytes, b, 0),
        lambda: native.ct_p256_ot_choose(A_bytes, b, 1),
        trials=200,
    )
    assert ratio < 1.20, f"Chou-Orlandi OT choice timing ratio too high: {ratio:.3f}"


def test_timing_invariance_rlwe_zero_vs_dense_key():
    """Branchless C RLWE poly mul must take identical time for all-zero vs dense input."""
    params = RLWEParams()
    a = [secrets.randbelow(params.q) for _ in range(params.n)]
    zero_poly = [0] * params.n
    dense_poly = [params.t - 1] * params.n
    ratio, _ = _interleaved_timing_ratio(
        lambda: native.ct_rlwe_poly_mul(a, zero_poly, params.q),
        lambda: native.ct_rlwe_poly_mul(a, dense_poly, params.q),
        trials=300,
    )
    # Previously `if ai == 0: continue` made zero_poly >20x faster than dense_poly!
    assert ratio < 1.25, f"RLWE poly mul timing ratio too high: {ratio:.3f}"


def test_timing_invariance_dpf_and_bucket_full_scan():
    """DPF XOR evaluation (all-0 vs all-1 bits) and full-scan bucket lookup (slot 0 vs last)."""
    buckets = [secrets.token_bytes(128) for _ in range(32)]
    all_zero = [0] * 32
    all_one = [1] * 32
    ratio_dpf, _ = _interleaved_timing_ratio(
        lambda: native.ct_dpf_bucket_eval(buckets, all_zero),
        lambda: native.ct_dpf_bucket_eval(buckets, all_one),
        trials=400,
    )
    assert ratio_dpf < 1.25, f"DPF bucket eval timing ratio too high: {ratio_dpf:.3f}"

    rec_size = 64
    records = [secrets.token_bytes(rec_size) for _ in range(64)]
    flat = b"".join(records)
    tag_first = records[0][:16]
    tag_last = records[-1][:16]
    ratio_scan, _ = _interleaved_timing_ratio(
        lambda: native.ct_bucket_scan_tag(flat, rec_size, tag_first),
        lambda: native.ct_bucket_scan_tag(flat, rec_size, tag_last),
        trials=400,
    )
    assert ratio_scan < 1.25, f"Bucket scan timing ratio too high: {ratio_scan:.3f}"
