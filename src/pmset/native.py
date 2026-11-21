"""Constant-time native C + OpenSSL backend bridge for ``pmset``.

Provides constant-time implementations of:
  - NIST P-256 elliptic curve arithmetic (OpenSSL NISTZ256 assembly)
  - Big-integer modular exponentiation & inversion (`BN_FLG_CONSTTIME`,
    `BN_mod_exp_mont_consttime`, Joye constant-bit-length exponent padding)
  - Branchless Ring-LWE polynomial multiplication, encryption, decryption, and PIR dot-product
  - Branchless Chou-Orlandi 1-out-of-2 OT choice selection
  - Non-short-circuiting Exponential ElGamal zero-testing
  - Branchless 2-server BGI15 DPF XOR bucket evaluation
  - Constant-time full-scan bucket tag lookup and byte comparison/selection

Set environment variable ``PMSET_REQUIRE_NATIVE=1`` (or call
:func:`require_constant_time`) to enforce fail-closed constant-time execution
with zero pure-Python fallback.
"""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

_C_U8_PTR = ctypes.POINTER(ctypes.c_uint8)
_C_U64_PTR = ctypes.POINTER(ctypes.c_uint64)
_C_I64_PTR = ctypes.POINTER(ctypes.c_int64)


class NativeBackendError(RuntimeError):
    """Raised when the constant-time native backend is required but unavailable or errors."""


@dataclass(frozen=True)
class NativeBackendInfo:
    """Status metadata describing the active native constant-time backend."""

    available: bool
    library_path: str | None
    abi_version: int | None
    openssl_version: str | None
    strict_mode: bool


def _lib_filename() -> str:
    sys_name = platform.system()
    if sys_name == "Darwin":
        return "libpmset_ct.dylib"
    if sys_name == "Windows":
        return "pmset_ct.dll"
    return "libpmset_ct.so"


def _native_dir() -> Path:
    return Path(__file__).resolve().parent / "_native"


def build_native_library(force: bool = False) -> Path:
    """Compile ``pmset_ct.c`` into the platform shared library linked against OpenSSL libcrypto."""
    ndir = _native_dir()
    src = ndir / "pmset_ct.c"
    out = ndir / _lib_filename()
    if out.is_file() and not force:
        if out.stat().st_mtime >= src.stat().st_mtime:
            return out
    if not src.is_file():
        raise NativeBackendError(f"Native C source not found: {src}")

    compiler = os.environ.get("CC") or shutil.which("gcc") or shutil.which("clang")
    if not compiler:
        raise NativeBackendError("No C compiler (gcc/clang) found to compile libpmset_ct")

    cmd = [
        compiler,
        "-O2",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-fPIC",
        "-shared",
        str(src),
        "-o",
        str(out),
        "-lcrypto",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise NativeBackendError(
            f"Failed to compile {src}: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    return out


class _NativeLib:
    """Typed ctypes wrapper around ``libpmset_ct``."""

    def __init__(self, path: Path) -> None:
        self.path = path
        lib = ctypes.CDLL(str(path))
        self._lib = lib

        lib.pmset_ct_abi_version.argtypes = []
        lib.pmset_ct_abi_version.restype = ctypes.c_uint32

        lib.pmset_ct_openssl_version.argtypes = []
        lib.pmset_ct_openssl_version.restype = ctypes.c_char_p

        lib.pmset_ct_memcmp.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
        lib.pmset_ct_memcmp.restype = ctypes.c_int

        lib.pmset_ct_select_bytes.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint8
        ]
        lib.pmset_ct_select_bytes.restype = None

        lib.pmset_ct_xor_bytes.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t
        ]
        lib.pmset_ct_xor_bytes.restype = None

        lib.pmset_ct_cond_xor_bytes.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint8
        ]
        lib.pmset_ct_cond_xor_bytes.restype = None

        lib.pmset_ct_dpf_bucket_eval.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_char_p
        ]
        lib.pmset_ct_dpf_bucket_eval.restype = None

        lib.pmset_ct_bucket_scan_tag.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
        ]
        lib.pmset_ct_bucket_scan_tag.restype = ctypes.c_int

        lib.pmset_ct_modexp.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
        ]
        lib.pmset_ct_modexp.restype = ctypes.c_int

        lib.pmset_ct_modexp_order.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
        ]
        lib.pmset_ct_modexp_order.restype = ctypes.c_int

        lib.pmset_ct_modinv.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
            ctypes.c_char_p, ctypes.c_size_t,
        ]
        lib.pmset_ct_modinv.restype = ctypes.c_int

        lib.pmset_ct_p256_scalar_mul.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
        ]
        lib.pmset_ct_p256_scalar_mul.restype = ctypes.c_int

        lib.pmset_ct_p256_point_add.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
        ]
        lib.pmset_ct_p256_point_add.restype = ctypes.c_int

        lib.pmset_ct_p256_point_neg.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.pmset_ct_p256_point_neg.restype = ctypes.c_int

        lib.pmset_ct_p256_ot_choose.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint8,
            ctypes.c_char_p, ctypes.c_char_p,
        ]
        lib.pmset_ct_p256_ot_choose.restype = ctypes.c_int

        lib.pmset_ct_p256_elgamal_is_zero.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p
        ]
        lib.pmset_ct_p256_elgamal_is_zero.restype = ctypes.c_int

        lib.pmset_ct_p256_elgamal_any_zero.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t
        ]
        lib.pmset_ct_p256_elgamal_any_zero.restype = ctypes.c_int

        lib.pmset_ct_rlwe_poly_mul.argtypes = [
            _C_U64_PTR, _C_U64_PTR, _C_U64_PTR, ctypes.c_size_t, ctypes.c_uint64
        ]
        lib.pmset_ct_rlwe_poly_mul.restype = None

        lib.pmset_ct_rlwe_encrypt.argtypes = [
            _C_U64_PTR, _C_I64_PTR, _C_I64_PTR, _C_U64_PTR,
            _C_U64_PTR, ctypes.c_size_t, ctypes.c_uint64, ctypes.c_uint64,
        ]
        lib.pmset_ct_rlwe_encrypt.restype = None

        lib.pmset_ct_rlwe_decrypt.argtypes = [
            _C_U64_PTR, _C_U64_PTR, _C_I64_PTR, _C_U64_PTR,
            ctypes.c_size_t, ctypes.c_uint64, ctypes.c_uint64,
        ]
        lib.pmset_ct_rlwe_decrypt.restype = None

        lib.pmset_ct_rlwe_pir_dot.argtypes = [
            _C_U64_PTR, _C_U64_PTR, _C_U64_PTR,
            ctypes.c_size_t, ctypes.c_size_t, ctypes.c_uint64,
            _C_U64_PTR, _C_U64_PTR,
        ]
        lib.pmset_ct_rlwe_pir_dot.restype = None

        self.abi_version: int = int(lib.pmset_ct_abi_version())
        self.openssl_version: str = lib.pmset_ct_openssl_version().decode("utf-8")


_STRICT_MODE: bool = os.environ.get("PMSET_REQUIRE_NATIVE", "0") in ("1", "true", "TRUE", "yes")
_NATIVE_LOADED: bool = False
_NATIVE_LIB: _NativeLib | None = None
_DISABLE_NATIVE_FOR_TEST: bool = False


def _load_native() -> _NativeLib | None:
    global _NATIVE_LOADED, _NATIVE_LIB
    if _DISABLE_NATIVE_FOR_TEST:
        return None
    if _NATIVE_LOADED:
        return _NATIVE_LIB
    _NATIVE_LOADED = True
    if os.environ.get("PMSET_DISABLE_NATIVE", "0") in ("1", "true", "TRUE"):
        _NATIVE_LIB = None
        return None
    lib_path = _native_dir() / _lib_filename()
    if not lib_path.is_file() and os.environ.get("PMSET_AUTO_BUILD_NATIVE", "1") != "0":
        try:
            lib_path = build_native_library()
        except Exception:
            _NATIVE_LIB = None
            return None
    if lib_path.is_file():
        try:
            _NATIVE_LIB = _NativeLib(lib_path)
            return _NATIVE_LIB
        except OSError:
            _NATIVE_LIB = None
            return None
    return None


def require_constant_time(enabled: bool = True) -> None:
    """Enforce fail-closed constant-time native execution (raises if unavailable)."""
    global _STRICT_MODE
    _STRICT_MODE = enabled
    if enabled and _load_native() is None:
        raise NativeBackendError(
            "Constant-time native backend (libpmset_ct) is required but unavailable. "
            "Run `pmset.native.build_native_library()` or install with gcc + OpenSSL."
        )


def is_native_available() -> bool:
    """Return True iff the compiled constant-time C + OpenSSL backend is loaded."""
    return _load_native() is not None


def backend_info() -> NativeBackendInfo:
    """Return diagnostic details about the active constant-time native backend."""
    lib = _load_native()
    if lib is None:
        return NativeBackendInfo(
            available=False,
            library_path=None,
            abi_version=None,
            openssl_version=None,
            strict_mode=_STRICT_MODE,
        )
    return NativeBackendInfo(
        available=True,
        library_path=str(lib.path),
        abi_version=lib.abi_version,
        openssl_version=lib.openssl_version,
        strict_mode=_STRICT_MODE,
    )


def _get_or_enforce() -> _NativeLib | None:
    lib = _load_native()
    if lib is None and _STRICT_MODE:
        raise NativeBackendError("Constant-time native backend required (PMSET_REQUIRE_NATIVE=1)")
    return lib


def _int_to_be(x: int, length: int | None = None) -> bytes:
    if x < 0:
        raise ValueError("Expected non-negative integer")
    min_len = max(1, (x.bit_length() + 7) // 8)
    nbytes = max(min_len, length) if length is not None else min_len
    return x.to_bytes(nbytes, "big")


# ---------------------------------------------------------------------------
# High-level constant-time operations (native C + OpenSSL when available)
# ---------------------------------------------------------------------------


def ct_memcmp(a: bytes, b: bytes) -> bool:
    """Constant-time equality check over equal-length byte strings."""
    if len(a) != len(b):
        return False
    lib = _get_or_enforce()
    if lib is not None:
        return bool(lib._lib.pmset_ct_memcmp(a, b, len(a)))
    import hmac

    return hmac.compare_digest(a, b)


def ct_select_bytes(a: bytes, b: bytes, select_b: int) -> bytes:
    """Branchless constant-time byte selection: returns ``b`` if ``select_b == 1`` else ``a``."""
    if len(a) != len(b):
        raise ValueError(f"ct_select_bytes length mismatch: {len(a)} != {len(b)}")
    lib = _get_or_enforce()
    if lib is not None:
        out = ctypes.create_string_buffer(len(a))
        lib._lib.pmset_ct_select_bytes(out, a, b, len(a), select_b & 1)
        return out.raw
    mask = (-(select_b & 1)) & 0xFF
    nmask = (~mask) & 0xFF
    return bytes((x & nmask) | (y & mask) for x, y in zip(a, b))


def ct_xor_bytes(a: bytes, b: bytes) -> bytes:
    """Constant-time bytewise XOR."""
    if len(a) != len(b):
        raise ValueError(f"ct_xor_bytes length mismatch: {len(a)} != {len(b)}")
    lib = _get_or_enforce()
    if lib is not None:
        out = ctypes.create_string_buffer(len(a))
        lib._lib.pmset_ct_xor_bytes(out, a, b, len(a))
        return out.raw
    return bytes(x ^ y for x, y in zip(a, b))


def ct_cond_xor_bytes(acc: bytes, src: bytes, cond: int) -> bytes:
    """Branchless conditional XOR: ``acc ^ src`` if ``cond == 1`` else ``acc``."""
    if len(acc) != len(src):
        raise ValueError("ct_cond_xor_bytes length mismatch")
    lib = _get_or_enforce()
    if lib is not None:
        buf = ctypes.create_string_buffer(acc, len(acc))
        lib._lib.pmset_ct_cond_xor_bytes(buf, src, len(acc), cond & 1)
        return buf.raw
    mask = (-(cond & 1)) & 0xFF
    return bytes(x ^ (y & mask) for x, y in zip(acc, src))


def ct_dpf_bucket_eval(buckets: Sequence[bytes], bits: Sequence[int]) -> bytes:
    """Branchless 2-server DPF XOR evaluation across all buckets."""
    num_buckets = len(buckets)
    if num_buckets == 0:
        return b""
    bucket_len = len(buckets[0])
    if bucket_len == 0:
        return b""
    lib = _get_or_enforce()
    if lib is not None:
        flat = b"".join(buckets)
        bit_bytes = bytes(b & 1 for b in bits[:num_buckets])
        out = ctypes.create_string_buffer(bucket_len)
        lib._lib.pmset_ct_dpf_bucket_eval(out, flat, num_buckets, bucket_len, bit_bytes)
        return out.raw
    acc = bytearray(bucket_len)
    for bit, bkt in zip(bits, buckets):
        mask = (-(bit & 1)) & 0xFF
        for j in range(bucket_len):
            acc[j] ^= bkt[j] & mask
    return bytes(acc)


def ct_bucket_scan_tag(
    bucket_bytes: bytes, record_size: int, target_tag: bytes
) -> tuple[bool, bytes]:
    """Constant-time full scan of ALL records in a bucket (zero early exit)."""
    if record_size <= 0 or not bucket_bytes:
        return False, b""
    num_records = len(bucket_bytes) // record_size
    if num_records == 0:
        return False, b""
    lib = _get_or_enforce()
    if lib is not None:
        matched_buf = ctypes.create_string_buffer(record_size)
        found = lib._lib.pmset_ct_bucket_scan_tag(
            bucket_bytes,
            num_records,
            record_size,
            target_tag,
            len(target_tag),
            matched_buf,
        )
        return bool(found), matched_buf.raw
    matched = bytes(record_size)
    found_any = 0
    tag_len = len(target_tag)
    for i in range(num_records):
        rec = bucket_bytes[i * record_size : (i + 1) * record_size]
        eq = 1 if ct_memcmp(rec[:tag_len], target_tag) else 0
        matched = ct_select_bytes(matched, rec, eq)
        found_any |= eq
    return bool(found_any), matched


def ct_modexp(base: int, exp: int, mod: int, *, order: int | None = None) -> int:
    """Constant-time modular exponentiation ``base^exp mod mod`` via OpenSSL BN_FLG_CONSTTIME.

    When ``order`` is provided (and ``base^order ≡ 1 (mod mod)``), applies Joye's
    constant-bit-length exponent padding via ``pmset_ct_modexp_order`` so even
    small exponents (e.g. ``exp = 1``) execute the exact same Montgomery ladder
    length as full-width exponents.
    """
    if mod <= 1:
        raise ValueError("mod must be > 1")
    if exp < 0:
        base = ct_modinv(base % mod, mod)
        exp = -exp
    lib = _get_or_enforce()
    if lib is not None and (mod & 1) == 1:
        mod_len = (mod.bit_length() + 7) // 8
        b_bytes = _int_to_be(base % mod, mod_len)
        m_bytes = _int_to_be(mod, mod_len)
        out = ctypes.create_string_buffer(mod_len)
        if order is not None and order > 0:
            ord_len = (order.bit_length() + 7) // 8
            e_bytes = _int_to_be(exp % order, ord_len)
            o_bytes = _int_to_be(order, ord_len)
            rc = lib._lib.pmset_ct_modexp_order(
                b_bytes, len(b_bytes),
                e_bytes, len(e_bytes),
                o_bytes, len(o_bytes),
                m_bytes, len(m_bytes),
                out, mod_len,
            )
        else:
            e_bytes = _int_to_be(exp, mod_len)
            rc = lib._lib.pmset_ct_modexp(
                b_bytes, len(b_bytes),
                e_bytes, len(e_bytes),
                m_bytes, len(m_bytes),
                out, mod_len,
            )
        if rc != 0:
            raise NativeBackendError(f"pmset_ct_modexp failed with code {rc}")
        return int.from_bytes(out.raw, "big")
    return pow(base, exp, mod)


def ct_modinv(a: int, mod: int) -> int:
    """Constant-time modular inverse ``a^(-1) mod mod`` via OpenSSL BN_FLG_CONSTTIME."""
    lib = _get_or_enforce()
    if lib is not None:
        mod_len = (mod.bit_length() + 7) // 8
        a_bytes = _int_to_be(a % mod, mod_len)
        m_bytes = _int_to_be(mod, mod_len)
        out = ctypes.create_string_buffer(mod_len)
        rc = lib._lib.pmset_ct_modinv(a_bytes, len(a_bytes), m_bytes, len(m_bytes), out, mod_len)
        if rc != 0:
            raise ValueError(f"Value is not invertible modulo {mod} (rc={rc})")
        return int.from_bytes(out.raw, "big")
    return pow(a, -1, mod)


def _pad_point33(pt_bytes: bytes) -> bytes:
    if pt_bytes == b"\x00":
        return b"\x00" * 33
    if len(pt_bytes) != 33:
        raise ValueError(f"Expected 33-byte SEC1 compressed point, got {len(pt_bytes)} bytes")
    return pt_bytes


def _unpad_point33(raw33: bytes) -> bytes:
    if raw33[0] == 0x00:
        return b"\x00"
    return raw33


def ct_p256_scalar_mul(scalar: int, pt_bytes: bytes | None, order_n: int) -> bytes | None:
    """Constant-time P-256 scalar multiplication using OpenSSL NISTZ256 assembly.

    Returns compressed point bytes (1 byte ``b"\\x00"`` for infinity, 33 bytes otherwise),
    or ``None`` if the native backend is unavailable (and not in strict mode).
    """
    lib = _get_or_enforce()
    if lib is None:
        return None
    k = scalar % order_n
    if k == 0:
        return b"\x00"
    s32 = k.to_bytes(32, "big")
    out33 = ctypes.create_string_buffer(33)
    if pt_bytes is None:
        rc = lib._lib.pmset_ct_p256_scalar_mul(s32, None, out33)
    else:
        p33 = _pad_point33(pt_bytes)
        if p33[0] == 0x00:
            return b"\x00"
        rc = lib._lib.pmset_ct_p256_scalar_mul(s32, p33, out33)
    if rc != 0:
        raise ValueError(f"Invalid P-256 scalar multiplication input (rc={rc})")
    return _unpad_point33(out33.raw)


def ct_p256_point_add(p1_bytes: bytes, p2_bytes: bytes) -> bytes | None:
    """Native P-256 point addition via OpenSSL."""
    lib = _get_or_enforce()
    if lib is None:
        return None
    out33 = ctypes.create_string_buffer(33)
    rc = lib._lib.pmset_ct_p256_point_add(_pad_point33(p1_bytes), _pad_point33(p2_bytes), out33)
    if rc != 0:
        raise ValueError(f"Invalid P-256 point addition input (rc={rc})")
    return _unpad_point33(out33.raw)


def ct_p256_point_neg(p_bytes: bytes) -> bytes | None:
    """Native P-256 point negation via OpenSSL."""
    lib = _get_or_enforce()
    if lib is None:
        return None
    out33 = ctypes.create_string_buffer(33)
    rc = lib._lib.pmset_ct_p256_point_neg(_pad_point33(p_bytes), out33)
    if rc != 0:
        raise ValueError(f"Invalid P-256 point negation input (rc={rc})")
    return _unpad_point33(out33.raw)


def ct_p256_ot_choose(
    A_bytes: bytes, b_scalar: int, choice: int
) -> tuple[bytes, bytes] | None:
    """Constant-time Chou-Orlandi OT choice on P-256 (ZERO branches on ``choice``)."""
    lib = _get_or_enforce()
    if lib is None:
        return None
    B_out = ctypes.create_string_buffer(33)
    shared_out = ctypes.create_string_buffer(33)
    rc = lib._lib.pmset_ct_p256_ot_choose(
        _pad_point33(A_bytes),
        b_scalar.to_bytes(32, "big"),
        choice & 1,
        B_out,
        shared_out,
    )
    if rc != 0:
        raise ValueError(f"pmset_ct_p256_ot_choose failed (rc={rc})")
    return _unpad_point33(B_out.raw), _unpad_point33(shared_out.raw)


def ct_p256_elgamal_is_zero(sk: int, c1_bytes: bytes, c2_bytes: bytes) -> bool | None:
    """Constant-time Exponential ElGamal zero-test: ``sk * C1 == C2``."""
    lib = _get_or_enforce()
    if lib is None:
        return None
    rc = lib._lib.pmset_ct_p256_elgamal_is_zero(
        sk.to_bytes(32, "big"), _pad_point33(c1_bytes), _pad_point33(c2_bytes)
    )
    if rc < 0:
        raise ValueError(f"pmset_ct_p256_elgamal_is_zero failed (rc={rc})")
    return bool(rc)


def ct_p256_elgamal_any_zero(
    sk: int, wire_pairs: Sequence[tuple[bytes, bytes]]
) -> bool | None:
    """Non-short-circuiting ElGamal zero test across all ciphertexts."""
    lib = _get_or_enforce()
    if lib is None:
        return None
    count = len(wire_pairs)
    if count == 0:
        return False
    c1s = b"".join(_pad_point33(c1) for c1, _ in wire_pairs)
    c2s = b"".join(_pad_point33(c2) for _, c2 in wire_pairs)
    rc = lib._lib.pmset_ct_p256_elgamal_any_zero(sk.to_bytes(32, "big"), c1s, c2s, count)
    if rc < 0:
        raise ValueError(f"pmset_ct_p256_elgamal_any_zero failed (rc={rc})")
    return bool(rc)


def ct_rlwe_poly_mul(a: Sequence[int], b: Sequence[int], q: int) -> list[int] | None:
    """Branchless native negacyclic polynomial multiplication in Z_q[X]/(X^N + 1)."""
    lib = _get_or_enforce()
    if lib is None or q >= (1 << 63):
        return None
    n = len(a)
    arr_a = (ctypes.c_uint64 * n)(*a)
    arr_b = (ctypes.c_uint64 * n)(*b)
    arr_out = (ctypes.c_uint64 * n)()
    lib._lib.pmset_ct_rlwe_poly_mul(arr_a, arr_b, arr_out, n, q)
    return list(arr_out)


def ct_rlwe_encrypt(
    a: Sequence[int], sk: Sequence[int], err: Sequence[int], m: Sequence[int], q: int, t: int
) -> list[int] | None:
    """Branchless native RLWE encryption kernel."""
    lib = _get_or_enforce()
    if lib is None or q >= (1 << 63):
        return None
    n = len(a)
    arr_a = (ctypes.c_uint64 * n)(*a)
    arr_sk = (ctypes.c_int64 * n)(*sk)
    arr_err = (ctypes.c_int64 * n)(*err)
    arr_m = (ctypes.c_uint64 * n)(*m)
    arr_b = (ctypes.c_uint64 * n)()
    lib._lib.pmset_ct_rlwe_encrypt(arr_a, arr_sk, arr_err, arr_m, arr_b, n, q, t)
    return list(arr_b)


def ct_rlwe_decrypt(
    a: Sequence[int], b: Sequence[int], sk: Sequence[int], q: int, t: int
) -> list[int] | None:
    """Branchless native RLWE decryption & nearest-integer rounding kernel."""
    lib = _get_or_enforce()
    if lib is None or q >= (1 << 63):
        return None
    n = len(a)
    arr_a = (ctypes.c_uint64 * n)(*a)
    arr_b = (ctypes.c_uint64 * n)(*b)
    arr_sk = (ctypes.c_int64 * n)(*sk)
    arr_m = (ctypes.c_uint64 * n)()
    lib._lib.pmset_ct_rlwe_decrypt(arr_a, arr_b, arr_sk, arr_m, n, q, t)
    return list(arr_m)


def ct_rlwe_pir_dot(
    ct_a_list: Sequence[Sequence[int]],
    ct_b_list: Sequence[Sequence[int]],
    pt_list: Sequence[Sequence[int]],
    q: int,
) -> tuple[list[int], list[int]] | None:
    """Branchless native RLWE PIR inner product across all B buckets."""
    lib = _get_or_enforce()
    if lib is None or q >= (1 << 63):
        return None
    num_buckets = len(ct_a_list)
    if num_buckets == 0:
        return [], []
    n = len(ct_a_list[0])
    total = num_buckets * n
    flat_a = (ctypes.c_uint64 * total)(*(c for poly in ct_a_list for c in poly))
    flat_b = (ctypes.c_uint64 * total)(*(c for poly in ct_b_list for c in poly))
    flat_pt = (ctypes.c_uint64 * total)(*(c for poly in pt_list for c in poly))
    out_a = (ctypes.c_uint64 * n)()
    out_b = (ctypes.c_uint64 * n)()
    lib._lib.pmset_ct_rlwe_pir_dot(flat_a, flat_b, flat_pt, num_buckets, n, q, out_a, out_b)
    return list(out_a), list(out_b)
