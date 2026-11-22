"""Pluggable constant-time native cryptographic backend architecture for ``pmset``.

Exposes a generic :class:`NativeCryptoBackend` interface and backend registry
with two built-in compiled C11 providers:

  1. **``aws-lc``** (:class:`AWSLCNativeBackend`): Links statically against
     Amazon's AWS-LC (with **s2n-bignum** HOL Light formally verified constant-time
     P-256 & Montgomery assembly, blinded modular inversion, and full ELF symbol
     isolation so it coexists cleanly with system OpenSSL).
  2. **``openssl``** (:class:`OpenSSLNativeBackend`): Links against OpenSSL 3.x
     ``libcrypto`` (NISTZ256 assembly, ``BN_FLG_CONSTTIME``,
     ``BN_mod_exp_mont_consttime``, ``BN_consttime_swap``).

Users can register additional custom backends (e.g., BoringSSL, Rust ``aws-lc-rs``,
HACL*, or hardware/HSM providers) via :func:`register_native_backend` and switch
backends at runtime via :func:`set_native_backend`, :func:`use_native_backend`,
or the ``PMSET_NATIVE_BACKEND`` environment variable.

Set ``PMSET_REQUIRE_NATIVE=1`` (or call :func:`require_constant_time`) to enforce
fail-closed constant-time execution with zero pure-Python fallback.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import platform
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

_C_U64_PTR = ctypes.POINTER(ctypes.c_uint64)
_C_I64_PTR = ctypes.POINTER(ctypes.c_int64)


class NativeBackendError(RuntimeError):
    """Raised when a required constant-time native backend is unavailable or fails."""


@dataclass(frozen=True)
class NativeBackendInfo:
    """Diagnostic metadata describing a native constant-time backend."""

    available: bool
    backend_name: str | None
    provider_version: str | None
    library_path: str | None
    abi_version: int | None
    strict_mode: bool

    @property
    def openssl_version(self) -> str | None:
        """Backward-compatible alias for :attr:`provider_version`."""
        return self.provider_version


def _lib_ext() -> str:
    sys_name = platform.system()
    if sys_name == "Darwin":
        return ".dylib"
    if sys_name == "Windows":
        return ".dll"
    return ".so"


def _native_dir() -> Path:
    return Path(__file__).resolve().parent / "_native"


def find_awslc_prefix() -> Path | None:
    """Discover an AWS-LC installation prefix containing ``include/openssl/is_awslc.h`` and ``libcrypto.a``."""
    env_prefix = os.environ.get("AWSLC_PREFIX")
    candidates = [
        Path(env_prefix) if env_prefix else None,
        Path.home() / ".local" / "share" / "pmset-tools" / "aws-lc",
        Path("/opt/aws-lc"),
        Path("/usr/local/aws-lc"),
        Path("/usr/local"),
    ]
    for prefix in candidates:
        if prefix is None:
            continue
        marker = prefix / "include" / "openssl" / "is_awslc.h"
        lib_a = prefix / "lib" / "libcrypto.a"
        lib64_a = prefix / "lib64" / "libcrypto.a"
        if marker.is_file() and (lib_a.is_file() or lib64_a.is_file()):
            return prefix
    return None


def _awslc_static_lib(prefix: Path) -> Path:
    lib_a = prefix / "lib" / "libcrypto.a"
    if lib_a.is_file():
        return lib_a
    return prefix / "lib64" / "libcrypto.a"


def _compile_shared_lib(cmd: list[str], out: Path) -> Path:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise NativeBackendError(
            f"Native compilation failed ({out.name}): "
            f"{proc.stderr.strip() or proc.stdout.strip()}"
        )
    return out


def _int_to_be(x: int, length: int | None = None) -> bytes:
    if x < 0:
        raise ValueError("Expected non-negative integer")
    min_len = max(1, (x.bit_length() + 7) // 8)
    nbytes = max(min_len, length) if length is not None else min_len
    return x.to_bytes(nbytes, "big")


def _pad_point33(pt_bytes: bytes) -> bytes:
    if pt_bytes == b"\x00":
        return b"\x00" * 33
    if len(pt_bytes) != 33:
        raise ValueError(f"Expected 33-byte SEC1 compressed point, got {len(pt_bytes)} bytes")
    return pt_bytes


def _unpad_point33(raw33: bytes) -> bytes:
    return b"\x00" if raw33[0] == 0x00 else raw33


# ---------------------------------------------------------------------------
# Generic Pluggable Native Backend Interface
# ---------------------------------------------------------------------------


class NativeCryptoBackend(ABC):
    """Pluggable interface for constant-time native cryptographic backends."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Canonical backend name (e.g. ``'aws-lc'``, ``'openssl'``)."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True iff this backend is compiled/loadable on the current host."""

    @abstractmethod
    def info(self, *, strict_mode: bool = False) -> NativeBackendInfo:
        """Return structured metadata describing this backend."""

    def build(self, force: bool = False) -> Path | None:
        """Optionally compile this backend from source; return artifact path if applicable."""
        return None

    @abstractmethod
    def memcmp(self, a: bytes, b: bytes) -> bool: ...

    @abstractmethod
    def select_bytes(self, a: bytes, b: bytes, select_b: int) -> bytes: ...

    @abstractmethod
    def xor_bytes(self, a: bytes, b: bytes) -> bytes: ...

    @abstractmethod
    def cond_xor_bytes(self, acc: bytes, src: bytes, cond: int) -> bytes: ...

    @abstractmethod
    def dpf_bucket_eval(self, buckets: Sequence[bytes], bits: Sequence[int]) -> bytes: ...

    @abstractmethod
    def bucket_scan_tag(
        self, bucket_bytes: bytes, record_size: int, target_tag: bytes
    ) -> tuple[bool, bytes]: ...

    @abstractmethod
    def modexp(self, base: int, exp: int, mod: int, *, order: int | None = None) -> int: ...

    @abstractmethod
    def modinv(self, a: int, mod: int) -> int: ...

    @abstractmethod
    def p256_scalar_mul(self, scalar: int, pt_bytes: bytes | None, order_n: int) -> bytes: ...

    @abstractmethod
    def p256_point_add(self, p1_bytes: bytes, p2_bytes: bytes) -> bytes: ...

    @abstractmethod
    def p256_point_neg(self, p_bytes: bytes) -> bytes: ...

    @abstractmethod
    def p256_ot_choose(
        self, A_bytes: bytes, b_scalar: int, choice: int
    ) -> tuple[bytes, bytes]: ...

    @abstractmethod
    def p256_elgamal_is_zero(self, sk: int, c1_bytes: bytes, c2_bytes: bytes) -> bool: ...

    @abstractmethod
    def p256_elgamal_any_zero(
        self, sk: int, wire_pairs: Sequence[tuple[bytes, bytes]]
    ) -> bool: ...

    @abstractmethod
    def rlwe_poly_mul(self, a: Sequence[int], b: Sequence[int], q: int) -> list[int]: ...

    @abstractmethod
    def rlwe_encrypt(
        self,
        a: Sequence[int],
        sk: Sequence[int],
        err: Sequence[int],
        m: Sequence[int],
        q: int,
        t: int,
    ) -> list[int]: ...

    @abstractmethod
    def rlwe_decrypt(
        self, a: Sequence[int], b: Sequence[int], sk: Sequence[int], q: int, t: int
    ) -> list[int]: ...

    @abstractmethod
    def rlwe_pir_dot(
        self,
        ct_a_list: Sequence[Sequence[int]],
        ct_b_list: Sequence[Sequence[int]],
        pt_list: Sequence[Sequence[int]],
        q: int,
    ) -> tuple[list[int], list[int]]: ...


# ---------------------------------------------------------------------------
# Generic C ABI Adapter (`pmset_ct.h` ABI v2)
# ---------------------------------------------------------------------------


class _LoadedCTLib:
    """Typed ctypes handle for any shared library implementing ``pmset_ct.h``."""

    def __init__(self, path: Path) -> None:
        self.path = path
        lib = ctypes.CDLL(str(path))
        self.lib = lib

        lib.pmset_ct_abi_version.argtypes = []
        lib.pmset_ct_abi_version.restype = ctypes.c_uint32

        lib.pmset_ct_provider_name.argtypes = []
        lib.pmset_ct_provider_name.restype = ctypes.c_char_p

        lib.pmset_ct_provider_version.argtypes = []
        lib.pmset_ct_provider_version.restype = ctypes.c_char_p

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
        if self.abi_version != 2:
            raise NativeBackendError(
                f"Incompatible native library ABI version {self.abi_version} in {path} (expected 2)"
            )
        self.provider_name: str = lib.pmset_ct_provider_name().decode("utf-8")
        self.provider_version: str = lib.pmset_ct_provider_version().decode("utf-8")


class CSharedLibBackend(NativeCryptoBackend):
    """Concrete :class:`NativeCryptoBackend` wrapping a ``pmset_ct.h`` shared library."""

    def __init__(self, backend_name: str, lib_path: Path) -> None:
        self._name = backend_name
        self._lib_path = lib_path
        self._loaded: _LoadedCTLib | None = None
        self._tried_load = False

    @property
    def name(self) -> str:
        return self._name

    @property
    def lib_path(self) -> Path:
        return self._lib_path

    def _ensure_loaded(self) -> _LoadedCTLib | None:
        if self._tried_load:
            return self._loaded
        self._tried_load = True
        if not self._lib_path.is_file() and os.environ.get("PMSET_AUTO_BUILD_NATIVE", "1") != "0":
            try:
                self.build()
            except Exception:
                self._loaded = None
                return None
        if self._lib_path.is_file():
            try:
                self._loaded = _LoadedCTLib(self._lib_path)
            except (OSError, AttributeError, NativeBackendError):
                self._loaded = None
        return self._loaded

    def _require_lib(self) -> _LoadedCTLib:
        loaded = self._ensure_loaded()
        if loaded is None:
            raise NativeBackendError(
                f"Native backend '{self._name}' library could not be loaded from {self._lib_path}"
            )
        return loaded

    def is_available(self) -> bool:
        return self._ensure_loaded() is not None

    def info(self, *, strict_mode: bool = False) -> NativeBackendInfo:
        loaded = self._ensure_loaded()
        if loaded is None:
            return NativeBackendInfo(
                available=False,
                backend_name=self._name,
                provider_version=None,
                library_path=None,
                abi_version=None,
                strict_mode=strict_mode,
            )
        return NativeBackendInfo(
            available=True,
            backend_name=loaded.provider_name,
            provider_version=loaded.provider_version,
            library_path=str(loaded.path),
            abi_version=loaded.abi_version,
            strict_mode=strict_mode,
        )

    def memcmp(self, a: bytes, b: bytes) -> bool:
        if len(a) != len(b):
            return False
        return bool(self._require_lib().lib.pmset_ct_memcmp(a, b, len(a)))

    def select_bytes(self, a: bytes, b: bytes, select_b: int) -> bytes:
        if len(a) != len(b):
            raise ValueError(f"select_bytes length mismatch: {len(a)} != {len(b)}")
        out = ctypes.create_string_buffer(len(a))
        self._require_lib().lib.pmset_ct_select_bytes(out, a, b, len(a), select_b & 1)
        return out.raw

    def xor_bytes(self, a: bytes, b: bytes) -> bytes:
        if len(a) != len(b):
            raise ValueError(f"xor_bytes length mismatch: {len(a)} != {len(b)}")
        out = ctypes.create_string_buffer(len(a))
        self._require_lib().lib.pmset_ct_xor_bytes(out, a, b, len(a))
        return out.raw

    def cond_xor_bytes(self, acc: bytes, src: bytes, cond: int) -> bytes:
        if len(acc) != len(src):
            raise ValueError(f"cond_xor_bytes length mismatch: {len(acc)} != {len(src)}")
        buf = ctypes.create_string_buffer(acc, len(acc))
        self._require_lib().lib.pmset_ct_cond_xor_bytes(buf, src, len(acc), cond & 1)
        return buf.raw

    def dpf_bucket_eval(self, buckets: Sequence[bytes], bits: Sequence[int]) -> bytes:
        num_buckets = len(buckets)
        bucket_len = len(buckets[0]) if num_buckets else 0
        if num_buckets == 0 or bucket_len == 0:
            return b""
        if len(bits) < num_buckets:
            raise ValueError(
                f"dpf_bucket_eval requires len(bits) >= len(buckets) ({len(bits)} < {num_buckets})"
            )
        if any(len(b) != bucket_len for b in buckets):
            raise ValueError("All buckets in dpf_bucket_eval must have identical byte length")
        flat = b"".join(buckets)
        bit_bytes = bytes(b & 1 for b in bits[:num_buckets])
        out = ctypes.create_string_buffer(bucket_len)
        self._require_lib().lib.pmset_ct_dpf_bucket_eval(
            out, flat, num_buckets, bucket_len, bit_bytes
        )
        return out.raw

    def bucket_scan_tag(
        self, bucket_bytes: bytes, record_size: int, target_tag: bytes
    ) -> tuple[bool, bytes]:
        if record_size <= 0:
            raise ValueError(f"record_size must be > 0, got {record_size}")
        if len(target_tag) > record_size:
            raise ValueError(
                f"target_tag length ({len(target_tag)}) cannot exceed record_size ({record_size})"
            )
        if len(bucket_bytes) % record_size != 0:
            raise ValueError(
                f"bucket_bytes length ({len(bucket_bytes)}) must be a multiple of record_size ({record_size})"
            )
        num_records = len(bucket_bytes) // record_size
        if num_records == 0:
            return False, b""
        matched = ctypes.create_string_buffer(record_size)
        rc = self._require_lib().lib.pmset_ct_bucket_scan_tag(
            bucket_bytes, num_records, record_size, target_tag, len(target_tag), matched
        )
        if rc < 0:
            raise NativeBackendError(f"[{self._name}] pmset_ct_bucket_scan_tag failed (rc={rc})")
        return bool(rc), matched.raw

    def modexp(self, base: int, exp: int, mod: int, *, order: int | None = None) -> int:
        if mod <= 1:
            raise ValueError(f"mod must be > 1, got {mod}")
        if (mod & 1) == 0:
            raise NativeBackendError(
                f"[{self._name}] Constant-time Montgomery modexp requires an odd modulus"
            )
        lib = self._require_lib().lib
        mod_len = (mod.bit_length() + 7) // 8
        b_val = base if base >= 0 else (base % mod)
        b_bytes = _int_to_be(b_val, mod_len)
        m_bytes = _int_to_be(mod, mod_len)
        out = ctypes.create_string_buffer(mod_len)
        if order is not None and order > 0:
            ord_len = (order.bit_length() + 7) // 8
            e_val = exp if exp >= 0 else (exp % order)
            e_bytes = _int_to_be(e_val, ord_len)
            o_bytes = _int_to_be(order, ord_len)
            rc = lib.pmset_ct_modexp_order(
                b_bytes, len(b_bytes),
                e_bytes, len(e_bytes),
                o_bytes, len(o_bytes),
                m_bytes, len(m_bytes),
                out, mod_len,
            )
        else:
            if exp < 0:
                raise ValueError("Negative exponent must be inverted before modexp")
            e_bytes = _int_to_be(exp, mod_len)
            rc = lib.pmset_ct_modexp(
                b_bytes, len(b_bytes),
                e_bytes, len(e_bytes),
                m_bytes, len(m_bytes),
                out, mod_len,
            )
        if rc != 0:
            raise NativeBackendError(f"[{self._name}] pmset_ct_modexp failed (rc={rc})")
        return int.from_bytes(out.raw, "big")

    def modinv(self, a: int, mod: int) -> int:
        if mod <= 1:
            raise ValueError(f"mod must be > 1, got {mod}")
        lib = self._require_lib().lib
        mod_len = (mod.bit_length() + 7) // 8
        a_val = a if a >= 0 else (a % mod)
        a_bytes = _int_to_be(a_val, mod_len)
        m_bytes = _int_to_be(mod, mod_len)
        out = ctypes.create_string_buffer(mod_len)
        rc = lib.pmset_ct_modinv(a_bytes, len(a_bytes), m_bytes, len(m_bytes), out, mod_len)
        if rc != 0:
            raise ValueError(f"[{self._name}] Value is not invertible modulo {mod} (rc={rc})")
        return int.from_bytes(out.raw, "big")

    def p256_scalar_mul(self, scalar: int, pt_bytes: bytes | None, order_n: int) -> bytes:
        k = scalar if 0 <= scalar < order_n else (scalar % order_n)
        if k == 0:
            return b"\x00"
        s32 = k.to_bytes(32, "big")
        out33 = ctypes.create_string_buffer(33)
        lib = self._require_lib().lib
        if pt_bytes is None:
            rc = lib.pmset_ct_p256_scalar_mul(s32, None, out33)
        else:
            p33 = _pad_point33(pt_bytes)
            if p33[0] == 0x00:
                return b"\x00"
            rc = lib.pmset_ct_p256_scalar_mul(s32, p33, out33)
        if rc != 0:
            raise ValueError(f"[{self._name}] Invalid P-256 scalar mul input (rc={rc})")
        return _unpad_point33(out33.raw)

    def p256_point_add(self, p1_bytes: bytes, p2_bytes: bytes) -> bytes:
        out33 = ctypes.create_string_buffer(33)
        rc = self._require_lib().lib.pmset_ct_p256_point_add(
            _pad_point33(p1_bytes), _pad_point33(p2_bytes), out33
        )
        if rc != 0:
            raise ValueError(f"[{self._name}] Invalid P-256 point add input (rc={rc})")
        return _unpad_point33(out33.raw)

    def p256_point_neg(self, p_bytes: bytes) -> bytes:
        out33 = ctypes.create_string_buffer(33)
        rc = self._require_lib().lib.pmset_ct_p256_point_neg(_pad_point33(p_bytes), out33)
        if rc != 0:
            raise ValueError(f"[{self._name}] Invalid P-256 point neg input (rc={rc})")
        return _unpad_point33(out33.raw)

    def p256_ot_choose(
        self, A_bytes: bytes, b_scalar: int, choice: int
    ) -> tuple[bytes, bytes]:
        B_out = ctypes.create_string_buffer(33)
        shared_out = ctypes.create_string_buffer(33)
        rc = self._require_lib().lib.pmset_ct_p256_ot_choose(
            _pad_point33(A_bytes),
            b_scalar.to_bytes(32, "big"),
            choice & 1,
            B_out,
            shared_out,
        )
        if rc != 0:
            raise ValueError(f"[{self._name}] pmset_ct_p256_ot_choose failed (rc={rc})")
        return _unpad_point33(B_out.raw), _unpad_point33(shared_out.raw)

    def p256_elgamal_is_zero(self, sk: int, c1_bytes: bytes, c2_bytes: bytes) -> bool:
        rc = self._require_lib().lib.pmset_ct_p256_elgamal_is_zero(
            sk.to_bytes(32, "big"), _pad_point33(c1_bytes), _pad_point33(c2_bytes)
        )
        if rc < 0:
            raise ValueError(f"[{self._name}] pmset_ct_p256_elgamal_is_zero failed (rc={rc})")
        return bool(rc)

    def p256_elgamal_any_zero(
        self, sk: int, wire_pairs: Sequence[tuple[bytes, bytes]]
    ) -> bool:
        count = len(wire_pairs)
        if count == 0:
            return False
        c1s = b"".join(_pad_point33(c1) for c1, _ in wire_pairs)
        c2s = b"".join(_pad_point33(c2) for _, c2 in wire_pairs)
        rc = self._require_lib().lib.pmset_ct_p256_elgamal_any_zero(
            sk.to_bytes(32, "big"), c1s, c2s, count
        )
        if rc < 0:
            raise ValueError(f"[{self._name}] pmset_ct_p256_elgamal_any_zero failed (rc={rc})")
        return bool(rc)

    def rlwe_poly_mul(self, a: Sequence[int], b: Sequence[int], q: int) -> list[int]:
        n = len(a)
        if len(b) != n:
            raise ValueError(f"rlwe_poly_mul length mismatch: {len(a)} != {len(b)}")
        if not (0 < q < (1 << 63)):
            raise ValueError(f"rlwe_poly_mul requires 0 < q < 2^63, got {q}")
        arr_a = (ctypes.c_uint64 * n)(*a)
        arr_b = (ctypes.c_uint64 * n)(*b)
        arr_out = (ctypes.c_uint64 * n)()
        self._require_lib().lib.pmset_ct_rlwe_poly_mul(arr_a, arr_b, arr_out, n, q)
        return list(arr_out)

    def rlwe_encrypt(
        self,
        a: Sequence[int],
        sk: Sequence[int],
        err: Sequence[int],
        m: Sequence[int],
        q: int,
        t: int,
    ) -> list[int]:
        n = len(a)
        if not (len(sk) == n and len(err) == n and len(m) == n):
            raise ValueError("rlwe_encrypt polynomial lengths must all equal len(a)")
        if not (0 < q < (1 << 63)) or t < 2:
            raise ValueError(f"rlwe_encrypt requires 0 < q < 2^63 and t >= 2, got q={q}, t={t}")
        arr_a = (ctypes.c_uint64 * n)(*a)
        arr_sk = (ctypes.c_int64 * n)(*sk)
        arr_err = (ctypes.c_int64 * n)(*err)
        arr_m = (ctypes.c_uint64 * n)(*m)
        arr_b = (ctypes.c_uint64 * n)()
        self._require_lib().lib.pmset_ct_rlwe_encrypt(arr_a, arr_sk, arr_err, arr_m, arr_b, n, q, t)
        return list(arr_b)

    def rlwe_decrypt(
        self, a: Sequence[int], b: Sequence[int], sk: Sequence[int], q: int, t: int
    ) -> list[int]:
        n = len(a)
        if not (len(b) == n and len(sk) == n):
            raise ValueError("rlwe_decrypt polynomial lengths must all equal len(a)")
        if not (0 < q < (1 << 63)) or t < 2:
            raise ValueError(f"rlwe_decrypt requires 0 < q < 2^63 and t >= 2, got q={q}, t={t}")
        arr_a = (ctypes.c_uint64 * n)(*a)
        arr_b = (ctypes.c_uint64 * n)(*b)
        arr_sk = (ctypes.c_int64 * n)(*sk)
        arr_m = (ctypes.c_uint64 * n)()
        self._require_lib().lib.pmset_ct_rlwe_decrypt(arr_a, arr_b, arr_sk, arr_m, n, q, t)
        return list(arr_m)

    def rlwe_pir_dot(
        self,
        ct_a_list: Sequence[Sequence[int]],
        ct_b_list: Sequence[Sequence[int]],
        pt_list: Sequence[Sequence[int]],
        q: int,
    ) -> tuple[list[int], list[int]]:
        num_buckets = len(ct_a_list)
        if not (len(ct_b_list) == num_buckets and len(pt_list) == num_buckets):
            raise ValueError("rlwe_pir_dot bucket list lengths must match")
        if not (0 < q < (1 << 63)):
            raise ValueError(f"rlwe_pir_dot requires 0 < q < 2^63, got {q}")
        if num_buckets == 0:
            return [], []
        n = len(ct_a_list[0])
        if (
            any(len(p) != n for p in ct_a_list)
            or any(len(p) != n for p in ct_b_list)
            or any(len(p) != n for p in pt_list)
        ):
            raise ValueError("All polynomials in rlwe_pir_dot must have identical degree n")
        total = num_buckets * n
        flat_a = (ctypes.c_uint64 * total)(*(c for poly in ct_a_list for c in poly))
        flat_b = (ctypes.c_uint64 * total)(*(c for poly in ct_b_list for c in poly))
        flat_pt = (ctypes.c_uint64 * total)(*(c for poly in pt_list for c in poly))
        out_a = (ctypes.c_uint64 * n)()
        out_b = (ctypes.c_uint64 * n)()
        self._require_lib().lib.pmset_ct_rlwe_pir_dot(
            flat_a, flat_b, flat_pt, num_buckets, n, q, out_a, out_b
        )
        return list(out_a), list(out_b)


# ---------------------------------------------------------------------------
# Concrete Built-In Providers: OpenSSL 3.x & AWS-LC (s2n-bignum)
# ---------------------------------------------------------------------------


class OpenSSLNativeBackend(CSharedLibBackend):
    """Constant-time native backend linked against system OpenSSL ``libcrypto``."""

    def __init__(self) -> None:
        super().__init__("openssl", _native_dir() / f"libpmset_ct_openssl{_lib_ext()}")

    def build(self, force: bool = False) -> Path:
        ndir = _native_dir()
        common = ndir / "pmset_ct_common.c"
        prov = ndir / "pmset_ct_openssl.c"
        out = self._lib_path
        if out.is_file() and not force:
            newest = max(common.stat().st_mtime, prov.stat().st_mtime)
            if out.stat().st_mtime >= newest:
                return out
        compiler = os.environ.get("CC") or shutil.which("gcc") or shutil.which("clang")
        if not compiler:
            raise NativeBackendError("No C compiler (gcc/clang) found to build OpenSSL backend")
        cmd = [
            compiler,
            "-O2",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-fPIC",
            "-fvisibility=hidden",
            "-shared",
            str(common),
            str(prov),
            "-o",
            str(out),
            "-lcrypto",
        ]
        built = _compile_shared_lib(cmd, out)
        self._tried_load = False
        self._loaded = None
        return built


class AWSLCNativeBackend(CSharedLibBackend):
    """Constant-time native backend linked statically against AWS-LC (s2n-bignum).

    Built with ``-fvisibility=hidden -Wl,-Bsymbolic -Wl,--exclude-libs,ALL`` so
    all AWS-LC internal symbols are hidden and cannot collide with Python's
    system OpenSSL ``libcrypto.so``.
    """

    def __init__(self, awslc_prefix: Path | None = None) -> None:
        super().__init__("aws-lc", _native_dir() / f"libpmset_ct_awslc{_lib_ext()}")
        self._awslc_prefix = awslc_prefix

    def build(self, force: bool = False) -> Path:
        ndir = _native_dir()
        common = ndir / "pmset_ct_common.c"
        prov = ndir / "pmset_ct_awslc.c"
        out = self._lib_path
        if out.is_file() and not force:
            newest = max(common.stat().st_mtime, prov.stat().st_mtime)
            if out.stat().st_mtime >= newest:
                return out
        prefix = self._awslc_prefix or find_awslc_prefix()
        if prefix is None:
            raise NativeBackendError(
                "AWS-LC installation not found. Set AWSLC_PREFIX to a directory "
                "containing include/openssl/is_awslc.h and lib/libcrypto.a."
            )
        compiler = os.environ.get("CC") or shutil.which("gcc") or shutil.which("clang")
        if not compiler:
            raise NativeBackendError("No C compiler (gcc/clang) found to build AWS-LC backend")

        static_lib = _awslc_static_lib(prefix)
        cmd = [
            compiler,
            "-O2",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-fPIC",
            "-fvisibility=hidden",
            "-shared",
            f"-I{prefix / 'include'}",
            str(common),
            str(prov),
            str(static_lib),
            "-lpthread",
            "-o",
            str(out),
        ]
        if platform.system() == "Linux":
            cmd.extend(["-Wl,-Bsymbolic", "-Wl,--exclude-libs,ALL"])
        built = _compile_shared_lib(cmd, out)
        self._tried_load = False
        self._loaded = None
        return built


# ---------------------------------------------------------------------------
# Pluggable Backend Registry & Runtime Selection
# ---------------------------------------------------------------------------


_BACKENDS: dict[str, NativeCryptoBackend] = {}
_AUTO_PRIORITY: list[str] = ["aws-lc", "openssl"]
_ACTIVE_BACKEND_NAME: str | None = os.environ.get("PMSET_NATIVE_BACKEND") or None
_STRICT_MODE: bool = os.environ.get("PMSET_REQUIRE_NATIVE", "0") in ("1", "true", "TRUE", "yes")
_DISABLE_NATIVE_FOR_TEST: bool = False


def register_native_backend(
    backend: NativeCryptoBackend, *, overwrite: bool = False
) -> NativeCryptoBackend:
    """Register a pluggable :class:`NativeCryptoBackend` implementation."""
    name = backend.name
    if name in _BACKENDS and not overwrite:
        raise ValueError(f"Native backend '{name}' is already registered")
    _BACKENDS[name] = backend
    if name not in _AUTO_PRIORITY:
        _AUTO_PRIORITY.append(name)
    return backend


# Register built-in constant-time backends
register_native_backend(AWSLCNativeBackend())
register_native_backend(OpenSSLNativeBackend())


def list_native_backends() -> list[str]:
    """Return sorted names of all registered native backends."""
    return sorted(_BACKENDS.keys())


def available_native_backends() -> list[str]:
    """Return sorted names of registered native backends currently loadable on this host."""
    return [name for name in list_native_backends() if _BACKENDS[name].is_available()]


def get_native_backend(name: str | None = None) -> NativeCryptoBackend | None:
    """Resolve a registered backend by ``name``, or resolve the active/auto-selected backend."""
    if _DISABLE_NATIVE_FOR_TEST:
        return None
    if os.environ.get("PMSET_DISABLE_NATIVE", "0") in ("1", "true", "TRUE"):
        return None

    target = name if name is not None else _ACTIVE_BACKEND_NAME
    if target is not None:
        if target not in _BACKENDS:
            available = ", ".join(list_native_backends())
            raise NativeBackendError(
                f"Unknown native backend '{target}'. Registered: {available}"
            )
        backend = _BACKENDS[target]
        if not backend.is_available():
            raise NativeBackendError(
                f"Selected native backend '{target}' is not available on this system"
            )
        return backend

    for candidate in _AUTO_PRIORITY:
        backend = _BACKENDS.get(candidate)
        if backend is not None and backend.is_available():
            return backend
    return None


def set_native_backend(name: str) -> NativeBackendInfo:
    """Switch the active constant-time native backend at runtime (e.g. ``'aws-lc'`` or ``'openssl'``)."""
    global _ACTIVE_BACKEND_NAME
    if name not in _BACKENDS:
        available = ", ".join(list_native_backends())
        raise NativeBackendError(f"Unknown native backend '{name}'. Registered: {available}")
    backend = _BACKENDS[name]
    if not backend.is_available():
        raise NativeBackendError(f"Native backend '{name}' is not available on this system")
    _ACTIVE_BACKEND_NAME = name
    return backend.info(strict_mode=_STRICT_MODE)


@contextlib.contextmanager
def use_native_backend(name: str) -> Iterator[NativeBackendInfo]:
    """Context manager temporarily switching the active native backend to ``name``."""
    global _ACTIVE_BACKEND_NAME
    prev = _ACTIVE_BACKEND_NAME
    info = set_native_backend(name)
    try:
        yield info
    finally:
        _ACTIVE_BACKEND_NAME = prev


def build_native_library(backend: str = "all", force: bool = False) -> dict[str, Path]:
    """Compile one (``'openssl'``/``'aws-lc'``) or ``'all'`` available native backends."""
    targets = list_native_backends() if backend == "all" else [backend]
    built: dict[str, Path] = {}
    for name in targets:
        if name not in _BACKENDS:
            raise NativeBackendError(f"Unknown native backend '{name}'")
        try:
            path = _BACKENDS[name].build(force=force)
            if path is not None:
                built[name] = path
        except NativeBackendError:
            if backend != "all":
                raise
    return built


def require_constant_time(enabled: bool = True) -> None:
    """Enforce fail-closed constant-time native execution (raises if unavailable)."""
    global _STRICT_MODE
    _STRICT_MODE = enabled
    if enabled and get_native_backend() is None:
        raise NativeBackendError(
            "Constant-time native backend is required but unavailable. "
            "Build 'aws-lc' or 'openssl' backend via `pmset.build_native_library()`."
        )


def is_native_available() -> bool:
    """Return True iff an active constant-time native backend is loaded."""
    try:
        return get_native_backend() is not None
    except NativeBackendError:
        return False


def backend_info(name: str | None = None) -> NativeBackendInfo:
    """Return diagnostic details about the active (or named) constant-time native backend."""
    if name is not None:
        if name not in _BACKENDS:
            raise NativeBackendError(f"Unknown native backend '{name}'")
        return _BACKENDS[name].info(strict_mode=_STRICT_MODE)
    backend = get_native_backend()
    if backend is None:
        return NativeBackendInfo(
            available=False,
            backend_name=None,
            provider_version=None,
            library_path=None,
            abi_version=None,
            strict_mode=_STRICT_MODE,
        )
    return backend.info(strict_mode=_STRICT_MODE)


def _get_or_enforce() -> NativeCryptoBackend | None:
    backend = get_native_backend()
    if backend is None and _STRICT_MODE:
        raise NativeBackendError("Constant-time native backend required (PMSET_REQUIRE_NATIVE=1)")
    return backend


# ---------------------------------------------------------------------------
# High-level constant-time operations delegating to the active plugged backend
# ---------------------------------------------------------------------------


def ct_memcmp(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    backend = _get_or_enforce()
    if backend is not None:
        return backend.memcmp(a, b)
    import hmac

    return hmac.compare_digest(a, b)


def ct_select_bytes(a: bytes, b: bytes, select_b: int) -> bytes:
    if len(a) != len(b):
        raise ValueError(f"ct_select_bytes length mismatch: {len(a)} != {len(b)}")
    backend = _get_or_enforce()
    if backend is not None:
        return backend.select_bytes(a, b, select_b)
    mask = (-(select_b & 1)) & 0xFF
    nmask = (~mask) & 0xFF
    return bytes((x & nmask) | (y & mask) for x, y in zip(a, b))


def ct_xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError(f"ct_xor_bytes length mismatch: {len(a)} != {len(b)}")
    backend = _get_or_enforce()
    if backend is not None:
        return backend.xor_bytes(a, b)
    return bytes(x ^ y for x, y in zip(a, b))


def ct_cond_xor_bytes(acc: bytes, src: bytes, cond: int) -> bytes:
    if len(acc) != len(src):
        raise ValueError("ct_cond_xor_bytes length mismatch")
    backend = _get_or_enforce()
    if backend is not None:
        return backend.cond_xor_bytes(acc, src, cond)
    mask = (-(cond & 1)) & 0xFF
    return bytes(x ^ (y & mask) for x, y in zip(acc, src))


def ct_dpf_bucket_eval(buckets: Sequence[bytes], bits: Sequence[int]) -> bytes:
    if not buckets or not buckets[0]:
        return b""
    num_buckets = len(buckets)
    bucket_len = len(buckets[0])
    if len(bits) < num_buckets:
        raise ValueError(
            f"ct_dpf_bucket_eval requires len(bits) >= len(buckets) ({len(bits)} < {num_buckets})"
        )
    if any(len(b) != bucket_len for b in buckets):
        raise ValueError("All buckets in ct_dpf_bucket_eval must have identical byte length")
    backend = _get_or_enforce()
    if backend is not None:
        return backend.dpf_bucket_eval(buckets, bits)
    acc = bytearray(bucket_len)
    for bit, bkt in zip(bits, buckets):
        mask = (-(bit & 1)) & 0xFF
        for j in range(bucket_len):
            acc[j] ^= bkt[j] & mask
    return bytes(acc)


def ct_bucket_scan_tag(
    bucket_bytes: bytes, record_size: int, target_tag: bytes
) -> tuple[bool, bytes]:
    if record_size <= 0:
        raise ValueError(f"record_size must be > 0, got {record_size}")
    if len(target_tag) > record_size:
        raise ValueError(
            f"target_tag length ({len(target_tag)}) cannot exceed record_size ({record_size})"
        )
    if len(bucket_bytes) % record_size != 0:
        raise ValueError(
            f"bucket_bytes length ({len(bucket_bytes)}) must be a multiple of record_size ({record_size})"
        )
    if not bucket_bytes:
        return False, b""
    backend = _get_or_enforce()
    if backend is not None:
        return backend.bucket_scan_tag(bucket_bytes, record_size, target_tag)
    num_records = len(bucket_bytes) // record_size
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
    if mod <= 1:
        raise ValueError("mod must be > 1")
    if exp < 0:
        base = ct_modinv(base, mod)
        exp = -exp
    backend = _get_or_enforce()
    if backend is not None:
        if (mod & 1) == 1:
            return backend.modexp(base, exp, mod, order=order)
        if _STRICT_MODE:
            raise NativeBackendError(
                "Constant-time native modexp requires an odd modulus (PMSET_REQUIRE_NATIVE=1)"
            )
    return pow(base, exp, mod)


def ct_modinv(a: int, mod: int) -> int:
    backend = _get_or_enforce()
    if backend is not None:
        return backend.modinv(a, mod)
    return pow(a, -1, mod)


def ct_p256_scalar_mul(scalar: int, pt_bytes: bytes | None, order_n: int) -> bytes | None:
    backend = _get_or_enforce()
    if backend is None:
        return None
    return backend.p256_scalar_mul(scalar, pt_bytes, order_n)


def ct_p256_point_add(p1_bytes: bytes, p2_bytes: bytes) -> bytes | None:
    backend = _get_or_enforce()
    if backend is None:
        return None
    return backend.p256_point_add(p1_bytes, p2_bytes)


def ct_p256_point_neg(p_bytes: bytes) -> bytes | None:
    backend = _get_or_enforce()
    if backend is None:
        return None
    return backend.p256_point_neg(p_bytes)


def ct_p256_ot_choose(
    A_bytes: bytes, b_scalar: int, choice: int
) -> tuple[bytes, bytes] | None:
    backend = _get_or_enforce()
    if backend is None:
        return None
    return backend.p256_ot_choose(A_bytes, b_scalar, choice)


def ct_p256_elgamal_is_zero(sk: int, c1_bytes: bytes, c2_bytes: bytes) -> bool | None:
    backend = _get_or_enforce()
    if backend is None:
        return None
    return backend.p256_elgamal_is_zero(sk, c1_bytes, c2_bytes)


def ct_p256_elgamal_any_zero(
    sk: int, wire_pairs: Sequence[tuple[bytes, bytes]]
) -> bool | None:
    backend = _get_or_enforce()
    if backend is None:
        return None
    return backend.p256_elgamal_any_zero(sk, wire_pairs)


def _check_rlwe_q_native(backend: NativeCryptoBackend | None, q: int) -> bool:
    if backend is None:
        return False
    if not (0 < q < (1 << 63)):
        if _STRICT_MODE:
            raise NativeBackendError(
                f"Constant-time native RLWE kernel requires 0 < q < 2^63, got q={q}"
            )
        return False
    return True


def ct_rlwe_poly_mul(a: Sequence[int], b: Sequence[int], q: int) -> list[int] | None:
    backend = _get_or_enforce()
    if not _check_rlwe_q_native(backend, q):
        return None
    assert backend is not None
    return backend.rlwe_poly_mul(a, b, q)


def ct_rlwe_encrypt(
    a: Sequence[int], sk: Sequence[int], err: Sequence[int], m: Sequence[int], q: int, t: int
) -> list[int] | None:
    backend = _get_or_enforce()
    if not _check_rlwe_q_native(backend, q):
        return None
    assert backend is not None
    return backend.rlwe_encrypt(a, sk, err, m, q, t)


def ct_rlwe_decrypt(
    a: Sequence[int], b: Sequence[int], sk: Sequence[int], q: int, t: int
) -> list[int] | None:
    backend = _get_or_enforce()
    if not _check_rlwe_q_native(backend, q):
        return None
    assert backend is not None
    return backend.rlwe_decrypt(a, b, sk, q, t)


def ct_rlwe_pir_dot(
    ct_a_list: Sequence[Sequence[int]],
    ct_b_list: Sequence[Sequence[int]],
    pt_list: Sequence[Sequence[int]],
    q: int,
) -> tuple[list[int], list[int]] | None:
    backend = _get_or_enforce()
    if not _check_rlwe_q_native(backend, q):
        return None
    assert backend is not None
    return backend.rlwe_pir_dot(ct_a_list, ct_b_list, pt_list, q)
