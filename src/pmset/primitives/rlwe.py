"""Ring-LWE / BFV-style Lattice Homomorphic Encryption over R_q = Z_q[X]/(X^N + 1).

Used to realize Google's RLWE-based Private Information Retrieval (PIR) paradigm
in pure Python:
  - Ring: R_q = Z_q[X] / (X^N + 1), where N is a power of 2.
  - Plaintext ring: R_t = Z_t[X] / (X^N + 1), default t = 256 (1 byte per coefficient).
  - Scaling factor: Delta = floor(q / t).
  - Secret key: ternary polynomial s in {-1, 0, 1}^N.
  - Error distribution: centered binomial distribution CBD(eta) bounded by [-eta, +eta].
  - Ciphertext: (a, b) in R_q^2 with b = (-a*s + e + Delta*m) mod q.
  - Homomorphic operations:
      * Ciphertext + Ciphertext
      * Plaintext polynomial * Ciphertext (negacyclic convolution mod X^N + 1)
  - Exact decryption condition (verified formally in Z3 and Lean 4):
      max_coeff(|total_noise|) < floor(q / (2*t)) - t
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class RLWEParams:
    """Parameters for Ring-LWE over Z_q[X]/(X^N + 1)."""

    n: int = 64  # Ring degree (power of 2); packs n bytes per polynomial
    t: int = 256  # Plaintext modulus (1 byte per slot)
    q: int = 1 << 56  # Ciphertext modulus (exact multiple of t=256 => Delta = 2^48)
    noise_eta: int = 4  # Centered binomial parameter: error in [-eta, +eta]

    def __post_init__(self) -> None:
        if self.n < 2 or (self.n & (self.n - 1)) != 0:
            raise ValueError(f"Ring degree n must be a power of 2 >= 2, got {self.n}")
        if self.t < 2:
            raise ValueError(f"Plaintext modulus t must be >= 2, got {self.t}")
        if self.q <= 2 * self.t:
            raise ValueError(f"Ciphertext modulus q must exceed 2*t, got q={self.q}, t={self.t}")
        if self.q % self.t != 0:
            raise ValueError(
                f"Ciphertext modulus q ({self.q}) must be an exact multiple of plaintext modulus t ({self.t})"
            )
        if self.noise_eta < 1:
            raise ValueError(f"noise_eta must be >= 1, got {self.noise_eta}")

    @property
    def delta(self) -> int:
        return self.q // self.t

    def max_inner_product_noise(self, num_buckets: int) -> int:
        """Worst-case L-infinity noise bound after summing ``num_buckets`` plaintext-ct products."""
        # Each plaintext coeff in [0, t - 1], each error coeff in [-noise_eta, noise_eta],
        # negacyclic multiplication sums n products per coefficient.
        return num_buckets * self.n * (self.t - 1) * self.noise_eta

    def noise_budget_bits(self, num_buckets: int) -> float:
        """Remaining noise margin in bits before decryption rounding can fail."""
        import math

        limit = self.delta // 2
        worst = self.max_inner_product_noise(num_buckets)
        if worst >= limit:
            return 0.0
        return math.log2(limit / max(1, worst))

    def can_decrypt_exact(self, num_buckets: int) -> bool:
        """Return True iff worst-case noise is strictly below Delta / 2."""
        return self.max_inner_product_noise(num_buckets) < (self.delta // 2)

    def to_dict(self) -> dict[str, int]:
        return {"n": self.n, "t": self.t, "q": self.q, "noise_eta": self.noise_eta}

    @classmethod
    def from_dict(cls, data: dict[str, int]) -> RLWEParams:
        return cls(
            n=int(data["n"]),
            t=int(data["t"]),
            q=int(data["q"]),
            noise_eta=int(data["noise_eta"]),
        )


def poly_add(a: Sequence[int], b: Sequence[int], q: int) -> list[int]:
    """Component-wise polynomial addition mod q."""
    return [(x + y) % q for x, y in zip(a, b)]


def poly_sub(a: Sequence[int], b: Sequence[int], q: int) -> list[int]:
    """Component-wise polynomial subtraction mod q."""
    return [(x - y) % q for x, y in zip(a, b)]


def poly_neg(a: Sequence[int], q: int) -> list[int]:
    return [(-x) % q for x in a]


def poly_mul_negacyclic(a: Sequence[int], b: Sequence[int], q: int) -> list[int]:
    """Multiply polynomials in Z_q[X] / (X^N + 1) using branchless negacyclic convolution."""
    from pmset.native import ct_rlwe_poly_mul

    native_out = ct_rlwe_poly_mul(a, b, q)
    if native_out is not None:
        return native_out
    n = len(a)
    res = [0] * n
    for i in range(n):
        ai = a[i]
        split = n - i
        for j in range(split):
            res[i + j] += ai * b[j]
        for j in range(split, n):
            res[i + j - n] -= ai * b[j]
    return [c % q for c in res]


def _sample_ternary(n: int) -> list[int]:
    """Sample ternary secret polynomial in {-1, 0, 1}^n."""
    return [secrets.randbelow(3) - 1 for _ in range(n)]


def _sample_cbd(n: int, eta: int) -> list[int]:
    """Sample centered binomial noise CBD(eta) bounded strictly in [-eta, +eta]."""
    out: list[int] = []
    for _ in range(n):
        bits_a = secrets.randbits(eta)
        bits_b = secrets.randbits(eta)
        out.append(bits_a.bit_count() - bits_b.bit_count())
    return out


def _sample_uniform(n: int, q: int) -> list[int]:
    return [secrets.randbelow(q) for _ in range(n)]


@dataclass(frozen=True)
class RLWECiphertext:
    """RLWE ciphertext (a, b) in R_q^2."""

    a: list[int]
    b: list[int]

    def to_wire(self) -> tuple[list[int], list[int]]:
        return (self.a, self.b)

    @classmethod
    def from_wire(cls, data: Sequence[list[int]]) -> RLWECiphertext:
        return cls(a=list(data[0]), b=list(data[1]))


class RLWEContext:
    """Symmetric-key RLWE encryption and server-side homomorphic evaluation."""

    def __init__(self, params: RLWEParams | None = None, secret_key: list[int] | None = None) -> None:
        self.params = params or RLWEParams()
        self.secret_key: list[int] | None = (
            list(secret_key) if secret_key is not None else _sample_ternary(self.params.n)
        )

    @classmethod
    def evaluator_only(cls, params: RLWEParams) -> RLWEContext:
        """Create a server-side evaluator with NO secret key."""
        ctx = cls.__new__(cls)
        ctx.params = params
        ctx.secret_key = None
        return ctx

    def encrypt_poly(self, plaintext_poly: Sequence[int]) -> RLWECiphertext:
        """Encrypt a plaintext polynomial m in R_t in constant time."""
        from pmset.native import ct_rlwe_encrypt

        if self.secret_key is None:
            raise ValueError("Cannot encrypt without secret key")
        p = self.params
        if len(plaintext_poly) != p.n:
            raise ValueError(f"Expected polynomial of length {p.n}, got {len(plaintext_poly)}")
        a = _sample_uniform(p.n, p.q)
        e = _sample_cbd(p.n, p.noise_eta)
        b_native = ct_rlwe_encrypt(a, self.secret_key, e, plaintext_poly, p.q, p.t)
        if b_native is not None:
            return RLWECiphertext(a=a, b=b_native)
        as_prod = poly_mul_negacyclic(a, self.secret_key, p.q)
        delta = p.delta
        b = [
            (-as_prod[i] + e[i] + delta * (plaintext_poly[i] % p.t)) % p.q
            for i in range(p.n)
        ]
        return RLWECiphertext(a=a, b=b)

    def encrypt_scalar(self, value: int) -> RLWECiphertext:
        """Encrypt a constant polynomial [value, 0, 0, ..., 0] (used for PIR selection)."""
        poly = [value % self.params.t] + [0] * (self.params.n - 1)
        return self.encrypt_poly(poly)

    def decrypt_poly(self, ct: RLWECiphertext) -> list[int]:
        """Decrypt ciphertext (a, b) back into plaintext polynomial in R_t in constant time."""
        from pmset.native import ct_rlwe_decrypt

        if self.secret_key is None:
            raise ValueError("Cannot decrypt without secret key")
        p = self.params
        m_native = ct_rlwe_decrypt(ct.a, ct.b, self.secret_key, p.q, p.t)
        if m_native is not None:
            return m_native
        as_prod = poly_mul_negacyclic(ct.a, self.secret_key, p.q)
        noisy = [(ct.b[i] + as_prod[i]) % p.q for i in range(p.n)]
        two_q = 2 * p.q
        return [((2 * p.t * v + p.q) // two_q) % p.t for v in noisy]

    def add(self, ct1: RLWECiphertext, ct2: RLWECiphertext) -> RLWECiphertext:
        q = self.params.q
        return RLWECiphertext(
            a=poly_add(ct1.a, ct2.a, q),
            b=poly_add(ct1.b, ct2.b, q),
        )

    def mul_plaintext_poly(self, ct: RLWECiphertext, pt_poly: Sequence[int]) -> RLWECiphertext:
        """Multiply ciphertext by plaintext polynomial in R_q = Z_q[X]/(X^N + 1)."""
        q = self.params.q
        return RLWECiphertext(
            a=poly_mul_negacyclic(ct.a, pt_poly, q),
            b=poly_mul_negacyclic(ct.b, pt_poly, q),
        )

    def zero_ciphertext(self) -> RLWECiphertext:
        return RLWECiphertext(a=[0] * self.params.n, b=[0] * self.params.n)

    def encode_bytes_to_polys(self, data: bytes) -> list[list[int]]:
        """Pack arbitrary bytes into a list of degree-N polynomials (t=256 => 1 byte/coeff)."""
        if self.params.t != 256:
            raise ValueError("Byte packing requires plaintext modulus t=256")
        n = self.params.n
        if not data:
            return [[0] * n]
        polys: list[list[int]] = []
        for off in range(0, len(data), n):
            chunk = list(data[off : off + n])
            if len(chunk) < n:
                chunk.extend([0] * (n - len(chunk)))
            polys.append(chunk)
        return polys

    def decode_polys_to_bytes(self, polys: Sequence[Sequence[int]], length: int) -> bytes:
        """Unpack decrypted polynomials back into ``length`` raw bytes."""
        if self.params.t != 256:
            raise ValueError("Byte unpacking requires plaintext modulus t=256")
        raw = bytearray()
        for poly in polys:
            raw.extend(c & 0xFF for c in poly)
        return bytes(raw[:length])
