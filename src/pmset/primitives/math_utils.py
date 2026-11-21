"""Cryptographic math utilities using CSPRNG (`secrets`)."""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from typing import Sequence

# RFC 3526 Group 14: 2048-bit MODP safe prime p = 2q + 1 where q is prime.
RFC3526_GROUP14_P = (
    0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
    << 1856
) | (
    0x29024E088A67CC74020BBEA63B139B22514A08798E3404DD
    << 1664
) | (
    0xEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
    << 1472
) | (
    0xE485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
    << 1280
) | (
    0xEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D
    << 1088
) | (
    0xC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F
    << 896
) | (
    0x83655D23DCA3AD961C62F356208552BB9ED529077096966D
    << 704
) | (
    0x670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B
    << 512
) | (
    0xE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9
    << 320
) | (
    0xDE2BCBF6955817183995497CEA956AE515D2261898FA0510
    << 128
) | 0x15728E5A8AACAA68FFFFFFFFFFFFFFFF

RFC3526_GROUP14_Q = (RFC3526_GROUP14_P - 1) // 2

# 512-bit safe prime (p = 2q + 1, both p and q prime) for fast interactive / testing modes.
# Generated deterministically and verified prime: p = 2^512 - 38117? No, let's use
# a verified RFC/standard Oakleys/safe prime or generate+verify at import if needed.
# Actually RFC 2409 / Oakley Group 1 (768-bit safe prime) is a classic standard safe prime!
RFC2409_GROUP1_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16,
)
RFC2409_GROUP1_Q = (RFC2409_GROUP1_P - 1) // 2

# 256-bit prime kept for backward compatibility with legacy DHOPRF
LEGACY_OPRF_PRIME = (1 << 256) - 189

_SMALL_PRIMES = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251,
)


def is_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin primality test using cryptographically secure random bases.

    Deterministic for small integers via trial division; error probability <= 4^(-rounds)
    for arbitrary integers. Rejects all Carmichael numbers.
    """
    if n < 2:
        return False
    for sp in _SMALL_PRIMES:
        if n == sp:
            return True
        if n % sp == 0:
            return False

    d = n - 1
    s = 0
    while (d & 1) == 0:
        d >>= 1
        s += 1

    span = n - 3  # bases in [2, n - 2]
    for _ in range(rounds):
        a = 2 + secrets.randbelow(span)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def is_safe_prime(p: int, rounds: int = 40) -> bool:
    """Return True iff p is prime and q = (p - 1) // 2 is also prime."""
    if p < 5 or (p & 1) == 0:
        return False
    q = (p - 1) >> 1
    return is_prime(q, rounds=rounds) and is_prime(p, rounds=rounds)


def generate_prime(bits: int) -> int:
    """Generate a cryptographically random prime with exactly ``bits`` bits."""
    if bits < 2:
        raise ValueError(f"Prime bit length must be >= 2, got {bits}")
    if bits == 2:
        return secrets.choice([2, 3])
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(candidate):
            return candidate


def random_int_range(low: int, high: int) -> int:
    """Cryptographically secure uniform integer in the inclusive range [low, high]."""
    if high < low:
        raise ValueError(f"Invalid range [{low}, {high}]")
    return low + secrets.randbelow(high - low + 1)


def random_coprime(modulus: int) -> int:
    """Sample a uniformly random integer in [1, modulus - 1] coprime to ``modulus``."""
    if modulus < 2:
        raise ValueError("modulus must be >= 2")
    while True:
        r = 1 + secrets.randbelow(modulus - 1)
        if math.gcd(r, modulus) == 1:
            return r


def lcm(a: int, b: int) -> int:
    """Least common multiple of two integers."""
    return abs(a * b) // math.gcd(a, b)


def hkdf_sha256(ikm: bytes, length: int, salt: bytes = b"", info: bytes = b"") -> bytes:
    """RFC 5869 HKDF using HMAC-SHA256."""
    if length < 0 or length > 255 * 32:
        raise ValueError(f"Invalid HKDF output length: {length}")
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


def prg_expand(seed: bytes, out_len: int, domain: bytes = b"PMSET-PRG") -> bytes:
    """Expand a seed into ``out_len`` pseudorandom bytes using SHAKE-256."""
    h = hashlib.shake_256()
    h.update(domain)
    h.update(len(seed).to_bytes(4, "big"))
    h.update(seed)
    return h.digest(out_len)


def polynomial_from_roots(roots: Sequence[int], modulus: int) -> list[int]:
    """Compute coefficients [c_0, c_1, ..., c_d] of P(X) = prod_{r in roots} (X - r) mod modulus."""
    coeffs = [1 % modulus]
    for r in roots:
        r_mod = r % modulus
        new_coeffs = [0] * (len(coeffs) + 1)
        for i, c in enumerate(coeffs):
            new_coeffs[i] = (new_coeffs[i] - c * r_mod) % modulus
            new_coeffs[i + 1] = (new_coeffs[i + 1] + c) % modulus
        coeffs = new_coeffs
    return coeffs


def eval_polynomial(coeffs: Sequence[int], x: int, modulus: int) -> int:
    """Evaluate sum_i coeffs[i] * x^i mod modulus via Horner's method."""
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % modulus
    return acc


def lagrange_coefficients_at_zero(xs: Sequence[int], prime: int) -> list[int]:
    """Compute Lagrange interpolation weights lambda_j at X = 0 over F_prime."""
    k = len(xs)
    if k == 0:
        raise ValueError("Need at least one evaluation point")
    if len(set(x % prime for x in xs)) != k:
        raise ValueError("Evaluation points must be distinct modulo prime")
    weights: list[int] = []
    for j in range(k):
        num = 1
        den = 1
        xj = xs[j] % prime
        for m in range(k):
            if m == j:
                continue
            xm = xs[m] % prime
            num = (num * (-xm)) % prime
            den = (den * (xj - xm)) % prime
        weights.append((num * pow(den, -1, prime)) % prime)
    return weights


def shamir_share(
    secret: int,
    num_shares: int,
    threshold: int,
    prime: int,
    xs: Sequence[int] | None = None,
) -> list[tuple[int, int]]:
    """Split ``secret`` into ``num_shares`` Shamir shares with reconstruction threshold ``threshold``.

    Privacy holds against any coalition of up to ``threshold - 1`` shares.
    """
    if not (1 <= threshold <= num_shares):
        raise ValueError(f"Require 1 <= threshold ({threshold}) <= num_shares ({num_shares})")
    eval_xs = list(xs) if xs is not None else list(range(1, num_shares + 1))
    if len(eval_xs) != num_shares:
        raise ValueError("Length of xs must equal num_shares")
    coeffs = [secret % prime] + [secrets.randbelow(prime) for _ in range(threshold - 1)]
    return [(x, eval_polynomial(coeffs, x, prime)) for x in eval_xs]


def shamir_reconstruct(shares: Sequence[tuple[int, int]], prime: int) -> int:
    """Reconstruct a Shamir-shared secret at X = 0 over F_prime."""
    xs = [x for x, _ in shares]
    weights = lagrange_coefficients_at_zero(xs, prime)
    acc = 0
    for (_, y), w in zip(shares, weights):
        acc = (acc + y * w) % prime
    return acc
