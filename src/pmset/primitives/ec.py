"""Pure-Python prime-order elliptic curve arithmetic on NIST P-256 (secp256r1).

Uses Jacobian projective coordinates (X, Y, Z) representing affine (X/Z^2, Y/Z^3)
for fast scalar multiplication without intermediate modular inversions.

P-256 has prime order n and cofactor h = 1, so every non-identity point on the
curve generates the entire prime-order group — eliminating small-subgroup
attacks that affect composite-order Z_p* groups.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

# NIST P-256 / secp256r1 domain parameters (FIPS 186-4 / SEC 2)
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = (P256_P - 3) % P256_P
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

# (p + 1) // 4 for square root extraction since P256_P ≡ 3 (mod 4)
_P256_SQRT_EXP = (P256_P + 1) >> 2


@dataclass(frozen=True)
class ECPoint:
    """Affine point on NIST P-256, or the point at infinity (x=None, y=None)."""

    x: int | None
    y: int | None

    @property
    def is_infinity(self) -> bool:
        return self.x is None or self.y is None

    def is_on_curve(self) -> bool:
        if self.is_infinity:
            return True
        assert self.x is not None and self.y is not None
        if not (0 <= self.x < P256_P and 0 <= self.y < P256_P):
            return False
        lhs = (self.y * self.y) % P256_P
        rhs = (pow(self.x, 3, P256_P) + P256_A * self.x + P256_B) % P256_P
        return lhs == rhs

    def to_compressed_bytes(self) -> bytes:
        """SEC1 compressed encoding (33 bytes; 1 zero byte for infinity)."""
        if self.is_infinity:
            return b"\x00"
        assert self.x is not None and self.y is not None
        prefix = b"\x03" if (self.y & 1) else b"\x02"
        return prefix + self.x.to_bytes(32, "big")

    @classmethod
    def from_compressed_bytes(cls, data: bytes) -> ECPoint:
        """Decode SEC1 compressed point and validate it lies on P-256."""
        if data == b"\x00":
            return P256_INFINITY
        if len(data) != 33 or data[0] not in (0x02, 0x03):
            raise ValueError("Invalid SEC1 compressed P-256 point encoding")
        x = int.from_bytes(data[1:], "big")
        if x >= P256_P:
            raise ValueError("Point x-coordinate out of field range")
        rhs = (pow(x, 3, P256_P) + P256_A * x + P256_B) % P256_P
        y = pow(rhs, _P256_SQRT_EXP, P256_P)
        if (y * y) % P256_P != rhs:
            raise ValueError("Decoded coordinates do not lie on P-256")
        want_odd = data[0] == 0x03
        if bool(y & 1) != want_odd:
            y = P256_P - y
        pt = cls(x, y)
        return pt

    def __neg__(self) -> ECPoint:
        if self.is_infinity:
            return self
        assert self.x is not None and self.y is not None
        return ECPoint(self.x, (-self.y) % P256_P)

    def __add__(self, other: ECPoint) -> ECPoint:
        return point_add(self, other)

    def __sub__(self, other: ECPoint) -> ECPoint:
        return point_add(self, -other)

    def __rmul__(self, scalar: int) -> ECPoint:
        return scalar_mul(scalar, self)


P256_INFINITY = ECPoint(None, None)
P256_GENERATOR = ECPoint(P256_GX, P256_GY)


def _jac_double(X1: int, Y1: int, Z1: int) -> tuple[int, int, int]:
    """Point doubling in Jacobian coordinates using a = -3 optimization."""
    if Z1 == 0 or Y1 == 0:
        return (0, 1, 0)
    p = P256_P
    Y1_sq = (Y1 * Y1) % p
    S = (4 * X1 * Y1_sq) % p
    Z1_sq = (Z1 * Z1) % p
    # Since a = -3 mod p: M = 3 * (X1 - Z1^2) * (X1 + Z1^2)
    M = (3 * (X1 - Z1_sq) * (X1 + Z1_sq)) % p
    X3 = (M * M - 2 * S) % p
    Y1_4 = (Y1_sq * Y1_sq) % p
    Y3 = (M * (S - X3) - 8 * Y1_4) % p
    Z3 = (2 * Y1 * Z1) % p
    return (X3, Y3, Z3)


def _jac_add(
    X1: int, Y1: int, Z1: int, X2: int, Y2: int, Z2: int
) -> tuple[int, int, int]:
    """Point addition in Jacobian coordinates."""
    if Z1 == 0:
        return (X2, Y2, Z2)
    if Z2 == 0:
        return (X1, Y1, Z1)
    p = P256_P
    Z1_sq = (Z1 * Z1) % p
    Z2_sq = (Z2 * Z2) % p
    U1 = (X1 * Z2_sq) % p
    U2 = (X2 * Z1_sq) % p
    S1 = (Y1 * Z2 * Z2_sq) % p
    S2 = (Y2 * Z1 * Z1_sq) % p
    if U1 == U2:
        if S1 != S2:
            return (0, 1, 0)
        return _jac_double(X1, Y1, Z1)
    H = (U2 - U1) % p
    R = (S2 - S1) % p
    H_sq = (H * H) % p
    H_cu = (H * H_sq) % p
    U1_H_sq = (U1 * H_sq) % p
    X3 = (R * R - H_cu - 2 * U1_H_sq) % p
    Y3 = (R * (U1_H_sq - X3) - S1 * H_cu) % p
    Z3 = (H * Z1 * Z2) % p
    return (X3, Y3, Z3)


def _jac_to_affine(X: int, Y: int, Z: int) -> ECPoint:
    if Z == 0:
        return P256_INFINITY
    p = P256_P
    z_inv = pow(Z, -1, p)
    z_inv2 = (z_inv * z_inv) % p
    z_inv3 = (z_inv2 * z_inv) % p
    return ECPoint((X * z_inv2) % p, (Y * z_inv3) % p)


def point_add(P: ECPoint, Q: ECPoint) -> ECPoint:
    """Add two affine points on P-256."""
    if P.is_infinity:
        return Q
    if Q.is_infinity:
        return P
    assert P.x is not None and P.y is not None and Q.x is not None and Q.y is not None
    X3, Y3, Z3 = _jac_add(P.x, P.y, 1, Q.x, Q.y, 1)
    return _jac_to_affine(X3, Y3, Z3)


def scalar_mul(k: int, P: ECPoint) -> ECPoint:
    """Compute k * P on P-256 using binary double-and-add in Jacobian coordinates."""
    k = k % P256_N
    if k == 0 or P.is_infinity:
        return P256_INFINITY
    assert P.x is not None and P.y is not None
    RX, RY, RZ = 0, 1, 0
    QX, QY, QZ = P.x, P.y, 1
    while k > 0:
        if k & 1:
            RX, RY, RZ = _jac_add(RX, RY, RZ, QX, QY, QZ)
        QX, QY, QZ = _jac_double(QX, QY, QZ)
        k >>= 1
    return _jac_to_affine(RX, RY, RZ)


def random_scalar() -> int:
    """Sample a uniformly random non-zero scalar in [1, P256_N - 1]."""
    return 1 + secrets.randbelow(P256_N - 1)


def hash_to_curve(data: bytes, domain: bytes = b"PMSET-P256-H2C-v1") -> ECPoint:
    """Deterministically hash arbitrary bytes to a non-identity point on P-256.

    Uses domain-separated SHA-256 counter try-and-increment with canonical square
    root parity. Expected iterations: 2.
    """
    p = P256_P
    for counter in range(256):
        digest = hashlib.sha256(domain + counter.to_bytes(2, "big") + data).digest()
        x = int.from_bytes(digest, "big") % p
        rhs = (pow(x, 3, p) + P256_A * x + P256_B) % p
        y = pow(rhs, _P256_SQRT_EXP, p)
        if (y * y) % p == rhs:
            # Select canonical y parity from an independent bit
            parity = hashlib.sha256(b"PARITY" + digest).digest()[0] & 1
            if (y & 1) != parity:
                y = p - y
            pt = ECPoint(x, y)
            if not pt.is_infinity:
                return pt
    raise RuntimeError("hash_to_curve failed to find curve point in 256 attempts")
