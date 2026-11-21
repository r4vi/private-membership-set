"""Oblivious Pseudorandom Function (OPRF) generic interface and implementations.

Provides three distinct cryptographic OPRF constructions:
  1. :class:`ECDHOPRF`: Prime-order NIST P-256 OPRF (RFC 9497 style).
  2. :class:`DHOPRF`: Safe-prime quadratic-residue prime-order subgroup DH-OPRF.
  3. :class:`RSAOPRF`: Chaum blind-signature RSA-OPRF.
"""

from __future__ import annotations

import hashlib
import math
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from pmset.primitives.ec import (
    P256_N,
    ECPoint,
    hash_to_curve,
    random_scalar,
    scalar_mul,
)
from pmset.primitives.math_utils import (
    RFC2409_GROUP1_P,
    RFC3526_GROUP14_P,
    generate_prime,
    is_prime,
    is_safe_prime,
    lcm,
    random_coprime,
    random_int_range,
)


class OPRF(ABC):
    """Generic interface for an Oblivious Pseudorandom Function."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Canonical OPRF identifier."""

    @abstractmethod
    def public_params(self) -> dict[str, Any]:
        """Serializable public parameters needed by clients."""

    @classmethod
    @abstractmethod
    def from_public_params(cls, params: dict[str, Any]) -> OPRF:
        """Instantiate an OPRF client/verifier from server public parameters."""

    @abstractmethod
    def keygen(self) -> Any:
        """Generate a fresh server secret key."""

    @abstractmethod
    def client_blind(self, item: bytes) -> tuple[Any, Any]:
        """Blind ``item``; returns ``(wire_blinded_element, client_blind_state)``."""

    @abstractmethod
    def server_evaluate(self, blinded_element: Any, server_key: Any) -> Any:
        """Evaluate the OPRF on a blinded element using ``server_key``."""

    @abstractmethod
    def client_finalize(self, item: bytes, evaluated_element: Any, blind_state: Any) -> bytes:
        """Unblind and finalize to a uniform 32-byte OPRF output."""

    @abstractmethod
    def server_evaluate_direct(self, item: bytes, server_key: Any) -> bytes:
        """Directly compute the 32-byte OPRF output on the server for preprocessing."""


class ECDHOPRF(OPRF):
    """Prime-order Elliptic Curve Diffie-Hellman OPRF on NIST P-256 (RFC 9497 style).

    Protocol:
      - Client: P = H_to_curve(x), r <-$ Z_n*, sends B = r * P
      - Server: sends Z = k * B
      - Client: N = r^(-1) * Z = k * P, outputs SHA256(len(x) || x || ser(N) || "Finalize")
    """

    DOMAIN_H2C = b"PMSET-ECDH-OPRF-P256-H2C-v1"
    DOMAIN_FIN = b"PMSET-ECDH-OPRF-P256-FIN-v1"

    @property
    def name(self) -> str:
        return "ecdh-p256"

    def public_params(self) -> dict[str, Any]:
        return {"oprf": self.name, "curve": "P-256"}

    @classmethod
    def from_public_params(cls, params: dict[str, Any]) -> ECDHOPRF:
        if params.get("curve", "P-256") != "P-256":
            raise ValueError(f"Unsupported curve: {params.get('curve')}")
        return cls()

    def keygen(self) -> int:
        return random_scalar()

    def _finalize(self, item: bytes, unblinded_point: ECPoint) -> bytes:
        pt_bytes = unblinded_point.to_compressed_bytes()
        return hashlib.sha256(
            self.DOMAIN_FIN
            + len(item).to_bytes(4, "big")
            + item
            + len(pt_bytes).to_bytes(4, "big")
            + pt_bytes
        ).digest()

    def client_blind(self, item: bytes) -> tuple[bytes, int]:
        P = hash_to_curve(item, domain=self.DOMAIN_H2C)
        r = random_scalar()
        blinded = scalar_mul(r, P)
        return blinded.to_compressed_bytes(), r

    def server_evaluate(self, blinded_element: bytes, server_key: int) -> bytes:
        B = ECPoint.from_compressed_bytes(blinded_element)
        if B.is_infinity:
            raise ValueError("Refusing to evaluate OPRF on identity element")
        Z = scalar_mul(server_key, B)
        return Z.to_compressed_bytes()

    def client_finalize(self, item: bytes, evaluated_element: bytes, blind_state: int) -> bytes:
        from pmset.native import ct_modinv

        Z = ECPoint.from_compressed_bytes(evaluated_element)
        if Z.is_infinity:
            raise ValueError("Server returned identity element in ECDH-OPRF")
        r_inv = ct_modinv(blind_state, P256_N)
        N = scalar_mul(r_inv, Z)
        return self._finalize(item, N)

    def server_evaluate_direct(self, item: bytes, server_key: int) -> bytes:
        P = hash_to_curve(item, domain=self.DOMAIN_H2C)
        N = scalar_mul(server_key, P)
        return self._finalize(item, N)


class DHOPRF(OPRF):
    """Finite-field Diffie-Hellman OPRF over a safe-prime prime-order subgroup.

    When ``safe_subgroup=True`` (the default, requiring safe prime p = 2q + 1),
    inputs are hashed into the prime-order quadratic-residue subgroup G_q via
    h = H(x)^2 mod p so the Decisional Diffie-Hellman (DDH) assumption holds
    without small-subgroup leakage.
    """

    DOMAIN_FIN = b"PMSET-DH-OPRF-FIN-v1"

    def __init__(self, p: int = RFC2409_GROUP1_P, *, safe_subgroup: bool = True) -> None:
        if p < 5 or (p & 1) == 0 or not is_prime(p):
            raise ValueError(f"DHOPRF requires an odd prime modulus >= 5, got p={p}")
        if safe_subgroup and not is_safe_prime(p):
            raise ValueError(
                "safe_subgroup=True requires a safe prime p = 2q + 1 with q prime"
            )
        self.p = p
        self.safe_subgroup = safe_subgroup
        self.order = (p - 1) >> 1 if safe_subgroup else (p - 1)

    @property
    def name(self) -> str:
        return "dh-safeprime" if self.safe_subgroup else "dh-zp"

    def public_params(self) -> dict[str, Any]:
        return {
            "oprf": self.name,
            "p": self.p,
            "safe_subgroup": self.safe_subgroup,
        }

    @classmethod
    def from_public_params(cls, params: dict[str, Any]) -> DHOPRF:
        return cls(
            p=int(params["p"]),
            safe_subgroup=bool(params.get("safe_subgroup", True)),
        )

    def keygen(self) -> int:
        return random_int_range(2, self.order - 1)

    def hash_to_group(self, item: bytes) -> int:
        """Map ``item`` into the target subgroup (prime-order G_q if safe_subgroup)."""
        # Derive a wide integer using SHA-512 to avoid bias
        digest = hashlib.sha512(b"PMSET-DH-H2G" + item).digest()
        base = (int.from_bytes(digest, "big") % (self.p - 3)) + 2  # in [2, p - 2]
        if self.safe_subgroup:
            # Squaring maps Z_p* onto the prime-order subgroup G_q of order q.
            # Because base in [2, p-2], base != +/-1 mod p, so base^2 != 1 mod p.
            return pow(base, 2, self.p)
        return base

    def _finalize(self, item: bytes, group_elem: int) -> bytes:
        elem_bytes = group_elem.to_bytes((self.p.bit_length() + 7) // 8, "big")
        return hashlib.sha256(
            self.DOMAIN_FIN + len(item).to_bytes(4, "big") + item + elem_bytes
        ).digest()

    def client_blind(self, item: bytes) -> tuple[int, int]:
        from pmset.native import ct_modexp

        h_x = self.hash_to_group(item)
        if self.safe_subgroup:
            # Order q is prime, so every r in [1, q - 1] is invertible mod q
            r = random_int_range(1, self.order - 1)
        else:
            r = random_coprime(self.order)
        blinded = ct_modexp(h_x, r, self.p, order=self.order)
        return blinded, r

    def server_evaluate(self, blinded_element: int, server_key: int) -> int:
        from pmset.native import ct_modexp

        if not (1 < blinded_element < self.p):
            raise ValueError("Invalid blinded group element")
        if self.safe_subgroup and ct_modexp(blinded_element, self.order, self.p) != 1:
            raise ValueError("Blinded element is not in the prime-order subgroup G_q")
        return ct_modexp(blinded_element, server_key, self.p, order=self.order)

    def client_finalize(self, item: bytes, evaluated_element: int, blind_state: int) -> bytes:
        from pmset.native import ct_modexp, ct_modinv

        if not (1 < evaluated_element < self.p):
            raise ValueError("Invalid evaluated group element")
        r_inv = ct_modinv(blind_state, self.order)
        unblinded = ct_modexp(evaluated_element, r_inv, self.p, order=self.order)
        return self._finalize(item, unblinded)

    def server_evaluate_direct(self, item: bytes, server_key: int) -> bytes:
        from pmset.native import ct_modexp

        h_x = self.hash_to_group(item)
        return self._finalize(item, ct_modexp(h_x, server_key, self.p, order=self.order))


@dataclass(frozen=True)
class RSAOPRFKey:
    """Server keypair for Chaum blind-RSA OPRF."""

    n: int
    e: int
    d: int


class RSAOPRF(OPRF):
    """Chaum Blind-Signature RSA OPRF (RFC 9474 / blind-RSA paradigm).

    Protocol:
      - Public parameters: (n, e)
      - Client: h = H_FDH(x) mod n, r <-$ Z_n*, sends b = h * r^e mod n
      - Server: sends z = b^d mod n = h^d * r mod n
      - Client: u = z * r^(-1) mod n = h^d mod n, outputs SHA256(x || u)
    """

    DOMAIN_FIN = b"PMSET-RSA-OPRF-FIN-v1"

    def __init__(self, bits: int = 1024, e: int = 65537, *, n: int | None = None) -> None:
        if n is not None:
            self.n = n
            self.bits = n.bit_length()
        else:
            self.n = 0
            self.bits = bits
        self.e = e

    @property
    def name(self) -> str:
        return "rsa-blind"

    def public_params(self) -> dict[str, Any]:
        if self.n == 0:
            raise ValueError("RSAOPRF public_params requires a generated or provided modulus n")
        return {"oprf": self.name, "n": self.n, "e": self.e}

    @classmethod
    def from_public_params(cls, params: dict[str, Any]) -> RSAOPRF:
        return cls(e=int(params["e"]), n=int(params["n"]))

    def keygen(self) -> RSAOPRFKey:
        from pmset.native import ct_modinv

        half = self.bits // 2
        while True:
            p = generate_prime(half)
            q = generate_prime(self.bits - half)
            if p == q:
                continue
            lam = lcm(p - 1, q - 1)
            if math.gcd(self.e, lam) == 1:
                n = p * q
                d = ct_modinv(self.e, lam)
                self.n = n
                return RSAOPRFKey(n=n, e=self.e, d=d)

    def _hash_fdh(self, item: bytes, n: int) -> int:
        """Full-domain hash into Z_n* using SHAKE-256."""
        n_bytes = (n.bit_length() + 7) // 8
        for counter in range(256):
            raw = hashlib.shake_256(
                b"PMSET-RSA-FDH" + counter.to_bytes(2, "big") + item
            ).digest(n_bytes + 16)
            h = int.from_bytes(raw, "big") % n
            if h > 1 and math.gcd(h, n) == 1:
                return h
        raise RuntimeError("Failed to hash into Z_n*")

    def _finalize(self, item: bytes, unblinded: int, n: int) -> bytes:
        u_bytes = unblinded.to_bytes((n.bit_length() + 7) // 8, "big")
        return hashlib.sha256(
            self.DOMAIN_FIN + len(item).to_bytes(4, "big") + item + u_bytes
        ).digest()

    def client_blind(self, item: bytes) -> tuple[int, int]:
        from pmset.native import ct_modexp

        if self.n == 0:
            raise ValueError("RSAOPRF client requires modulus n from public_params")
        h = self._hash_fdh(item, self.n)
        r = random_coprime(self.n)
        blinded = (h * ct_modexp(r, self.e, self.n)) % self.n
        return blinded, r

    def server_evaluate(self, blinded_element: int, server_key: RSAOPRFKey) -> int:
        from pmset.native import ct_modexp

        if not (1 < blinded_element < server_key.n):
            raise ValueError("Invalid blinded RSA element")
        if math.gcd(blinded_element, server_key.n) != 1:
            raise ValueError("Blinded RSA element not coprime to modulus")
        return ct_modexp(blinded_element, server_key.d, server_key.n)

    def client_finalize(self, item: bytes, evaluated_element: int, blind_state: int) -> bytes:
        from pmset.native import ct_modinv

        r_inv = ct_modinv(blind_state, self.n)
        unblinded = (evaluated_element * r_inv) % self.n
        return self._finalize(item, unblinded, self.n)

    def server_evaluate_direct(self, item: bytes, server_key: RSAOPRFKey) -> bytes:
        from pmset.native import ct_modexp

        h = self._hash_fdh(item, server_key.n)
        sig = ct_modexp(h, server_key.d, server_key.n)
        return self._finalize(item, sig, server_key.n)


def create_oprf_from_params(params: dict[str, Any]) -> OPRF:
    """Factory reconstructing any supported OPRF from serialized public parameters."""
    kind = params.get("oprf")
    if kind == "ecdh-p256":
        return ECDHOPRF.from_public_params(params)
    if kind in ("dh-safeprime", "dh-zp"):
        return DHOPRF.from_public_params(params)
    if kind == "rsa-blind":
        return RSAOPRF.from_public_params(params)
    raise ValueError(f"Unknown OPRF kind: {kind!r}")


__all__ = [
    "DHOPRF",
    "ECDHOPRF",
    "OPRF",
    "RFC2409_GROUP1_P",
    "RFC3526_GROUP14_P",
    "RSAOPRF",
    "RSAOPRFKey",
    "create_oprf_from_params",
]
