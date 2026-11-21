"""1-out-of-2 Oblivious Transfer (OT) primitive: Chou-Orlandi ECDH OT on P-256.

Chou-Orlandi (2015, "The Simplest Protocol for Oblivious Transfer"):
  - Sender publishes A = a*G (reusable across sessions, enabling 1-round batch OT).
  - Receiver with choice bit c in {0, 1} picks random b in Z_n*:
      B = b*G        if c == 0
      B = A + b*G    if c == 1
    and derives key k_c = H(sid || A || B || b*A).
  - Sender computes:
      k_0 = H(sid || A || B || a*B)
      k_1 = H(sid || A || B || a*(B - A))
    and returns masked messages (m_0 XOR PRG(k_0), m_1 XOR PRG(k_1)).
  - Receiver recovers m_c = e_c XOR PRG(k_c).

Security:
  - Receiver privacy is **information-theoretic**: for any B, there exist unique
    scalars b_0, b_1 = b_0 - a mod n explaining c = 0 and c = 1 with equal probability.
  - Sender privacy holds under the Computational Diffie-Hellman (CDH) assumption in
    the random oracle model.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Sequence

from pmset.primitives.ec import (
    P256_GENERATOR,
    ECPoint,
    point_add,
    random_scalar,
    scalar_mul,
)
from pmset.primitives.math_utils import prg_expand


class ObliviousTransfer(ABC):
    """Generic interface for 1-out-of-2 batch Oblivious Transfer."""

    @abstractmethod
    def receiver_choose(self, choices: Sequence[int]) -> tuple[list[bytes], list[bytes]]:
        """Produce wire choice messages and local decryption keys for ``choices``."""

    @abstractmethod
    def sender_respond(
        self,
        receiver_msgs: Sequence[bytes],
        message_pairs: Sequence[tuple[bytes, bytes]],
    ) -> list[tuple[bytes, bytes]]:
        """Encrypt each ``(m0, m1)`` pair under the sender-derived OT keys."""

    @abstractmethod
    def receiver_decrypt(
        self,
        choices: Sequence[int],
        keys: Sequence[bytes],
        encrypted_pairs: Sequence[tuple[bytes, bytes]],
    ) -> list[bytes]:
        """Decrypt the chosen message ``m_{c_i}`` for each OT instance."""


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError(f"XOR length mismatch: {len(a)} != {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


@dataclass(frozen=True)
class ChouOrlandiSenderKey:
    """Reusable sender keypair (a, A = a*G) for Chou-Orlandi OT."""

    a: int
    A: ECPoint

    @classmethod
    def generate(cls) -> ChouOrlandiSenderKey:
        a = random_scalar()
        return cls(a=a, A=scalar_mul(a, P256_GENERATOR))


class ChouOrlandiOT(ObliviousTransfer):
    """Chou-Orlandi 1-out-of-2 Oblivious Transfer over NIST P-256."""

    DOMAIN = b"PMSET-CHOU-ORLANDI-OT-P256-v1"

    def __init__(
        self,
        sender_public_A: ECPoint,
        sender_secret_a: int | None = None,
    ) -> None:
        if sender_public_A.is_infinity or not sender_public_A.is_on_curve():
            raise ValueError("Invalid Chou-Orlandi sender public key A")
        self.A = sender_public_A
        self.A_bytes = sender_public_A.to_compressed_bytes()
        self._a = sender_secret_a

    def _derive_key(self, index: int, B_bytes: bytes, shared_point: ECPoint) -> bytes:
        return hashlib.sha256(
            self.DOMAIN
            + index.to_bytes(4, "big")
            + self.A_bytes
            + B_bytes
            + shared_point.to_compressed_bytes()
        ).digest()

    def receiver_choose(self, choices: Sequence[int]) -> tuple[list[bytes], list[bytes]]:
        wire_B: list[bytes] = []
        keys: list[bytes] = []
        for idx, c in enumerate(choices):
            if c not in (0, 1):
                raise ValueError(f"OT choice bit must be 0 or 1, got {c}")
            b = random_scalar()
            bG = scalar_mul(b, P256_GENERATOR)
            B = bG if c == 0 else point_add(self.A, bG)
            B_bytes = B.to_compressed_bytes()
            shared = scalar_mul(b, self.A)
            key = self._derive_key(idx, B_bytes, shared)
            wire_B.append(B_bytes)
            keys.append(key)
        return wire_B, keys

    def sender_respond(
        self,
        receiver_msgs: Sequence[bytes],
        message_pairs: Sequence[tuple[bytes, bytes]],
    ) -> list[tuple[bytes, bytes]]:
        if self._a is None:
            raise ValueError("ChouOrlandiOT sender_respond requires sender_secret_a")
        if len(receiver_msgs) != len(message_pairs):
            raise ValueError(
                f"OT count mismatch: {len(receiver_msgs)} choices vs {len(message_pairs)} pairs"
            )
        neg_A = -self.A
        out: list[tuple[bytes, bytes]] = []
        for idx, (B_bytes, (m0, m1)) in enumerate(zip(receiver_msgs, message_pairs)):
            if len(m0) != len(m1):
                raise ValueError("Both messages in an OT pair must have equal byte length")
            B = ECPoint.from_compressed_bytes(B_bytes)
            if B.is_infinity:
                raise ValueError("Invalid OT point at infinity")
            k0 = self._derive_key(idx, B_bytes, scalar_mul(self._a, B))
            k1 = self._derive_key(idx, B_bytes, scalar_mul(self._a, point_add(B, neg_A)))
            pad0 = prg_expand(k0, len(m0), domain=b"PMSET-OT-PAD")
            pad1 = prg_expand(k1, len(m1), domain=b"PMSET-OT-PAD")
            out.append((_xor_bytes(m0, pad0), _xor_bytes(m1, pad1)))
        return out

    def receiver_decrypt(
        self,
        choices: Sequence[int],
        keys: Sequence[bytes],
        encrypted_pairs: Sequence[tuple[bytes, bytes]],
    ) -> list[bytes]:
        if not (len(choices) == len(keys) == len(encrypted_pairs)):
            raise ValueError("OT decrypt length mismatch")
        out: list[bytes] = []
        for c, key, (e0, e1) in zip(choices, keys, encrypted_pairs):
            ct = e0 if c == 0 else e1
            pad = prg_expand(key, len(ct), domain=b"PMSET-OT-PAD")
            out.append(_xor_bytes(ct, pad))
        return out
