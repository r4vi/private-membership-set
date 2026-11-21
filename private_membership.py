"""Backward-compatibility facade for the original ``private_membership.py`` API.

New code should import from :mod:`pmset` directly, which provides the canonical
generic :class:`pmset.PMSetProtocol` interface, 12 concrete cryptographic
implementations, and formal verification in Z3, TLA+, and Lean 4.
"""

from __future__ import annotations

import hashlib
import math
import secrets

from pmset.primitives.he import PaillierHE
from pmset.primitives.math_utils import (
    LEGACY_OPRF_PRIME as OPRF_PRIME,
    generate_prime as get_prime,
    is_prime as _pmset_is_prime,
    lcm,
    random_coprime,
    random_int_range,
)


def is_prime(n: int, k: int = 40) -> bool:
    """Miller-Rabin primality test backed by :func:`pmset.primitives.math_utils.is_prime`."""
    return _pmset_is_prime(n, rounds=k)


class DHOPRF:
    """Legacy Z_p* DH-OPRF compatibility wrapper (see :class:`pmset.primitives.oprf.DHOPRF`)."""

    def __init__(self, p: int = OPRF_PRIME) -> None:
        if p < 3 or p % 2 == 0 or not is_prime(p):
            raise ValueError(f"DHOPRF requires an odd prime modulus, got p={p}")
        self.p = p

    def hash_to_group(self, x: str) -> int:
        h = hashlib.sha256(x.encode()).digest()
        return (int.from_bytes(h, "big") % (self.p - 1)) + 1

    def client_blind(self, x: str) -> tuple[int, int]:
        r = random_coprime(self.p - 1)
        h_x = self.hash_to_group(x)
        return pow(h_x, r, self.p), r

    def server_sign(self, blinded_x: int, k: int) -> int:
        return pow(blinded_x, k, self.p)

    def client_unblind(self, signed_blinded_x: int, r: int) -> int:
        r_inv = pow(r, -1, self.p - 1)
        return pow(signed_blinded_x, r_inv, self.p)

    def server_compute_hash(self, x: str, k: int) -> int:
        return pow(self.hash_to_group(x), k, self.p)


class Paillier(PaillierHE):
    """Legacy Paillier alias backed by :class:`pmset.primitives.he.PaillierHE`."""

    def __init__(self, bits: int = 1024) -> None:
        super().__init__(bits=bits)
        self.l = self.lam


class PSMServer:
    """Legacy single-level DH-OPRF + Paillier linear PIR server facade."""

    def __init__(self, items: list[str], bucket_count: int = 16) -> None:
        self.oprf = DHOPRF()
        self.k = random_int_range(2, self.oprf.p - 2)
        self.bucket_count = bucket_count
        self.buckets: list[list[int]] = [[] for _ in range(bucket_count)]
        self._setup(items)

    def _setup(self, items: list[str]) -> None:
        for item in items:
            h_k = self.oprf.server_compute_hash(item, self.k)
            self.buckets[h_k % self.bucket_count].append(h_k)

        max_size = max(1, max(len(b) for b in self.buckets))
        for b in self.buckets:
            while len(b) < max_size:
                b.append(random_int_range(2, self.oprf.p - 2))

    def handle_oprf_request(self, blinded_element: int) -> int:
        return self.oprf.server_sign(blinded_element, self.k)

    def handle_pir_request(self, encrypted_query_vector: list[int], n: int) -> list[int]:
        bucket_size = len(self.buckets[0])
        n_sq = n * n
        response: list[int] = []
        for j in range(bucket_size):
            encrypted_sum = 1
            for i in range(self.bucket_count):
                term = pow(encrypted_query_vector[i], self.buckets[i][j], n_sq)
                encrypted_sum = (encrypted_sum * term) % n_sq
            response.append(encrypted_sum)
        return response


class PSMClient:
    """Legacy single-level DH-OPRF + Paillier linear PIR client facade."""

    def __init__(self, bucket_count: int = 16) -> None:
        self.oprf = DHOPRF()
        self.bucket_count = bucket_count
        self.pir = Paillier(bits=1024)

    def query(self, server: PSMServer, element: str) -> bool:
        if server.bucket_count != self.bucket_count:
            raise ValueError(
                f"Bucket count mismatch: server uses {server.bucket_count} buckets, "
                f"client uses {self.bucket_count}. They must match for PIR to work."
            )
        blinded, r = self.oprf.client_blind(element)
        signed = server.handle_oprf_request(blinded)
        target_h_k = self.oprf.client_unblind(signed, r)
        bucket_idx = target_h_k % self.bucket_count

        query_vector = [
            self.pir.encrypt(1 if i == bucket_idx else 0)
            for i in range(self.bucket_count)
        ]
        encrypted_response = server.handle_pir_request(query_vector, self.pir.n)
        retrieved_bucket = [self.pir.decrypt(c) for c in encrypted_response]
        return target_h_k in retrieved_bucket


if __name__ == "__main__":
    import pmset

    proto = pmset.get_protocol("oprf_rlwe_pir")
    items = ["alice@example.com", "bob@example.com", "charlie@example.com", "dave@example.com"]
    server = proto.create_server(items)
    client = proto.create_client(server.public_params())
    for q in ["alice@example.com", "eve@example.com", "bob@example.com", "malory@example.com"]:
        res = client.query_detailed(server, q, verify_wire_roundtrip=True)
        print(f"[{proto.name}] '{q}' -> {'MEMBER' if res.is_member else 'NOT A MEMBER'}")
