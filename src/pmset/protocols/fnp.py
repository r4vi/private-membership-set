"""Freedman-Nissim-Pinkas (FNP04) Oblivious Polynomial Evaluation PMSet protocol.

Reference: M. Freedman, K. Nissim, B. Pinkas, "Efficient Private Matching and Set
Intersection", EUROCRYPT 2004.

Protocol (1 round):
  1. Server holds set S = {s_1, ..., s_d}, hashed to distinct integers H(s_i).
  2. Client encrypts powers of x = H(query) under its Paillier key:
       [Enc(x^1), Enc(x^2), ..., Enc(x^d)]
     and sends (N, encrypted_powers) to Server.
  3. Server forms the monic root polynomial P(X) = prod_{s in S} (X - H(s)) mod N
     with coefficients [c_0, c_1, ..., c_d], evaluates E(P(x)) homomorphically:
       E(P(x)) = Enc(c_0) * prod_{i=1}^d Enc(x^i)^{c_i} mod N^2
     and masks with fresh random r in Z_N* + fresh rerandomization:
       E(r * P(x)) = Rerand(E(P(x))^r).
  4. Client decrypts v = Dec(E(r * P(x))):
       v == 0  iff  P(x) == 0 mod N  iff  x in S!
     When x not in S, r * P(x) mod N is uniform in Z_N* (zero server set leakage).
"""

from __future__ import annotations

import hashlib
from typing import Any

from pmset.core.interfaces import PMSetClient, PMSetProtocol, PMSetServer, PMSetSession
from pmset.core.types import (
    ComplexityProfile,
    DatasetInput,
    Item,
    ProtocolCapabilities,
    ProtocolMessage,
    ProtocolMetadata,
    PublicParams,
    QueryResult,
    SecurityModel,
    normalize_dataset,
    normalize_item,
)
from pmset.primitives.he import PaillierHE, PaillierPublicKey
from pmset.primitives.math_utils import polynomial_from_roots, random_coprime


def _hash_item_to_int(item: bytes) -> int:
    """Map an arbitrary item to a 256-bit positive integer (always < N for N >= 512 bits)."""
    return int.from_bytes(hashlib.sha256(b"PMSET-FNP04-v1" + item).digest(), "big") | 1


class FNPPaillierServer(PMSetServer):
    """Stateless server implementing FNP04 Oblivious Polynomial Evaluation."""

    def __init__(self, items: DatasetInput, *, key_bits: int = 512) -> None:
        if key_bits < 384:
            raise ValueError("FNP Paillier key_bits must be >= 384 so 256-bit hashes fit < N")
        dataset = normalize_dataset(items)
        self._roots = tuple(_hash_item_to_int(k) for k in dataset.keys())
        self._key_bits = key_bits

    @property
    def protocol_name(self) -> str:
        return "fnp_paillier"

    @property
    def item_count(self) -> int:
        return len(self._roots)

    def public_params(self) -> PublicParams:
        return PublicParams(
            protocol=self.protocol_name,
            params={"set_size": len(self._roots), "key_bits": self._key_bits},
        )

    def handle_request(self, request: ProtocolMessage) -> ProtocolMessage:
        if request.protocol != self.protocol_name or request.phase != "fnp_eval":
            raise ValueError(f"Unexpected message ({request.protocol}, {request.phase})")
        n = int(request.payload["n"])
        if n.bit_length() < 300:
            raise ValueError("Client Paillier modulus too small for 256-bit element hashes")
        enc_powers: list[int] = request.payload["encrypted_powers"]
        degree = len(self._roots)
        if len(enc_powers) != degree:
            raise ValueError(
                f"FNP degree mismatch: server set has {degree} items, got {len(enc_powers)} powers"
            )

        pk = PaillierPublicKey(n=n)
        coeffs = polynomial_from_roots(self._roots, n)
        # E(P(x)) = E(c_0) * prod_{i=1}^d E(x^i)^{c_i} mod n^2
        acc = pk.encrypt(coeffs[0])
        for i in range(1, degree + 1):
            c_i = coeffs[i]
            if c_i != 0:
                acc = pk.add(acc, pk.mul_scalar(enc_powers[i - 1], c_i))

        # Mask with uniform invertible r in Z_n* and rerandomize
        r = random_coprime(n)
        masked = pk.rerandomize(pk.mul_scalar(acc, r))
        return ProtocolMessage(
            protocol=self.protocol_name,
            phase="fnp_response",
            round_num=1,
            payload={"masked_eval": masked},
        )


class _FNPPaillierSession(PMSetSession):
    def __init__(self, item_bytes: bytes, set_size: int, he: PaillierHE) -> None:
        self._item_bytes = item_bytes
        self._set_size = set_size
        self._he = he
        self._stage = "need_eval"
        self._result: QueryResult | None = None

    @property
    def is_complete(self) -> bool:
        return self._stage == "done"

    def next_request(self) -> ProtocolMessage:
        if self._stage != "need_eval":
            raise RuntimeError(f"Cannot generate request in stage '{self._stage}'")
        x = _hash_item_to_int(self._item_bytes) % self._he.n
        enc_powers: list[int] = []
        cur = 1
        for _ in range(self._set_size):
            cur = (cur * x) % self._he.n
            enc_powers.append(self._he.encrypt(cur))
        self._stage = "awaiting_eval"
        return ProtocolMessage(
            protocol="fnp_paillier",
            phase="fnp_eval",
            round_num=1,
            payload={"n": self._he.n, "encrypted_powers": enc_powers},
        )

    def process_response(self, response: ProtocolMessage) -> None:
        if self._stage != "awaiting_eval" or response.phase != "fnp_response":
            raise ValueError(f"Unexpected response in stage '{self._stage}'")
        val = self._he.decrypt(int(response.payload["masked_eval"]))
        self._result = QueryResult(is_member=(val == 0), payload=None)
        self._stage = "done"

    def result(self) -> QueryResult:
        if self._result is None:
            raise RuntimeError("Session not complete")
        return self._result


class FNPPaillierClient(PMSetClient):
    """Client for FNP04 Oblivious Polynomial Evaluation."""

    def __init__(self, public_params: PublicParams) -> None:
        if public_params.protocol != "fnp_paillier":
            raise ValueError(f"Protocol mismatch: got '{public_params.protocol}'")
        self._set_size = int(public_params.params["set_size"])
        self._key_bits = int(public_params.params.get("key_bits", 512))
        self._he = PaillierHE(bits=self._key_bits)

    @property
    def protocol_name(self) -> str:
        return "fnp_paillier"

    def start_query(self, item: Item) -> PMSetSession:
        return _FNPPaillierSession(normalize_item(item), self._set_size, self._he)


class FNPPaillierProtocol(PMSetProtocol):
    """Freedman-Nissim-Pinkas (EUROCRYPT 2004) Oblivious Polynomial Evaluation."""

    _META = ProtocolMetadata(
        name="fnp_paillier",
        display_name="FNP04 Oblivious Polynomial Evaluation (Paillier HE)",
        family="Homomorphic Polynomial Evaluation",
        description=(
            "1-round protocol representing the server's set S as roots of P(X) = prod(X - s). "
            "Client sends encrypted powers E(x^1..x^d); server evaluates E(r * P(x)) homomorphically."
        ),
        assumptions=("DCR (Paillier)", "Collision-Resistant Hash"),
        security_model=SecurityModel.SEMI_HONEST_COMPUTATIONAL,
        capabilities=ProtocolCapabilities(
            supports_payloads=False,
            supports_batch=True,
            false_positive_free=True,
            false_negative_free=True,
            rounds=1,
        ),
        complexity=ComplexityProfile(
            rounds=1,
            client_upload="O(N) Paillier ciphertexts",
            server_download="O(1) (1 Paillier ciphertext!)",
            server_compute="O(N) modular exponentiations",
            client_compute="O(N) Paillier encrypts + 1 decrypt",
        ),
        references=("Freedman-Nissim-Pinkas EUROCRYPT 2004",),
        tla_spec="FNPPaillier.tla",
        lean_theorem="PMSet.Protocols.fnp_paillier_correct",
    )

    @property
    def metadata(self) -> ProtocolMetadata:
        return self._META

    def create_server(self, items: DatasetInput, **config: Any) -> FNPPaillierServer:
        return FNPPaillierServer(items, **config)

    def create_client(self, public_params: PublicParams, **config: Any) -> FNPPaillierClient:
        return FNPPaillierClient(public_params)
