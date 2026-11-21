"""Exponential ElGamal Shuffled Homomorphic Zero-Testing PMSet protocol.

Protocol (1 round, prime-order NIST P-256 group):
  1. Client hashes query item to scalar x = H(item) mod n, encrypts it under
     Exponential ElGamal: C = Enc_pk(x) = (r*G, r*PK + x*G), and sends (PK, C).
  2. For each element s in S, Server homomorphically computes:
       D_s = Rerand_pk( r_s * (C - H(s)*G) ) = Enc_pk( r_s * (x - H(s)) )
     with fresh uniform non-zero scalar r_s in Z_n*, and cryptographically
     shuffles the resulting list of ciphertexts.
  3. Client checks whether ANY returned ciphertext decrypts to the point at
     infinity O = 0*G (no discrete logarithm needed!):
       - If x == H(s) for some s in S: r_s * 0 == 0 => decrypts to O => True!
       - If x != H(s) for all s in S: every r_s * (x - H(s)) is uniform in Z_n*
         => reveals nothing about S (not even element differences) => False!
"""

from __future__ import annotations

import hashlib
import secrets
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
from pmset.primitives.ec import P256_N, ECPoint, random_scalar
from pmset.primitives.he import (
    ElGamalCiphertext,
    ExponentialElGamalHE,
    ExponentialElGamalPublicKey,
)


def _hash_to_scalar(item: bytes) -> int:
    digest = hashlib.sha256(b"PMSET-ELGAMAL-EQ-v1" + item).digest()
    return (int.from_bytes(digest, "big") % (P256_N - 1)) + 1


class ElGamalEqualityServer(PMSetServer):
    """Stateless server performing randomized homomorphic equality checks + shuffle."""

    def __init__(self, items: DatasetInput) -> None:
        dataset = normalize_dataset(items)
        self._scalars = tuple(_hash_to_scalar(k) for k in dataset.keys())

    @property
    def protocol_name(self) -> str:
        return "elgamal_equality"

    @property
    def item_count(self) -> int:
        return len(self._scalars)

    def public_params(self) -> PublicParams:
        return PublicParams(
            protocol=self.protocol_name,
            params={"curve": "P-256", "set_size": len(self._scalars)},
        )

    def handle_request(self, request: ProtocolMessage) -> ProtocolMessage:
        if request.protocol != self.protocol_name or request.phase != "elgamal_eq":
            raise ValueError(f"Unexpected message ({request.protocol}, {request.phase})")
        pk = ExponentialElGamalPublicKey(
            pk=ECPoint.from_compressed_bytes(bytes(request.payload["pk"]))
        )
        ct_x = ElGamalCiphertext.from_wire(request.payload["ciphertext"])

        results: list[tuple[bytes, bytes]] = []
        for s in self._scalars:
            diff = pk.sub_plaintext(ct_x, s)
            r_s = random_scalar()
            masked = pk.rerandomize(pk.mul_scalar(diff, r_s))
            results.append(masked.to_wire())

        # Fisher-Yates shuffle with CSPRNG to hide matching element's position
        for i in range(len(results) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            results[i], results[j] = results[j], results[i]

        return ProtocolMessage(
            protocol=self.protocol_name,
            phase="elgamal_eq_response",
            round_num=1,
            payload={"ciphertexts": results},
        )


class _ElGamalEqualitySession(PMSetSession):
    def __init__(self, item_bytes: bytes, he: ExponentialElGamalHE) -> None:
        self._item_bytes = item_bytes
        self._he = he
        self._stage = "need_req"
        self._result: QueryResult | None = None

    @property
    def is_complete(self) -> bool:
        return self._stage == "done"

    def next_request(self) -> ProtocolMessage:
        if self._stage != "need_req":
            raise RuntimeError(f"Invalid session stage '{self._stage}'")
        x = _hash_to_scalar(self._item_bytes)
        ct = self._he.encrypt(x)
        self._stage = "awaiting_resp"
        return ProtocolMessage(
            protocol="elgamal_equality",
            phase="elgamal_eq",
            round_num=1,
            payload={
                "pk": self._he.pk.to_compressed_bytes(),
                "ciphertext": ct.to_wire(),
            },
        )

    def process_response(self, response: ProtocolMessage) -> None:
        if self._stage != "awaiting_resp" or response.phase != "elgamal_eq_response":
            raise ValueError(f"Unexpected response in stage '{self._stage}'")
        cts = [ElGamalCiphertext.from_wire(w) for w in response.payload["ciphertexts"]]
        # Non-short-circuiting constant-time zero test across all ciphertexts
        found = self._he.any_zero(cts)
        self._result = QueryResult(is_member=found, payload=None)
        self._stage = "done"

    def result(self) -> QueryResult:
        if self._result is None:
            raise RuntimeError("Session not complete")
        return self._result


class ElGamalEqualityClient(PMSetClient):
    """Client for Exponential ElGamal Randomized Homomorphic Equality Testing."""

    def __init__(self, public_params: PublicParams) -> None:
        if public_params.protocol != "elgamal_equality":
            raise ValueError(f"Protocol mismatch: got '{public_params.protocol}'")
        self._he = ExponentialElGamalHE()

    @property
    def protocol_name(self) -> str:
        return "elgamal_equality"

    def start_query(self, item: Item) -> PMSetSession:
        return _ElGamalEqualitySession(normalize_item(item), self._he)


class ElGamalEqualityProtocol(PMSetProtocol):
    """1-Round Exponential ElGamal Shuffled Homomorphic Equality Testing on P-256."""

    _META = ProtocolMetadata(
        name="elgamal_equality",
        display_name="Exponential ElGamal Shuffled Zero-Test (P-256)",
        family="Homomorphic Equality Testing",
        description=(
            "1-round protocol with O(1) client upload (just 1 P-256 ElGamal ciphertext!). "
            "Server computes randomized Enc(r_s * (x - s)) for each s in S, shuffles, "
            "and client checks whether any ciphertext decrypts to the group identity."
        ),
        assumptions=("DDH (NIST P-256)", "Collision-Resistant Hash"),
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
            client_upload="O(1) (99 bytes!)",
            server_download="O(N) P-256 ElGamal ciphertexts",
            server_compute="O(N) P-256 scalar multiplications",
            client_compute="O(N) P-256 scalar multiplications",
        ),
        references=("ElGamal 1985", "Randomized Homomorphic Equality Testing"),
        tla_spec="ElGamalEquality.tla",
        lean_theorem="PMSet.Protocols.elgamal_equality_correct",
    )

    @property
    def metadata(self) -> ProtocolMetadata:
        return self._META

    def create_server(self, items: DatasetInput, **config: Any) -> ElGamalEqualityServer:
        return ElGamalEqualityServer(items)

    def create_client(self, public_params: PublicParams, **config: Any) -> ElGamalEqualityClient:
        return ElGamalEqualityClient(public_params)
