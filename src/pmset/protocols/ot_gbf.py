"""Dong-Chen-Wen (DCW13) Garbled Bloom Filter + 1-out-of-2 Oblivious Transfer PMSet.

Reference: C. Dong, L. Chen, Z. Wen, "When Private Set Intersection Meets Big Data:
An Efficient and Scalable Protocol", ACM CCS 2013.

Protocol (1 round, zero homomorphic encryption!):
  1. Server builds a Garbled Bloom Filter (GBF) of m slots with k hash functions
     and 128-bit shares so XOR_{j=1}^k GBF[h_j(s)] == tag(s) for all s in S,
     and publishes (m, k, seed, lambda_bytes, OT public key A = a*G).
  2. Client forms choice bit vector c in {0, 1}^m with c_i = 1 iff i in {h_1(x)..h_k(x)}
     and runs m parallel Chou-Orlandi 1-out-of-2 OTs.
  3. Server responds to each OT i with (fresh_random_dummy, GBF[i]).
  4. Client decrypts the k chosen shares at {h_1(x)..h_k(x)}, XORs them, and
     checks equality with tag(x).
"""

from __future__ import annotations

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
from pmset.primitives.ec import ECPoint
from pmset.primitives.indexing import GarbledBloomFilter
from pmset.primitives.ot import ChouOrlandiOT, ChouOrlandiSenderKey


class OTGarbledBloomServer(PMSetServer):
    """Stateless server holding a Garbled Bloom Filter queried via Chou-Orlandi OT."""

    def __init__(
        self,
        items: DatasetInput,
        *,
        num_slots: int | None = None,
        num_hashes: int = 3,
        lambda_bytes: int = 16,
    ) -> None:
        dataset = normalize_dataset(items)
        self._item_count = len(dataset)
        self._gbf = GarbledBloomFilter.build(
            list(dataset.keys()),
            num_slots=num_slots,
            num_hashes=num_hashes,
            lambda_bytes=lambda_bytes,
        )
        self._ot_key = ChouOrlandiSenderKey.generate()
        self._ot = ChouOrlandiOT(self._ot_key.A, sender_secret_a=self._ot_key.a)

    @property
    def protocol_name(self) -> str:
        return "ot_garbled_bloom"

    @property
    def item_count(self) -> int:
        return self._item_count

    def public_params(self) -> PublicParams:
        return PublicParams(
            protocol=self.protocol_name,
            params={
                "num_slots": self._gbf.num_slots,
                "num_hashes": self._gbf.num_hashes,
                "seed": self._gbf.seed,
                "lambda_bytes": self._gbf.lambda_bytes,
                "ot_public_A": self._ot_key.A.to_compressed_bytes(),
            },
        )

    def handle_request(self, request: ProtocolMessage) -> ProtocolMessage:
        if request.protocol != self.protocol_name or request.phase != "ot_gbf_query":
            raise ValueError(f"Unexpected message ({request.protocol}, {request.phase})")
        receiver_msgs: list[bytes] = request.payload["ot_choices"]
        if len(receiver_msgs) != self._gbf.num_slots:
            raise ValueError(
                f"OT choice count mismatch: expected {self._gbf.num_slots}, got {len(receiver_msgs)}"
            )
        # m_0 is fresh random dummy; m_1 is the real GBF slot share
        pairs = [
            (secrets.token_bytes(self._gbf.lambda_bytes), slot)
            for slot in self._gbf.slots
        ]
        encrypted_pairs = self._ot.sender_respond(receiver_msgs, pairs)
        return ProtocolMessage(
            protocol=self.protocol_name,
            phase="ot_gbf_response",
            round_num=1,
            payload={"encrypted_pairs": encrypted_pairs},
        )


class _OTGarbledBloomSession(PMSetSession):
    def __init__(
        self,
        item_bytes: bytes,
        num_slots: int,
        num_hashes: int,
        seed: bytes,
        lambda_bytes: int,
        ot: ChouOrlandiOT,
    ) -> None:
        self._item_bytes = item_bytes
        self._num_slots = num_slots
        self._num_hashes = num_hashes
        self._seed = seed
        self._lambda_bytes = lambda_bytes
        self._ot = ot
        self._stage = "need_ot"
        self._positions: list[int] = []
        self._choices: list[int] = []
        self._ot_keys: list[bytes] = []
        self._result: QueryResult | None = None

    @property
    def is_complete(self) -> bool:
        return self._stage == "done"

    def next_request(self) -> ProtocolMessage:
        if self._stage != "need_ot":
            raise RuntimeError(f"Invalid session stage '{self._stage}'")
        self._positions = GarbledBloomFilter.positions(
            self._item_bytes, self._num_slots, self._num_hashes, self._seed
        )
        pos_set = set(self._positions)
        self._choices = [1 if i in pos_set else 0 for i in range(self._num_slots)]
        wire_B, self._ot_keys = self._ot.receiver_choose(self._choices)
        self._stage = "awaiting_ot"
        return ProtocolMessage(
            protocol="ot_garbled_bloom",
            phase="ot_gbf_query",
            round_num=1,
            payload={"ot_choices": wire_B},
        )

    def process_response(self, response: ProtocolMessage) -> None:
        if self._stage != "awaiting_ot" or response.phase != "ot_gbf_response":
            raise ValueError(f"Unexpected response in stage '{self._stage}'")
        enc_pairs = [(bytes(e0), bytes(e1)) for e0, e1 in response.payload["encrypted_pairs"]]
        decrypted = self._ot.receiver_decrypt(self._choices, self._ot_keys, enc_pairs)
        retrieved = {pos: decrypted[pos] for pos in self._positions}
        gbf_view = GarbledBloomFilter(
            self._num_slots, self._num_hashes, self._seed, (), self._lambda_bytes
        )
        is_member = gbf_view.verify_shares(self._item_bytes, retrieved)
        self._result = QueryResult(is_member=is_member, payload=None)
        self._stage = "done"

    def result(self) -> QueryResult:
        if self._result is None:
            raise RuntimeError("Session not complete")
        return self._result


class OTGarbledBloomClient(PMSetClient):
    """Client for DCW13 Garbled Bloom Filter + Oblivious Transfer."""

    def __init__(self, public_params: PublicParams) -> None:
        if public_params.protocol != "ot_garbled_bloom":
            raise ValueError(f"Protocol mismatch: got '{public_params.protocol}'")
        p = public_params.params
        self._num_slots = int(p["num_slots"])
        self._num_hashes = int(p["num_hashes"])
        self._seed = bytes(p["seed"])
        self._lambda_bytes = int(p["lambda_bytes"])
        A = ECPoint.from_compressed_bytes(bytes(p["ot_public_A"]))
        self._ot = ChouOrlandiOT(A)

    @property
    def protocol_name(self) -> str:
        return "ot_garbled_bloom"

    def start_query(self, item: Item) -> PMSetSession:
        return _OTGarbledBloomSession(
            normalize_item(item),
            self._num_slots,
            self._num_hashes,
            self._seed,
            self._lambda_bytes,
            self._ot,
        )


class OTGarbledBloomFilterProtocol(PMSetProtocol):
    """Dong-Chen-Wen (ACM CCS 2013) Garbled Bloom Filter + Chou-Orlandi 1-out-of-2 OT."""

    _META = ProtocolMetadata(
        name="ot_garbled_bloom",
        display_name="Garbled Bloom Filter + 1-out-of-2 ECDH OT (DCW13)",
        family="Oblivious Transfer + Garbled Data Structures",
        description=(
            "1-round protocol with NO homomorphic encryption: combines XOR secret-shared "
            "Garbled Bloom Filters with Chou-Orlandi 1-out-of-2 Oblivious Transfer on P-256."
        ),
        assumptions=("CDH (NIST P-256)", "Random Oracle"),
        security_model=SecurityModel.SEMI_HONEST_COMPUTATIONAL,
        capabilities=ProtocolCapabilities(
            supports_payloads=False,
            supports_batch=True,
            false_positive_free=False,  # Cryptographically negligible: 2^-128
            false_negative_free=True,
            rounds=1,
        ),
        complexity=ComplexityProfile(
            rounds=1,
            client_upload="O(m) P-256 points (m = O(k*N))",
            server_download="O(m) 128-bit masked pairs",
            server_compute="O(m) P-256 scalar muls",
            client_compute="O(m) P-256 scalar muls + k XORs",
        ),
        references=("Dong-Chen-Wen ACM CCS 2013", "Chou-Orlandi LATINCRYPT 2015"),
        tla_spec="OTGarbledBloom.tla",
        lean_theorem="PMSet.Protocols.ot_garbled_bloom_correct",
    )

    @property
    def metadata(self) -> ProtocolMetadata:
        return self._META

    def create_server(self, items: DatasetInput, **config: Any) -> OTGarbledBloomServer:
        return OTGarbledBloomServer(items, **config)

    def create_client(self, public_params: PublicParams, **config: Any) -> OTGarbledBloomClient:
        return OTGarbledBloomClient(public_params)
