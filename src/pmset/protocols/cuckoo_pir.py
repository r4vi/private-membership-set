"""Cuckoo Hashing + ECDH-OPRF + PIR Private Set Membership (PSZ14 optimization).

Instead of standard hash bucketing (which requires padding every bucket to the
maximum load O(N/B + sqrt(N log B / B))), the server places all OPRF-hashed
records into a 2-hash Cuckoo table where EVERY bin holds at most 1 item, plus
a tiny bounded stash.

Protocol (2 rounds):
  Round 1 (OPRF): Client obtains y = OPRF_k(x) and computes the two candidate
                  Cuckoo positions (h1(y), h2(y)).
  Round 2 (PIR):  Client issues TWO parallel PIR queries (for h1 and h2) over
                  the 1-record-per-bin Cuckoo table. Server also returns the
                  tiny encrypted stash (typically empty). Client checks both
                  retrieved slots and the stash via AEAD decryption.
"""

from __future__ import annotations

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
from pmset.primitives.indexing import CuckooTable, PrefixBucketizer
from pmset.primitives.oprf import ECDHOPRF
from pmset.primitives.pir import RLWEPIR, SingleServerPIR
from pmset.primitives.rlwe import RLWEParams


class CuckooOPRFPIRServer(PMSetServer):
    """Stateless server indexing OPRF records into a 2-hash Cuckoo table."""

    def __init__(
        self,
        items: DatasetInput,
        *,
        num_bins: int | None = None,
        use_aead: bool = True,
        pir: SingleServerPIR | None = None,
    ) -> None:
        self._oprf = ECDHOPRF()
        self._oprf_key = self._oprf.keygen()
        self._pir = pir if pir is not None else RLWEPIR(RLWEParams())
        self._use_aead = use_aead

        dataset = normalize_dataset(items)
        self._item_count = len(dataset)
        oprf_entries = {
            self._oprf.server_evaluate_direct(k, self._oprf_key): v
            for k, v in dataset.items()
        }
        self._table, self._record_size = CuckooTable.build(
            oprf_entries, num_bins=num_bins, use_aead=use_aead
        )
        self._slots: tuple[bytes, ...] = tuple(
            s for s in self._table.slots if s is not None
        )

    @property
    def protocol_name(self) -> str:
        return "cuckoo_oprf_pir"

    @property
    def item_count(self) -> int:
        return self._item_count

    def public_params(self) -> PublicParams:
        return PublicParams(
            protocol=self.protocol_name,
            params={
                "oprf": self._oprf.public_params(),
                "pir": self._pir.public_params(),
                "num_bins": self._table.num_bins,
                "cuckoo_seed": self._table.seed,
                "record_size": self._record_size,
                "use_aead": self._use_aead,
            },
        )

    def handle_request(self, request: ProtocolMessage) -> ProtocolMessage:
        if request.protocol != self.protocol_name:
            raise ValueError(f"Protocol mismatch: got '{request.protocol}'")
        if request.phase == "oprf_evaluate":
            evaluated = self._oprf.server_evaluate(request.payload["blinded"], self._oprf_key)
            return ProtocolMessage(
                protocol=self.protocol_name,
                phase="oprf_response",
                round_num=1,
                payload={"evaluated": evaluated},
            )
        if request.phase == "cuckoo_pir_query":
            ans1 = self._pir.server_answer(self._slots, request.payload["pir_query_1"])
            ans2 = self._pir.server_answer(self._slots, request.payload["pir_query_2"])
            return ProtocolMessage(
                protocol=self.protocol_name,
                phase="cuckoo_pir_response",
                round_num=2,
                payload={
                    "pir_response_1": ans1,
                    "pir_response_2": ans2,
                    "stash": list(self._table.stash),
                },
            )
        raise ValueError(f"Unknown phase '{request.phase}'")


class _CuckooOPRFPIRSession(PMSetSession):
    def __init__(
        self,
        item_bytes: bytes,
        oprf: ECDHOPRF,
        pir: SingleServerPIR,
        num_bins: int,
        cuckoo_seed: bytes,
        record_size: int,
        use_aead: bool,
    ) -> None:
        self._item_bytes = item_bytes
        self._oprf = oprf
        self._pir = pir
        self._num_bins = num_bins
        self._cuckoo_seed = cuckoo_seed
        self._record_size = record_size
        self._use_aead = use_aead
        self._lookup = PrefixBucketizer()

        self._stage = "need_oprf"
        self._blind_state: int | None = None
        self._oprf_output: bytes | None = None
        self._pir_state_1: Any = None
        self._pir_state_2: Any = None
        self._result: QueryResult | None = None

    @property
    def is_complete(self) -> bool:
        return self._stage == "done"

    def next_request(self) -> ProtocolMessage:
        if self._stage == "need_oprf":
            blinded, self._blind_state = self._oprf.client_blind(self._item_bytes)
            self._stage = "awaiting_oprf"
            return ProtocolMessage(
                protocol="cuckoo_oprf_pir",
                phase="oprf_evaluate",
                round_num=1,
                payload={"blinded": blinded},
            )
        if self._stage == "need_pir":
            assert self._oprf_output is not None
            pos1, pos2 = CuckooTable.hash_positions(
                self._oprf_output, self._num_bins, self._cuckoo_seed
            )
            q1, self._pir_state_1 = self._pir.client_generate_query(pos1, self._num_bins)
            q2, self._pir_state_2 = self._pir.client_generate_query(pos2, self._num_bins)
            self._stage = "awaiting_pir"
            return ProtocolMessage(
                protocol="cuckoo_oprf_pir",
                phase="cuckoo_pir_query",
                round_num=2,
                payload={"pir_query_1": q1, "pir_query_2": q2},
            )
        raise RuntimeError(f"Invalid session stage '{self._stage}'")

    def process_response(self, response: ProtocolMessage) -> None:
        if self._stage == "awaiting_oprf":
            assert self._blind_state is not None
            self._oprf_output = self._oprf.client_finalize(
                self._item_bytes, response.payload["evaluated"], self._blind_state
            )
            self._stage = "need_pir"
            return
        if self._stage == "awaiting_pir":
            assert self._oprf_output is not None
            slot1 = self._pir.client_extract(
                response.payload["pir_response_1"], self._pir_state_1, self._record_size
            )
            slot2 = self._pir.client_extract(
                response.payload["pir_response_2"], self._pir_state_2, self._record_size
            )
            stash_records: list[bytes] = response.payload["stash"]
            combined = slot1 + slot2 + b"".join(stash_records)
            is_member, payload = self._lookup.lookup_in_bucket(
                combined,
                self._oprf_output,
                record_size=self._record_size,
                use_aead=self._use_aead,
            )
            self._result = QueryResult(is_member=is_member, payload=payload)
            self._stage = "done"
            return
        raise RuntimeError(f"Unexpected response in stage '{self._stage}'")

    def result(self) -> QueryResult:
        if self._result is None:
            raise RuntimeError("Session not complete")
        return self._result


class CuckooOPRFPIRClient(PMSetClient):
    """Client for Cuckoo-Hashed OPRF + PIR."""

    def __init__(
        self,
        public_params: PublicParams,
        *,
        pir_override: SingleServerPIR | None = None,
    ) -> None:
        from pmset.protocols.oprf_pir import _make_pir_from_params

        if public_params.protocol != "cuckoo_oprf_pir":
            raise ValueError(f"Protocol mismatch: got '{public_params.protocol}'")
        p = public_params.params
        self._oprf = ECDHOPRF.from_public_params(p["oprf"])
        self._pir = pir_override if pir_override is not None else _make_pir_from_params(p["pir"])
        self._num_bins = int(p["num_bins"])
        self._cuckoo_seed = bytes(p["cuckoo_seed"])
        self._record_size = int(p["record_size"])
        self._use_aead = bool(p["use_aead"])

    @property
    def protocol_name(self) -> str:
        return "cuckoo_oprf_pir"

    def start_query(self, item: Item) -> PMSetSession:
        return _CuckooOPRFPIRSession(
            item_bytes=normalize_item(item),
            oprf=self._oprf,
            pir=self._pir,
            num_bins=self._num_bins,
            cuckoo_seed=self._cuckoo_seed,
            record_size=self._record_size,
            use_aead=self._use_aead,
        )


class CuckooOPRFPIRProtocol(PMSetProtocol):
    """Pinkas-Schneider-Zohner (PSZ14) Cuckoo Hashing + ECDH-OPRF + RLWE PIR."""

    _META = ProtocolMetadata(
        name="cuckoo_oprf_pir",
        display_name="Cuckoo Hashing + P-256 ECDH-OPRF + RLWE PIR (PSZ14)",
        family="Cuckoo + OPRF + PIR",
        description=(
            "Eliminates hash-bucket max-load padding by storing at most 1 record per bin "
            "in a 2-hash Cuckoo table (with tiny encrypted stash) and running 2 parallel RLWE PIR queries."
        ),
        assumptions=("DDH (NIST P-256)", "Ring-LWE", "Random Oracle"),
        security_model=SecurityModel.SEMI_HONEST_POST_QUANTUM,
        capabilities=ProtocolCapabilities(
            supports_payloads=True,
            supports_batch=True,
            false_positive_free=True,
            false_negative_free=True,
            post_quantum_pir=True,
            rounds=2,
        ),
        complexity=ComplexityProfile(
            rounds=2,
            client_upload="2 * O(2.4*N) RLWE ciphertexts",
            server_download="O(1) RLWE ciphertexts (2 single-record slots + stash)",
            server_compute="O(N) ring poly muls",
            client_compute="O(N) RLWE encrypts + 2 decrypts",
        ),
        references=("Pinkas-Schneider-Zohner USENIX Security 2014",),
        tla_spec="CuckooOPRFPIR.tla",
        lean_theorem="PMSet.Protocols.cuckoo_oprf_pir_correct",
    )

    @property
    def metadata(self) -> ProtocolMetadata:
        return self._META

    def create_server(self, items: DatasetInput, **config: Any) -> CuckooOPRFPIRServer:
        return CuckooOPRFPIRServer(items, **config)

    def create_client(self, public_params: PublicParams, **config: Any) -> CuckooOPRFPIRClient:
        return CuckooOPRFPIRClient(public_params, pir_override=config.get("pir"))
