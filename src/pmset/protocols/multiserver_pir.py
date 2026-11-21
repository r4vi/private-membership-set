"""Multi-Server Private Set Membership protocols: 2-Server DPF/FSS & k-Server Shamir IT-PIR.

Each protocol instantiates ``k >= 2`` strictly isolated :class:`PMSetServerReplica`
objects that NEVER communicate or share state when answering PIR queries:
  1. ``two_server_dpf_pir``: P-256 ECDH-OPRF + 2-Server Boyle-Gilboa-Ishai (BGI15)
     Distributed Point Function (FSS) PIR with O(log B) query size and pure
     symmetric-key XOR evaluation on each replica!
  2. ``shamir_multiserver_pir``: P-256 ECDH-OPRF + k-Server t-Private Information-
     Theoretic Chor-Goldreich-Kushilevitz-Sudan (CGKS) Shamir Secret-Sharing PIR,
     achieving information-theoretic PIR privacy against any coalition of <= t servers!
"""

from __future__ import annotations

from typing import Any

from pmset.core.interfaces import (
    MultiServerPMSetServer,
    PMSetClient,
    PMSetProtocol,
    PMSetServerReplica,
    PMSetSession,
)
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
from pmset.primitives.indexing import BuiltBuckets, PrefixBucketizer
from pmset.primitives.oprf import ECDHOPRF
from pmset.primitives.pir import (
    MultiServerPIR,
    ShamirMultiServerPIR,
    TwoServerDPFPIR,
)


class _IsolatedPIRReplica(PMSetServerReplica):
    """A single non-colluding server replica holding replicated buckets and an optional OPRF key."""

    def __init__(
        self,
        replica_id: int,
        buckets: tuple[bytes, ...],
        pir: MultiServerPIR,
        oprf: ECDHOPRF | None = None,
        oprf_key: int | None = None,
    ) -> None:
        self._replica_id = replica_id
        self._buckets = buckets
        self._pir = pir
        self._oprf = oprf
        self._oprf_key = oprf_key

    @property
    def replica_id(self) -> int:
        return self._replica_id

    def handle_replica_request(self, phase: str, payload: dict[str, Any]) -> dict[str, Any]:
        if phase == "oprf_evaluate":
            if self._oprf is None or self._oprf_key is None:
                raise ValueError(f"Replica {self._replica_id} does not serve OPRF requests")
            evaluated = self._oprf.server_evaluate(payload["blinded"], self._oprf_key)
            return {"evaluated": evaluated}
        if phase == "multiserver_pir_query":
            return self._pir.server_answer(self._replica_id, self._buckets, payload)
        raise ValueError(f"Unknown replica phase '{phase}'")


class MultiServerOPRFPIRServer(MultiServerPMSetServer):
    """Multi-server cluster wrapping ``k`` isolated replicas for OPRF + Multi-Server PIR."""

    def __init__(
        self,
        protocol_name: str,
        items: DatasetInput,
        *,
        pir: MultiServerPIR,
        bucket_count: int = 16,
        use_aead: bool = True,
    ) -> None:
        self._protocol_name = protocol_name
        self._pir = pir
        self._oprf = ECDHOPRF()
        self._bucketizer = PrefixBucketizer()
        oprf_key = self._oprf.keygen()

        dataset = normalize_dataset(items)
        self._item_count = len(dataset)
        oprf_entries = {
            self._oprf.server_evaluate_direct(k, oprf_key): v
            for k, v in dataset.items()
        }
        self._built: BuiltBuckets = self._bucketizer.build(
            oprf_entries, bucket_count=bucket_count, use_aead=use_aead
        )

        # Replica 0 serves OPRF (blinded, so learns nothing about x) + its isolated PIR share;
        # all other replicas serve strictly their isolated PIR share.
        self._replicas: tuple[PMSetServerReplica, ...] = tuple(
            _IsolatedPIRReplica(
                replica_id=rid,
                buckets=self._built.buckets,
                pir=pir,
                oprf=self._oprf if rid == 0 else None,
                oprf_key=oprf_key if rid == 0 else None,
            )
            for rid in range(pir.num_servers)
        )

    @property
    def protocol_name(self) -> str:
        return self._protocol_name

    @property
    def item_count(self) -> int:
        return self._item_count

    @property
    def replicas(self) -> tuple[PMSetServerReplica, ...]:
        return self._replicas

    def public_params(self) -> PublicParams:
        pir_params: dict[str, Any] = {"pir": self._pir.name, "num_servers": self._pir.num_servers}
        if isinstance(self._pir, ShamirMultiServerPIR):
            pir_params["privacy_threshold"] = self._pir.privacy_threshold
            pir_params["prime"] = self._pir.prime
        return PublicParams(
            protocol=self._protocol_name,
            params={
                "oprf": self._oprf.public_params(),
                "pir": pir_params,
                "bucket_count": self._built.bucket_count,
                "record_size": self._built.record_size,
                "bucket_byte_len": self._built.bucket_byte_len,
                "use_aead": self._built.use_aead,
            },
        )


class _MultiServerOPRFPIRSession(PMSetSession):
    def __init__(
        self,
        protocol_name: str,
        item_bytes: bytes,
        oprf: ECDHOPRF,
        pir: MultiServerPIR,
        bucket_count: int,
        record_size: int,
        bucket_byte_len: int,
        use_aead: bool,
    ) -> None:
        self._protocol_name = protocol_name
        self._item_bytes = item_bytes
        self._oprf = oprf
        self._pir = pir
        self._bucketizer = PrefixBucketizer()
        self._bucket_count = bucket_count
        self._record_size = record_size
        self._bucket_byte_len = bucket_byte_len
        self._use_aead = use_aead

        self._stage = "need_oprf"
        self._blind_state: int | None = None
        self._oprf_output: bytes | None = None
        self._pir_state: Any = None
        self._result: QueryResult | None = None

    @property
    def is_complete(self) -> bool:
        return self._stage == "done"

    def next_request(self) -> ProtocolMessage:
        if self._stage == "need_oprf":
            blinded, self._blind_state = self._oprf.client_blind(self._item_bytes)
            self._stage = "awaiting_oprf"
            return ProtocolMessage(
                protocol=self._protocol_name,
                phase="oprf_evaluate",
                round_num=1,
                replica_payloads={0: {"blinded": blinded}},
            )
        if self._stage == "need_pir":
            assert self._oprf_output is not None
            bucket_idx = self._bucketizer.bucket_index(self._oprf_output, self._bucket_count)
            per_server_queries, self._pir_state = self._pir.client_generate_queries(
                bucket_idx, self._bucket_count
            )
            self._stage = "awaiting_pir"
            return ProtocolMessage(
                protocol=self._protocol_name,
                phase="multiserver_pir_query",
                round_num=2,
                replica_payloads=per_server_queries,
            )
        raise RuntimeError(f"Invalid session stage '{self._stage}'")

    def process_response(self, response: ProtocolMessage) -> None:
        if response.replica_payloads is None:
            raise ValueError("Expected multi-server replica_payloads in response")
        if self._stage == "awaiting_oprf":
            assert self._blind_state is not None
            self._oprf_output = self._oprf.client_finalize(
                self._item_bytes, response.replica_payloads[0]["evaluated"], self._blind_state
            )
            self._stage = "need_pir"
            return
        if self._stage == "awaiting_pir":
            assert self._oprf_output is not None
            bucket_bytes = self._pir.client_combine(
                response.replica_payloads, self._pir_state, self._bucket_byte_len
            )
            is_member, payload = self._bucketizer.lookup_in_bucket(
                bucket_bytes,
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


class MultiServerOPRFPIRClient(PMSetClient):
    """Client for multi-server OPRF + DPF/Shamir PIR."""

    def __init__(self, public_params: PublicParams) -> None:
        self._protocol_name = public_params.protocol
        p = public_params.params
        self._oprf = ECDHOPRF.from_public_params(p["oprf"])
        pir_cfg = p["pir"]
        if pir_cfg["pir"] == "two-server-dpf":
            self._pir: MultiServerPIR = TwoServerDPFPIR()
        elif str(pir_cfg["pir"]).startswith("shamir-it-pir"):
            self._pir = ShamirMultiServerPIR(
                num_servers=int(pir_cfg["num_servers"]),
                privacy_threshold=int(pir_cfg["privacy_threshold"]),
                prime=int(pir_cfg["prime"]),
            )
        else:
            raise ValueError(f"Unknown multi-server PIR: {pir_cfg['pir']!r}")
        self._bucket_count = int(p["bucket_count"])
        self._record_size = int(p["record_size"])
        self._bucket_byte_len = int(p["bucket_byte_len"])
        self._use_aead = bool(p["use_aead"])

    @property
    def protocol_name(self) -> str:
        return self._protocol_name

    def start_query(self, item: Item) -> PMSetSession:
        return _MultiServerOPRFPIRSession(
            protocol_name=self._protocol_name,
            item_bytes=normalize_item(item),
            oprf=self._oprf,
            pir=self._pir,
            bucket_count=self._bucket_count,
            record_size=self._record_size,
            bucket_byte_len=self._bucket_byte_len,
            use_aead=self._use_aead,
        )


class TwoServerDPFPIRProtocol(PMSetProtocol):
    """2-Server Boyle-Gilboa-Ishai (BGI15) DPF/FSS PIR + P-256 ECDH-OPRF."""

    _META = ProtocolMetadata(
        name="two_server_dpf_pir",
        display_name="2-Server DPF/FSS PIR + P-256 ECDH-OPRF (BGI15)",
        family="Multi-Server FSS / DPF PIR",
        description=(
            "Splits the bucket selector via a Boyle-Gilboa-Ishai Distributed Point Function "
            "PRG tree across 2 non-colluding servers: O(log B) query size and pure XOR evaluation!"
        ),
        assumptions=("2 Non-Colluding Servers", "PRG (SHAKE-256)", "DDH (NIST P-256)"),
        security_model=SecurityModel.SEMI_HONEST_MULTI_SERVER_FSS,
        capabilities=ProtocolCapabilities(
            supports_payloads=True,
            supports_batch=True,
            false_positive_free=True,
            false_negative_free=True,
            multi_server=True,
            num_servers=2,
            post_quantum_pir=True,
            rounds=2,
        ),
        complexity=ComplexityProfile(
            rounds=2,
            client_upload="O(log B) bytes per server!",
            server_download="O(N/B) bytes per server",
            server_compute="O(B) PRG ops + O(N) XORs",
            client_compute="O(log B) PRG ops + 1 XOR",
        ),
        references=("Boyle-Gilboa-Ishai EUROCRYPT 2015 / CCS 2016",),
        tla_spec="TwoServerDPFPIR.tla",
        lean_theorem="PMSet.Protocols.two_server_dpf_pir_correct",
    )

    @property
    def metadata(self) -> ProtocolMetadata:
        return self._META

    def create_server(self, items: DatasetInput, **config: Any) -> MultiServerOPRFPIRServer:
        return MultiServerOPRFPIRServer(
            self.name,
            items,
            pir=TwoServerDPFPIR(),
            bucket_count=int(config.get("bucket_count", 16)),
            use_aead=bool(config.get("use_aead", True)),
        )

    def create_client(self, public_params: PublicParams, **config: Any) -> MultiServerOPRFPIRClient:
        if public_params.protocol != self.name:
            raise ValueError(f"Protocol mismatch: got '{public_params.protocol}'")
        return MultiServerOPRFPIRClient(public_params)


class ShamirMultiServerPIRProtocol(PMSetProtocol):
    """k-Server t-Private Information-Theoretic Shamir PIR (CGKS) + P-256 ECDH-OPRF."""

    _META = ProtocolMetadata(
        name="shamir_multiserver_pir",
        display_name="k-Server t-Private Information-Theoretic Shamir PIR + OPRF (CGKS)",
        family="Multi-Server Information-Theoretic PIR",
        description=(
            "Secret-shares the PIR indicator vector across k >= t+1 non-colluding servers using "
            "degree-t Shamir polynomials over F_p. Any coalition of <= t servers has ZERO "
            "information-theoretic advantage in distinguishing queried buckets."
        ),
        assumptions=("At most t < k Colluding Servers", "DDH (NIST P-256 for OPRF)"),
        security_model=SecurityModel.SEMI_HONEST_INFORMATION_THEORETIC,
        capabilities=ProtocolCapabilities(
            supports_payloads=True,
            supports_batch=True,
            false_positive_free=True,
            false_negative_free=True,
            multi_server=True,
            num_servers=3,
            post_quantum_pir=True,
            rounds=2,
        ),
        complexity=ComplexityProfile(
            rounds=2,
            client_upload="O(B) field elements per server",
            server_download="O(N/B) field elements per server",
            server_compute="O(N) field multiplications",
            client_compute="O(k * B) poly evals + Lagrange interpolation",
        ),
        references=("Chor-Goldreich-Kushilevitz-Sudan FOCS 1995", "Shamir 1979"),
        tla_spec="ShamirMultiServerPIR.tla",
        lean_theorem="PMSet.Protocols.shamir_multiserver_pir_correct",
    )

    @property
    def metadata(self) -> ProtocolMetadata:
        return self._META

    def create_server(self, items: DatasetInput, **config: Any) -> MultiServerOPRFPIRServer:
        num_servers = int(config.get("num_servers", 3))
        privacy_threshold = int(config.get("privacy_threshold", 1))
        pir = ShamirMultiServerPIR(
            num_servers=num_servers,
            privacy_threshold=privacy_threshold,
        )
        return MultiServerOPRFPIRServer(
            self.name,
            items,
            pir=pir,
            bucket_count=int(config.get("bucket_count", 16)),
            use_aead=bool(config.get("use_aead", True)),
        )

    def create_client(self, public_params: PublicParams, **config: Any) -> MultiServerOPRFPIRClient:
        if public_params.protocol != self.name:
            raise ValueError(f"Protocol mismatch: got '{public_params.protocol}'")
        return MultiServerOPRFPIRClient(public_params)
