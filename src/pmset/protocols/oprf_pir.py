"""Modular OPRF + Bucketized Single-Server PIR PMSet protocol family.

Implements Google's Private Set Membership (PSM) architecture in a fully
composable form:
  Round 1 (OPRF): Client blinds item -> Server evaluates -> Client unblinds &
                  derives bucket index, lookup tag, and AEAD decryption key.
  Round 2 (PIR):  Client generates PIR query for bucket index -> Server answers
                  homomorphically over uniformly padded buckets -> Client
                  extracts bucket, verifies lookup tag, and decrypts AEAD payload.

Concrete specializations registered in the global catalog:
  - ``dh_oprf_paillier_pir``: Safe-prime DH-OPRF + Paillier 1D PIR + AEAD
  - ``ecdh_oprf_paillier_pir``: P-256 ECDH-OPRF + Prefix Buckets + Paillier 1D PIR + AEAD
  - ``ecdh_oprf_paillier_2d_pir``: P-256 ECDH-OPRF + Prefix Buckets + Paillier 2D sqrt(B) PIR + AEAD
  - ``rsa_oprf_paillier_pir``: Chaum Blind-RSA OPRF + Prefix Buckets + Paillier 1D PIR + AEAD
  - ``oprf_rlwe_pir``: P-256 ECDH-OPRF + Prefix Buckets + Post-Quantum RLWE Lattice PIR + AEAD
"""

from __future__ import annotations

from typing import Any, Callable

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
from pmset.primitives.indexing import (
    Bucketizer,
    BuiltBuckets,
    ModuloBucketizer,
    PrefixBucketizer,
)
from pmset.primitives.oprf import (
    DHOPRF,
    ECDHOPRF,
    OPRF,
    RSAOPRF,
    create_oprf_from_params,
)
from pmset.primitives.pir import (
    Paillier2DPIR,
    PaillierLinearPIR,
    RLWEPIR,
    SingleServerPIR,
)
from pmset.primitives.rlwe import RLWEParams


def _make_bucketizer(mode: str) -> Bucketizer:
    if mode == "prefix":
        return PrefixBucketizer()
    if mode == "modulo":
        return ModuloBucketizer()
    raise ValueError(f"Unknown bucketizer mode: {mode!r}")


def _make_pir_from_params(params: dict[str, Any]) -> SingleServerPIR:
    kind = params.get("pir")
    if kind == "paillier-linear":
        return PaillierLinearPIR(key_bits=int(params.get("key_bits", 512)))
    if kind == "paillier-2d":
        return Paillier2DPIR(key_bits=int(params.get("key_bits", 512)))
    if kind == "rlwe-lattice":
        return RLWEPIR(params=RLWEParams.from_dict(params["rlwe"]))
    raise ValueError(f"Unknown single-server PIR kind: {kind!r}")


class OPRFPIRServer(PMSetServer):
    """Stateless server for any OPRF + Bucketized Single-Server PIR composition."""

    def __init__(
        self,
        protocol_name: str,
        items: DatasetInput,
        *,
        oprf: OPRF,
        pir: SingleServerPIR,
        bucketizer: Bucketizer,
        bucket_count: int = 8,
        use_aead: bool = True,
    ) -> None:
        if bucket_count < 1:
            raise ValueError(f"bucket_count must be >= 1, got {bucket_count}")
        self._protocol_name = protocol_name
        self._oprf = oprf
        self._pir = pir
        self._bucketizer = bucketizer
        self._oprf_key = oprf.keygen()

        dataset = normalize_dataset(items)
        self._item_count = len(dataset)
        oprf_entries = {
            oprf.server_evaluate_direct(item_bytes, self._oprf_key): payload
            for item_bytes, payload in dataset.items()
        }
        self._built: BuiltBuckets = bucketizer.build(
            oprf_entries, bucket_count=bucket_count, use_aead=use_aead
        )

    @property
    def protocol_name(self) -> str:
        return self._protocol_name

    @property
    def item_count(self) -> int:
        return self._item_count

    @property
    def bucket_count(self) -> int:
        return self._built.bucket_count

    @property
    def buckets(self) -> tuple[bytes, ...]:
        return self._built.buckets

    def public_params(self) -> PublicParams:
        return PublicParams(
            protocol=self._protocol_name,
            params={
                "oprf": self._oprf.public_params(),
                "pir": self._pir.public_params(),
                "bucket_mode": self._bucketizer.mode,
                "bucket_count": self._built.bucket_count,
                "record_size": self._built.record_size,
                "bucket_byte_len": self._built.bucket_byte_len,
                "use_aead": self._built.use_aead,
            },
        )

    def handle_request(self, request: ProtocolMessage) -> ProtocolMessage:
        if request.protocol != self._protocol_name:
            raise ValueError(
                f"Protocol mismatch: expected '{self._protocol_name}', got '{request.protocol}'"
            )
        if request.phase == "oprf_evaluate":
            evaluated = self._oprf.server_evaluate(request.payload["blinded"], self._oprf_key)
            return ProtocolMessage(
                protocol=self._protocol_name,
                phase="oprf_response",
                round_num=1,
                payload={"evaluated": evaluated},
            )
        if request.phase == "pir_query":
            answer = self._pir.server_answer(self._built.buckets, request.payload["pir_query"])
            return ProtocolMessage(
                protocol=self._protocol_name,
                phase="pir_response",
                round_num=2,
                payload={"pir_response": answer},
            )
        raise ValueError(f"Unknown phase '{request.phase}' for {self._protocol_name}")


class _OPRFPIRSession(PMSetSession):
    def __init__(
        self,
        protocol_name: str,
        item_bytes: bytes,
        oprf: OPRF,
        pir: SingleServerPIR,
        bucketizer: Bucketizer,
        bucket_count: int,
        record_size: int,
        bucket_byte_len: int,
        use_aead: bool,
    ) -> None:
        self._protocol_name = protocol_name
        self._item_bytes = item_bytes
        self._oprf = oprf
        self._pir = pir
        self._bucketizer = bucketizer
        self._bucket_count = bucket_count
        self._record_size = record_size
        self._bucket_byte_len = bucket_byte_len
        self._use_aead = use_aead

        self._stage = "need_oprf"
        self._blind_state: Any = None
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
                payload={"blinded": blinded},
            )
        if self._stage == "need_pir":
            assert self._oprf_output is not None
            bucket_idx = self._bucketizer.bucket_index(self._oprf_output, self._bucket_count)
            pir_query, self._pir_state = self._pir.client_generate_query(
                bucket_idx, self._bucket_count
            )
            self._stage = "awaiting_pir"
            return ProtocolMessage(
                protocol=self._protocol_name,
                phase="pir_query",
                round_num=2,
                payload={"pir_query": pir_query},
            )
        raise RuntimeError(f"Session cannot produce request in stage '{self._stage}'")

    def process_response(self, response: ProtocolMessage) -> None:
        if response.protocol != self._protocol_name:
            raise ValueError(
                f"Protocol mismatch: expected '{self._protocol_name}', got '{response.protocol}'"
            )
        if self._stage == "awaiting_oprf":
            if response.phase != "oprf_response":
                raise ValueError(f"Expected 'oprf_response', got '{response.phase}'")
            self._oprf_output = self._oprf.client_finalize(
                self._item_bytes, response.payload["evaluated"], self._blind_state
            )
            self._stage = "need_pir"
            return
        if self._stage == "awaiting_pir":
            if response.phase != "pir_response":
                raise ValueError(f"Expected 'pir_response', got '{response.phase}'")
            assert self._oprf_output is not None
            bucket_bytes = self._pir.client_extract(
                response.payload["pir_response"],
                self._pir_state,
                self._bucket_byte_len,
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
            raise RuntimeError("Query session is not complete")
        return self._result


class OPRFPIRClient(PMSetClient):
    """Client for any OPRF + Bucketized Single-Server PIR protocol."""

    def __init__(
        self,
        public_params: PublicParams,
        *,
        pir_override: SingleServerPIR | None = None,
    ) -> None:
        self._protocol_name = public_params.protocol
        p = public_params.params
        self._oprf = create_oprf_from_params(p["oprf"])
        self._pir = pir_override if pir_override is not None else _make_pir_from_params(p["pir"])
        self._bucketizer = _make_bucketizer(p["bucket_mode"])
        self._bucket_count = int(p["bucket_count"])
        self._record_size = int(p["record_size"])
        self._bucket_byte_len = int(p["bucket_byte_len"])
        self._use_aead = bool(p["use_aead"])

    @property
    def protocol_name(self) -> str:
        return self._protocol_name

    def start_query(self, item: Item) -> PMSetSession:
        return _OPRFPIRSession(
            protocol_name=self._protocol_name,
            item_bytes=normalize_item(item),
            oprf=self._oprf,
            pir=self._pir,
            bucketizer=self._bucketizer,
            bucket_count=self._bucket_count,
            record_size=self._record_size,
            bucket_byte_len=self._bucket_byte_len,
            use_aead=self._use_aead,
        )


class ComposableOPRFPIRProtocol(PMSetProtocol):
    """Generic configurable OPRF + Bucketized PIR protocol factory."""

    def __init__(
        self,
        meta: ProtocolMetadata,
        *,
        oprf_factory: Callable[..., OPRF],
        pir_factory: Callable[..., SingleServerPIR],
        default_bucket_mode: str = "prefix",
        default_bucket_count: int = 8,
        default_use_aead: bool = True,
    ) -> None:
        self._meta = meta
        self._oprf_factory = oprf_factory
        self._pir_factory = pir_factory
        self._default_bucket_mode = default_bucket_mode
        self._default_bucket_count = default_bucket_count
        self._default_use_aead = default_use_aead

    @property
    def metadata(self) -> ProtocolMetadata:
        return self._meta

    def create_server(self, items: DatasetInput, **config: Any) -> OPRFPIRServer:
        bucket_count = int(config.pop("bucket_count", self._default_bucket_count))
        bucket_mode = str(config.pop("bucket_mode", self._default_bucket_mode))
        use_aead = bool(config.pop("use_aead", self._default_use_aead))
        oprf = config.pop("oprf", None) or self._oprf_factory(**config.pop("oprf_config", {}))
        pir = config.pop("pir", None) or self._pir_factory(**config.pop("pir_config", {}))
        return OPRFPIRServer(
            self.name,
            items,
            oprf=oprf,
            pir=pir,
            bucketizer=_make_bucketizer(bucket_mode),
            bucket_count=bucket_count,
            use_aead=use_aead,
        )

    def create_client(self, public_params: PublicParams, **config: Any) -> OPRFPIRClient:
        if public_params.protocol != self.name:
            raise ValueError(
                f"PublicParams protocol mismatch: expected '{self.name}', got '{public_params.protocol}'"
            )
        return OPRFPIRClient(public_params, pir_override=config.get("pir"))


# ---------------------------------------------------------------------------
# Concrete OPRF + PIR protocol instances
# ---------------------------------------------------------------------------


def make_dh_oprf_paillier_pir() -> ComposableOPRFPIRProtocol:
    return ComposableOPRFPIRProtocol(
        ProtocolMetadata(
            name="dh_oprf_paillier_pir",
            display_name="Safe-Prime DH-OPRF + Paillier Linear PIR",
            family="OPRF + Single-Server PIR",
            description=(
                "Hardened evolution of the classic DH-OPRF + Paillier linear PIR protocol: "
                "uses a safe-prime prime-order quadratic-residue subgroup (DDH-secure), "
                "CSPRNG, uniform bucket padding, and AES-256-GCM AEAD encrypted records."
            ),
            assumptions=("DDH (safe-prime subgroup)", "DCR (Paillier)", "Random Oracle"),
            security_model=SecurityModel.SEMI_HONEST_COMPUTATIONAL,
            capabilities=ProtocolCapabilities(
                supports_payloads=True,
                supports_batch=True,
                false_positive_free=True,
                false_negative_free=True,
                rounds=2,
            ),
            complexity=ComplexityProfile(
                rounds=2,
                client_upload="O(B) Paillier ciphertexts",
                server_download="O(N/B) Paillier ciphertexts",
                server_compute="O(N) modular exponentiations",
                client_compute="O(B) Paillier encrypts + O(N/B) decrypts",
            ),
            references=("Google Private Membership", "Paillier 1999"),
            tla_spec="OPRFPIR.tla",
            lean_theorem="PMSet.Protocols.dh_oprf_paillier_pir_correct",
        ),
        oprf_factory=lambda **kw: DHOPRF(**kw),
        pir_factory=lambda **kw: PaillierLinearPIR(key_bits=kw.get("key_bits", 512)),
        default_bucket_mode="modulo",
        default_bucket_count=8,
    )


def make_ecdh_oprf_paillier_pir() -> ComposableOPRFPIRProtocol:
    return ComposableOPRFPIRProtocol(
        ProtocolMetadata(
            name="ecdh_oprf_paillier_pir",
            display_name="P-256 ECDH-OPRF + Prefix Buckets + Paillier 1D PIR",
            family="OPRF + Single-Server PIR",
            description=(
                "Prime-order NIST P-256 ECDH-OPRF (RFC 9497 style) paired with Google-style "
                "prefix bucketization, HKDF-keyed AES-256-GCM record encryption, and Paillier 1D PIR."
            ),
            assumptions=("DDH (NIST P-256)", "DCR (Paillier)", "Random Oracle"),
            security_model=SecurityModel.SEMI_HONEST_COMPUTATIONAL,
            capabilities=ProtocolCapabilities(
                supports_payloads=True,
                supports_batch=True,
                false_positive_free=True,
                false_negative_free=True,
                rounds=2,
            ),
            complexity=ComplexityProfile(
                rounds=2,
                client_upload="O(B) Paillier ciphertexts",
                server_download="O(N/B) Paillier ciphertexts",
                server_compute="O(N) modular exponentiations",
                client_compute="O(B) Paillier encrypts + 2 P-256 scalar muls",
            ),
            references=("RFC 9497", "Google Private Membership"),
            tla_spec="OPRFPIR.tla",
            lean_theorem="PMSet.Protocols.ecdh_oprf_paillier_pir_correct",
        ),
        oprf_factory=lambda **kw: ECDHOPRF(),
        pir_factory=lambda **kw: PaillierLinearPIR(key_bits=kw.get("key_bits", 512)),
        default_bucket_mode="prefix",
        default_bucket_count=8,
    )


def make_ecdh_oprf_paillier_2d_pir() -> ComposableOPRFPIRProtocol:
    return ComposableOPRFPIRProtocol(
        ProtocolMetadata(
            name="ecdh_oprf_paillier_2d_pir",
            display_name="P-256 ECDH-OPRF + Paillier 2D sqrt(B) PIR",
            family="OPRF + Single-Server PIR",
            description=(
                "Arranges B prefix buckets in a sqrt(B) x sqrt(B) matrix so the client only "
                "uploads O(sqrt(B)) Paillier ciphertexts instead of O(B)."
            ),
            assumptions=("DDH (NIST P-256)", "DCR (Paillier)", "Random Oracle"),
            security_model=SecurityModel.SEMI_HONEST_COMPUTATIONAL,
            capabilities=ProtocolCapabilities(
                supports_payloads=True,
                supports_batch=True,
                false_positive_free=True,
                false_negative_free=True,
                rounds=2,
            ),
            complexity=ComplexityProfile(
                rounds=2,
                client_upload="O(sqrt(B)) Paillier ciphertexts",
                server_download="O(sqrt(B) * N/B) Paillier ciphertexts",
                server_compute="O(N) modular exponentiations",
                client_compute="O(sqrt(B)) encrypts + O(N/B) decrypts",
            ),
            references=("Kushilevitz-Ostrovsky 1997", "Google Private Membership"),
            tla_spec="OPRFPIR.tla",
            lean_theorem="PMSet.Protocols.ecdh_oprf_paillier_2d_pir_correct",
        ),
        oprf_factory=lambda **kw: ECDHOPRF(),
        pir_factory=lambda **kw: Paillier2DPIR(key_bits=kw.get("key_bits", 512)),
        default_bucket_mode="prefix",
        default_bucket_count=9,
    )


def make_rsa_oprf_paillier_pir() -> ComposableOPRFPIRProtocol:
    return ComposableOPRFPIRProtocol(
        ProtocolMetadata(
            name="rsa_oprf_paillier_pir",
            display_name="Chaum Blind-RSA OPRF + Paillier PIR",
            family="OPRF + Single-Server PIR",
            description=(
                "Chaum blind-signature RSA-OPRF (RFC 9474 paradigm) paired with prefix "
                "bucketization, AEAD encryption, and Paillier PIR."
            ),
            assumptions=("RSA One-More Inversion", "DCR (Paillier)", "Random Oracle"),
            security_model=SecurityModel.SEMI_HONEST_COMPUTATIONAL,
            capabilities=ProtocolCapabilities(
                supports_payloads=True,
                supports_batch=True,
                false_positive_free=True,
                false_negative_free=True,
                rounds=2,
            ),
            complexity=ComplexityProfile(
                rounds=2,
                client_upload="O(B) Paillier ciphertexts",
                server_download="O(N/B) Paillier ciphertexts",
                server_compute="O(N) modular exponentiations",
                client_compute="O(B) Paillier encrypts + 1 RSA blind",
            ),
            references=("Chaum 1983", "RFC 9474"),
            tla_spec="OPRFPIR.tla",
            lean_theorem="PMSet.Protocols.rsa_oprf_paillier_pir_correct",
        ),
        oprf_factory=lambda **kw: RSAOPRF(bits=kw.get("rsa_bits", 512)),
        pir_factory=lambda **kw: PaillierLinearPIR(key_bits=kw.get("key_bits", 512)),
        default_bucket_mode="prefix",
        default_bucket_count=8,
    )


def make_oprf_rlwe_pir() -> ComposableOPRFPIRProtocol:
    return ComposableOPRFPIRProtocol(
        ProtocolMetadata(
            name="oprf_rlwe_pir",
            display_name="P-256 ECDH-OPRF + Post-Quantum RLWE Lattice PIR",
            family="OPRF + Lattice PIR (Google PSM-RLWE)",
            description=(
                "Pure-Python realization of Google's RLWE-based Private Membership protocol: "
                "P-256 ECDH-OPRF + prefix bucketization + AES-256-GCM encrypted buckets + "
                "Ring-LWE lattice PIR over R_q = Z_q[X]/(X^N + 1) with byte-packed polynomials."
            ),
            assumptions=("DDH (NIST P-256)", "Ring-LWE (Post-Quantum PIR)", "Random Oracle"),
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
                client_upload="O(B) RLWE ciphertexts",
                server_download="O(ceil(bucket_bytes / N)) RLWE ciphertexts",
                server_compute="O(B * ceil(bucket_bytes / N)) ring poly muls",
                client_compute="O(B) RLWE encrypts + O(chunks) decrypts",
            ),
            references=("Google private-membership (RLWE)", "Angel et al. SealPIR 2018"),
            tla_spec="OPRFPIR.tla",
            lean_theorem="PMSet.Protocols.oprf_rlwe_pir_correct",
        ),
        oprf_factory=lambda **kw: ECDHOPRF(),
        pir_factory=lambda **kw: RLWEPIR(params=kw.get("rlwe_params", RLWEParams())),
        default_bucket_mode="prefix",
        default_bucket_count=8,
    )
