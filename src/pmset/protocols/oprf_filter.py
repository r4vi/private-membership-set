"""Amortized O(1) ECDH-OPRF + Compact Encrypted Filter / Hashed Set PMSet protocol.

Used widely in real-world private credential checks and unbalanced PSI (e.g.,
Apple / Cloudflare / Password Monitor style):
  - Setup (amortized once via PublicParams): Server computes OPRF_k(s) for every
    s in S, derives a 128-bit lookup tag (and optional AEAD-encrypted payload
    keyed by HKDF(OPRF_k(s))), and publishes either:
      * ``filter_mode="exact"``: sorted list of opaque 16-byte tags (+ optional
        encrypted payloads) — ZERO false positives!
      * ``filter_mode="bloom"``: compact Bloom filter over the tags — tiny
        bandwidth with configurable FPR (e.g. 1e-6).
  - Query (1 round, O(1) bandwidth & computation!):
      Client runs P-256 ECDH-OPRF with Server to obtain OPRF_k(x), derives tag
      and AEAD key, and checks membership locally against the server digest.

Security: Under DDH / One-More DH on P-256, the published OPRF tags are
pseudorandom without the server's secret key k, preventing offline dictionary
attacks against S.
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
from pmset.primitives.aead import DecryptionError, aead_decrypt, aead_encrypt
from pmset.primitives.indexing import BloomFilter, derive_bucket_and_keys
from pmset.primitives.oprf import ECDHOPRF


class ECDHOPRFFilterServer(PMSetServer):
    """Stateless server for Amortized O(1) ECDH-OPRF + Encrypted Filter/Set."""

    def __init__(
        self,
        items: DatasetInput,
        *,
        filter_mode: str = "exact",
        false_positive_rate: float = 1e-6,
    ) -> None:
        if filter_mode not in ("exact", "bloom"):
            raise ValueError(f"filter_mode must be 'exact' or 'bloom', got {filter_mode!r}")
        self._oprf = ECDHOPRF()
        self._oprf_key = self._oprf.keygen()
        self._filter_mode = filter_mode

        dataset = normalize_dataset(items)
        self._item_count = len(dataset)
        self._exact_entries: dict[bytes, bytes] = {}
        self._bloom: BloomFilter | None = None

        if filter_mode == "bloom":
            if any(v is not None for v in dataset.values()):
                raise ValueError(
                    "ECDHOPRFFilterServer with filter_mode='bloom' does not support item payloads; "
                    "use filter_mode='exact' for AEAD payload retrieval"
                )
            bf = BloomFilter.for_capacity(len(dataset), false_positive_rate=false_positive_rate)
            for item_bytes in dataset.keys():
                oprf_out = self._oprf.server_evaluate_direct(item_bytes, self._oprf_key)
                _, tag, _ = derive_bucket_and_keys(oprf_out, bucket_count=1)
                bf.add(tag)
            self._bloom = bf
        else:
            for item_bytes, payload in dataset.items():
                oprf_out = self._oprf.server_evaluate_direct(item_bytes, self._oprf_key)
                _, tag, aead_key = derive_bucket_and_keys(oprf_out, bucket_count=1)
                pt = (b"\x01" + payload) if payload is not None else b"\x00"
                self._exact_entries[tag] = aead_encrypt(aead_key, pt, aad=tag)

    @property
    def protocol_name(self) -> str:
        return "ecdh_oprf_filter"

    @property
    def item_count(self) -> int:
        return self._item_count

    def public_params(self) -> PublicParams:
        params: dict[str, Any] = {
            "oprf": self._oprf.public_params(),
            "filter_mode": self._filter_mode,
        }
        if self._filter_mode == "bloom":
            assert self._bloom is not None
            params["bloom"] = self._bloom.to_dict()
        else:
            # Sort lexicographically by opaque tag to hide insertion order
            params["entries"] = sorted(
                [(tag, ct) for tag, ct in self._exact_entries.items()],
                key=lambda pair: pair[0],
            )
        return PublicParams(protocol=self.protocol_name, params=params)

    def handle_request(self, request: ProtocolMessage) -> ProtocolMessage:
        if request.protocol != self.protocol_name or request.phase != "oprf_evaluate":
            raise ValueError(f"Unexpected message ({request.protocol}, {request.phase})")
        evaluated = self._oprf.server_evaluate(request.payload["blinded"], self._oprf_key)
        return ProtocolMessage(
            protocol=self.protocol_name,
            phase="oprf_response",
            round_num=1,
            payload={"evaluated": evaluated},
        )


class _ECDHOPRFFilterSession(PMSetSession):
    def __init__(
        self,
        item_bytes: bytes,
        oprf: ECDHOPRF,
        filter_mode: str,
        exact_map: dict[bytes, bytes] | None,
        bloom: BloomFilter | None,
    ) -> None:
        self._item_bytes = item_bytes
        self._oprf = oprf
        self._filter_mode = filter_mode
        self._exact_map = exact_map
        self._bloom = bloom
        self._stage = "need_oprf"
        self._blind_state: int | None = None
        self._result: QueryResult | None = None

    @property
    def is_complete(self) -> bool:
        return self._stage == "done"

    def next_request(self) -> ProtocolMessage:
        if self._stage != "need_oprf":
            raise RuntimeError(f"Invalid session stage '{self._stage}'")
        blinded, self._blind_state = self._oprf.client_blind(self._item_bytes)
        self._stage = "awaiting_oprf"
        return ProtocolMessage(
            protocol="ecdh_oprf_filter",
            phase="oprf_evaluate",
            round_num=1,
            payload={"blinded": blinded},
        )

    def process_response(self, response: ProtocolMessage) -> None:
        if self._stage != "awaiting_oprf" or response.phase != "oprf_response":
            raise ValueError(f"Unexpected response in stage '{self._stage}'")
        assert self._blind_state is not None
        oprf_out = self._oprf.client_finalize(
            self._item_bytes, response.payload["evaluated"], self._blind_state
        )
        _, tag, aead_key = derive_bucket_and_keys(oprf_out, bucket_count=1)
        if self._filter_mode == "bloom":
            assert self._bloom is not None
            self._result = QueryResult(is_member=self._bloom.contains(tag), payload=None)
        else:
            assert self._exact_map is not None
            ct = self._exact_map.get(tag)
            if ct is None:
                self._result = QueryResult(is_member=False, payload=None)
            else:
                try:
                    pt = aead_decrypt(aead_key, ct, aad=tag)
                    payload = pt[1:] if (pt and pt[0] == 1) else None
                    self._result = QueryResult(is_member=True, payload=payload)
                except DecryptionError:
                    self._result = QueryResult(is_member=False, payload=None)
        self._stage = "done"

    def result(self) -> QueryResult:
        if self._result is None:
            raise RuntimeError("Session not complete")
        return self._result


class ECDHOPRFFilterClient(PMSetClient):
    """Client for Amortized O(1) ECDH-OPRF + Encrypted Filter/Set."""

    def __init__(self, public_params: PublicParams) -> None:
        if public_params.protocol != "ecdh_oprf_filter":
            raise ValueError(f"Protocol mismatch: got '{public_params.protocol}'")
        p = public_params.params
        self._oprf = ECDHOPRF.from_public_params(p["oprf"])
        self._filter_mode = str(p["filter_mode"])
        if self._filter_mode == "bloom":
            self._bloom: BloomFilter | None = BloomFilter.from_dict(p["bloom"])
            self._exact_map: dict[bytes, bytes] | None = None
        else:
            self._bloom = None
            self._exact_map = {bytes(t): bytes(ct) for t, ct in p["entries"]}

    @property
    def protocol_name(self) -> str:
        return "ecdh_oprf_filter"

    def start_query(self, item: Item) -> PMSetSession:
        return _ECDHOPRFFilterSession(
            normalize_item(item),
            self._oprf,
            self._filter_mode,
            self._exact_map,
            self._bloom,
        )


class ECDHOPRFFilterProtocol(PMSetProtocol):
    """Amortized O(1) P-256 ECDH-OPRF + Compact Encrypted Set / Bloom Filter."""

    _META = ProtocolMetadata(
        name="ecdh_oprf_filter",
        display_name="Amortized O(1) P-256 ECDH-OPRF + Encrypted Filter/Set",
        family="Amortized OPRF + Digest",
        description=(
            "1-round, O(1) per-query protocol: server publishes an OPRF-keyed opaque "
            "tag set (or Bloom filter) once in PublicParams; each query is a single "
            "33-byte P-256 OPRF round-trip."
        ),
        assumptions=("One-More DDH (NIST P-256)", "Random Oracle"),
        security_model=SecurityModel.SEMI_HONEST_COMPUTATIONAL,
        capabilities=ProtocolCapabilities(
            supports_payloads=True,
            supports_batch=True,
            false_positive_free=True,
            false_negative_free=True,
            rounds=1,
        ),
        complexity=ComplexityProfile(
            rounds=1,
            client_upload="O(1) (33 bytes!)",
            server_download="O(1) online (33 bytes!) + O(N) one-time digest",
            server_compute="O(1) (1 P-256 scalar mul!)",
            client_compute="O(1) (2 P-256 scalar muls!)",
        ),
        references=("RFC 9497", "Kiss et al. Unbalanced PSI", "Cloudflare/Apple OPRF PSI"),
        tla_spec="OPRFFilter.tla",
        lean_theorem="PMSet.Protocols.ecdh_oprf_filter_correct",
    )

    @property
    def metadata(self) -> ProtocolMetadata:
        return self._META

    def create_server(self, items: DatasetInput, **config: Any) -> ECDHOPRFFilterServer:
        return ECDHOPRFFilterServer(items, **config)

    def create_client(self, public_params: PublicParams, **config: Any) -> ECDHOPRFFilterClient:
        return ECDHOPRFFilterClient(public_params)
