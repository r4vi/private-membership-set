"""Core data types and metadata models for Private Set Membership (PMSet) protocols."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence, Union

from pmset.core.serialization import decode_value, encode_value

Item = Union[str, bytes]
DatasetInput = Union[Sequence[Item], Mapping[Item, bytes]]


def normalize_item(item: Item) -> bytes:
    """Convert a string or bytes item into its canonical UTF-8 byte representation."""
    if isinstance(item, bytes):
        return item
    if isinstance(item, str):
        return item.encode("utf-8")
    raise TypeError(f"PMSet items must be str or bytes, got {type(item).__name__}")


def normalize_dataset(items: DatasetInput) -> dict[bytes, bytes | None]:
    """Normalize a collection of items or item->payload mapping into canonical form."""
    if isinstance(items, Mapping):
        out: dict[bytes, bytes | None] = {}
        for k, v in items.items():
            if not isinstance(v, (bytes, bytearray)):
                raise TypeError(f"Payload values must be bytes, got {type(v).__name__}")
            out[normalize_item(k)] = bytes(v)
        return out
    return {normalize_item(x): None for x in items}


class SecurityModel(str, Enum):
    """Cryptographic security model of a PMSet protocol."""

    SEMI_HONEST_COMPUTATIONAL = "semi-honest-computational"
    SEMI_HONEST_POST_QUANTUM = "semi-honest-post-quantum"
    SEMI_HONEST_INFORMATION_THEORETIC = "semi-honest-information-theoretic"
    SEMI_HONEST_MULTI_SERVER_FSS = "semi-honest-multi-server-fss"


@dataclass(frozen=True)
class ProtocolCapabilities:
    """Declares what optional features a PMSet protocol supports."""

    supports_payloads: bool = False
    supports_batch: bool = True
    false_positive_free: bool = True
    false_negative_free: bool = True
    multi_server: bool = False
    num_servers: int = 1
    post_quantum_pir: bool = False
    rounds: int = 1


@dataclass(frozen=True)
class ComplexityProfile:
    """Asymptotic communication and computation profile for N items and B buckets."""

    rounds: int
    client_upload: str
    server_download: str
    server_compute: str
    client_compute: str


@dataclass(frozen=True)
class ProtocolMetadata:
    """Structured metadata describing a concrete PMSet implementation."""

    name: str
    display_name: str
    family: str
    description: str
    assumptions: tuple[str, ...]
    security_model: SecurityModel
    capabilities: ProtocolCapabilities
    complexity: ComplexityProfile
    references: tuple[str, ...] = ()
    tla_spec: str | None = None
    lean_theorem: str | None = None


@dataclass(frozen=True)
class PublicParams:
    """Public protocol parameters advertised by a server and consumed by clients."""

    protocol: str
    params: dict[str, Any] = field(default_factory=dict)

    def to_bytes(self) -> bytes:
        return encode_value({"protocol": self.protocol, "params": self.params})

    @classmethod
    def from_bytes(cls, data: bytes) -> PublicParams:
        decoded = decode_value(data)
        if not isinstance(decoded, dict) or "protocol" not in decoded or "params" not in decoded:
            raise ValueError("Invalid PublicParams wire payload")
        return cls(protocol=decoded["protocol"], params=decoded["params"])


@dataclass(frozen=True)
class ProtocolMessage:
    """A single serializable protocol message exchanged between client and server(s).

    For single-server protocols, ``replica_payloads`` is ``None`` and ``payload``
    holds the message body.
    For multi-server protocols, ``replica_payloads`` maps each non-colluding
    server index ``i`` to the strictly isolated message meant ONLY for replica ``i``.
    """

    protocol: str
    phase: str
    round_num: int
    payload: dict[str, Any] = field(default_factory=dict)
    replica_payloads: dict[int, dict[str, Any]] | None = None

    def to_bytes(self) -> bytes:
        rep = (
            {str(k): v for k, v in self.replica_payloads.items()}
            if self.replica_payloads is not None
            else None
        )
        return encode_value(
            {
                "protocol": self.protocol,
                "phase": self.phase,
                "round_num": self.round_num,
                "payload": self.payload,
                "replica_payloads": rep,
            }
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> ProtocolMessage:
        decoded = decode_value(data)
        if not isinstance(decoded, dict):
            raise ValueError("Invalid ProtocolMessage wire payload")
        rep_raw = decoded.get("replica_payloads")
        rep = {int(k): v for k, v in rep_raw.items()} if rep_raw is not None else None
        return cls(
            protocol=decoded["protocol"],
            phase=decoded["phase"],
            round_num=decoded["round_num"],
            payload=decoded["payload"],
            replica_payloads=rep,
        )


@dataclass(frozen=True)
class CommunicationStats:
    """Measured communication costs for a protocol execution."""

    rounds: int
    bytes_sent: int
    bytes_received: int

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received


@dataclass(frozen=True)
class QueryResult:
    """Outcome of a single private set membership query."""

    is_member: bool
    payload: bytes | None = None
    stats: CommunicationStats | None = None
    protocol: str | None = None


@dataclass(frozen=True)
class BatchQueryResult:
    """Outcome of a batch of private set membership queries."""

    results: tuple[QueryResult, ...]
    stats: CommunicationStats | None = None

    @property
    def memberships(self) -> list[bool]:
        return [r.is_member for r in self.results]
