"""Generic, protocol-agnostic interfaces for Private Set Membership (PMSet).

Every concrete PMSet technique — whether 1-round homomorphic polynomial evaluation,
2-round OPRF + PIR, OT + Garbled Bloom Filter, RLWE lattice PIR, or k-server
information-theoretic / FSS PIR — implements the exact same three abstractions:

  1. :class:`PMSetServer`: holds the preprocessed private set and handles
     stateless :class:`ProtocolMessage` requests.
  2. :class:`PMSetClient` + :class:`PMSetSession`: drives the client-side
     state machine over any transport (in-process, HTTP, gRPC, sockets).
  3. :class:`PMSetProtocol`: factory + metadata + formal-verification descriptor
     binding a server and client implementation together.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Sequence

from pmset.core.types import (
    BatchQueryResult,
    DatasetInput,
    Item,
    ProtocolMessage,
    ProtocolMetadata,
    PublicParams,
    QueryResult,
)


class PMSetSession(ABC):
    """Stateful client-side session for a single membership query.

    Sessions are transport-agnostic: a caller loops ``next_request()`` ->
    send to server -> ``process_response(resp)`` until ``is_complete`` is True,
    then reads ``result()``.
    """

    @property
    @abstractmethod
    def is_complete(self) -> bool:
        """Whether the protocol has finished and :meth:`result` is ready."""

    @abstractmethod
    def next_request(self) -> ProtocolMessage:
        """Produce the next outbound :class:`ProtocolMessage` for the server(s)."""

    @abstractmethod
    def process_response(self, response: ProtocolMessage) -> None:
        """Ingest the server response corresponding to the last request."""

    @abstractmethod
    def result(self) -> QueryResult:
        """Return the final membership decision (and optional payload)."""


class PMSetServer(ABC):
    """Server holding a private set (or key->payload mapping).

    **Stateless-Server Contract**: :meth:`handle_request` MUST NOT mutate any
    per-client state on the server. Interleaved or concurrent queries from
    arbitrary clients must produce identical results.
    """

    @property
    @abstractmethod
    def protocol_name(self) -> str:
        """Canonical protocol identifier."""

    @abstractmethod
    def public_params(self) -> PublicParams:
        """Return the public parameters needed to configure a matching client."""

    @abstractmethod
    def handle_request(self, request: ProtocolMessage) -> ProtocolMessage:
        """Process a single client protocol message without storing client state."""

    @property
    @abstractmethod
    def item_count(self) -> int:
        """Number of distinct items indexed on the server."""


class PMSetServerReplica(ABC):
    """An individual non-colluding server replica in a multi-server PMSet scheme."""

    @property
    @abstractmethod
    def replica_id(self) -> int:
        """Zero-based index of this server replica."""

    @abstractmethod
    def handle_replica_request(self, phase: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Process a request directed solely to this replica."""


class MultiServerPMSetServer(PMSetServer):
    """Coordinator wrapper around ``k >= 2`` strictly isolated server replicas.

    Each replica in :attr:`replicas` holds only its own secret/state and only
    ever sees its own entry from ``request.replica_payloads[replica_id]``.
    """

    @property
    @abstractmethod
    def replicas(self) -> tuple[PMSetServerReplica, ...]:
        """The independent non-colluding server replicas."""

    def handle_request(self, request: ProtocolMessage) -> ProtocolMessage:
        if request.protocol != self.protocol_name:
            raise ValueError(
                f"Protocol mismatch: server expects '{self.protocol_name}', got '{request.protocol}'"
            )
        if request.replica_payloads is None:
            raise ValueError(
                f"Multi-server protocol '{self.protocol_name}' requires replica_payloads"
            )
        responses: dict[int, dict[str, Any]] = {}
        for replica in self.replicas:
            rid = replica.replica_id
            if rid in request.replica_payloads:
                responses[rid] = replica.handle_replica_request(
                    request.phase, request.replica_payloads[rid]
                )
        return ProtocolMessage(
            protocol=self.protocol_name,
            phase=f"{request.phase}_response",
            round_num=request.round_num,
            replica_payloads=responses,
        )


class PMSetClient(ABC):
    """Client capable of privately querying a compatible :class:`PMSetServer`."""

    @property
    @abstractmethod
    def protocol_name(self) -> str:
        """Canonical protocol identifier."""

    @abstractmethod
    def start_query(self, item: Item) -> PMSetSession:
        """Start an interactive transport-agnostic query session for ``item``."""

    def query_detailed(
        self,
        server: PMSetServer,
        item: Item,
        *,
        verify_wire_roundtrip: bool = False,
    ) -> QueryResult:
        """Execute a full membership query against ``server`` and return full details."""
        from pmset.core.runner import execute_query

        return execute_query(self, server, item, verify_wire_roundtrip=verify_wire_roundtrip)

    def query(self, server: PMSetServer, item: Item) -> bool:
        """Execute a membership query and return ``True`` iff ``item`` is in the server set."""
        return self.query_detailed(server, item).is_member

    def query_batch(
        self,
        server: PMSetServer,
        items: Sequence[Item],
        *,
        verify_wire_roundtrip: bool = False,
    ) -> BatchQueryResult:
        """Execute a batch of membership queries against ``server``."""
        from pmset.core.runner import execute_batch_query

        return execute_batch_query(
            self, server, items, verify_wire_roundtrip=verify_wire_roundtrip
        )


class PMSetProtocol(ABC):
    """Factory and specification descriptor for a concrete PMSet algorithm."""

    @property
    @abstractmethod
    def metadata(self) -> ProtocolMetadata:
        """Return static metadata, security model, capabilities, and verification links."""

    @property
    def name(self) -> str:
        return self.metadata.name

    @abstractmethod
    def create_server(self, items: DatasetInput, **config: Any) -> PMSetServer:
        """Construct and preprocess a server instance for ``items``."""

    @abstractmethod
    def create_client(self, public_params: PublicParams, **config: Any) -> PMSetClient:
        """Construct a client instance configured from server ``public_params``."""
