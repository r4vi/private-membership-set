"""Transport-agnostic execution driver and transcript recorder for PMSet protocols."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from pmset.core.interfaces import PMSetClient, PMSetServer
from pmset.core.types import (
    BatchQueryResult,
    CommunicationStats,
    Item,
    ProtocolMessage,
    QueryResult,
)


@dataclass(frozen=True)
class TranscriptEntry:
    """Single round-trip recorded on the wire between client and server(s)."""

    round_num: int
    phase: str
    request_bytes: bytes
    response_bytes: bytes


@dataclass
class TranscriptRecorder:
    """Captures exact wire bytes exchanged during protocol execution."""

    entries: list[TranscriptEntry] = field(default_factory=list)

    @property
    def bytes_sent(self) -> int:
        return sum(len(e.request_bytes) for e in self.entries)

    @property
    def bytes_received(self) -> int:
        return sum(len(e.response_bytes) for e in self.entries)

    @property
    def rounds(self) -> int:
        return len(self.entries)


def execute_query(
    client: PMSetClient,
    server: PMSetServer,
    item: Item,
    *,
    verify_wire_roundtrip: bool = False,
    transcript: TranscriptRecorder | None = None,
    max_rounds: int = 32,
) -> QueryResult:
    """Run a complete interactive PMSet query session between ``client`` and ``server``.

    When ``verify_wire_roundtrip=True``, every message is serialized to canonical
    wire bytes and deserialized before delivery to guarantee transport safety.
    """
    if client.protocol_name != server.protocol_name:
        raise ValueError(
            f"Protocol mismatch: client uses '{client.protocol_name}', "
            f"server uses '{server.protocol_name}'"
        )

    session = client.start_query(item)
    rounds = 0
    bytes_sent = 0
    bytes_received = 0

    while not session.is_complete:
        if rounds >= max_rounds:
            raise RuntimeError(
                f"Protocol '{client.protocol_name}' exceeded max_rounds={max_rounds}"
            )
        req = session.next_request()
        req_bytes = req.to_bytes()
        bytes_sent += len(req_bytes)

        wire_req = ProtocolMessage.from_bytes(req_bytes) if verify_wire_roundtrip else req
        resp = server.handle_request(wire_req)
        resp_bytes = resp.to_bytes()
        bytes_received += len(resp_bytes)

        wire_resp = ProtocolMessage.from_bytes(resp_bytes) if verify_wire_roundtrip else resp
        session.process_response(wire_resp)
        rounds += 1

        if transcript is not None:
            transcript.entries.append(
                TranscriptEntry(
                    round_num=rounds,
                    phase=req.phase,
                    request_bytes=req_bytes,
                    response_bytes=resp_bytes,
                )
            )

    raw = session.result()
    stats = CommunicationStats(
        rounds=rounds,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
    )
    return QueryResult(
        is_member=raw.is_member,
        payload=raw.payload,
        stats=stats,
        protocol=client.protocol_name,
    )


def execute_batch_query(
    client: PMSetClient,
    server: PMSetServer,
    items: Sequence[Item],
    *,
    verify_wire_roundtrip: bool = False,
) -> BatchQueryResult:
    """Execute a batch of queries and aggregate communication statistics."""
    results: list[QueryResult] = []
    total_rounds = 0
    total_sent = 0
    total_recv = 0

    for item in items:
        res = execute_query(
            client, server, item, verify_wire_roundtrip=verify_wire_roundtrip
        )
        results.append(res)
        if res.stats is not None:
            total_rounds += res.stats.rounds
            total_sent += res.stats.bytes_sent
            total_recv += res.stats.bytes_received

    return BatchQueryResult(
        results=tuple(results),
        stats=CommunicationStats(
            rounds=total_rounds,
            bytes_sent=total_sent,
            bytes_received=total_recv,
        ),
    )
