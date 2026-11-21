"""Head-to-head benchmark suite across all concrete PMSet protocol implementations."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Sequence

from pmset.core.registry import all_protocols, get_protocol
from pmset.core.runner import execute_query


@dataclass(frozen=True)
class BenchmarkRow:
    """Measured performance and wire cost for a single PMSet protocol."""

    protocol: str
    family: str
    rounds: int
    setup_ms: float
    query_ms: float
    bytes_sent: int
    bytes_received: int
    supports_payloads: bool
    multi_server: bool

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received


def benchmark_protocols(
    *,
    set_size: int = 16,
    protocols: Sequence[str] | None = None,
) -> list[BenchmarkRow]:
    """Benchmark setup time, single-query latency, and exact wire bandwidth."""
    items = [f"user-{i}@example.com" for i in range(set_size)]
    query_member = items[0] if items else "nobody@example.com"
    query_absent = "absent@example.com"

    selected = [get_protocol(n) for n in protocols] if protocols else all_protocols()
    rows: list[BenchmarkRow] = []

    for proto in selected:
        t0 = time.perf_counter()
        server = proto.create_server(items)
        setup_ms = (time.perf_counter() - t0) * 1000.0

        params = server.public_params()
        client = proto.create_client(params)

        t1 = time.perf_counter()
        res_in = execute_query(client, server, query_member, verify_wire_roundtrip=True)
        res_out = execute_query(client, server, query_absent, verify_wire_roundtrip=True)
        query_ms = ((time.perf_counter() - t1) * 1000.0) / 2.0

        assert res_in.is_member is (set_size > 0)
        assert res_out.is_member is False
        assert res_in.stats is not None

        rows.append(
            BenchmarkRow(
                protocol=proto.name,
                family=proto.metadata.family,
                rounds=res_in.stats.rounds,
                setup_ms=setup_ms,
                query_ms=query_ms,
                bytes_sent=res_in.stats.bytes_sent,
                bytes_received=res_in.stats.bytes_received,
                supports_payloads=proto.metadata.capabilities.supports_payloads,
                multi_server=proto.metadata.capabilities.multi_server,
            )
        )
    return rows


def format_benchmark_table(rows: Sequence[BenchmarkRow]) -> str:
    """Format benchmark rows as an aligned Markdown table."""
    header = (
        "| Protocol | Rounds | Setup (ms) | Query (ms) | Upload (B) | Download (B) | Payloads |\n"
        "|---|---:|---:|---:|---:|---:|:---:|"
    )
    lines = [header]
    for r in rows:
        lines.append(
            f"| `{r.protocol}` | {r.rounds} | {r.setup_ms:.1f} | {r.query_ms:.1f} "
            f"| {r.bytes_sent:,} | {r.bytes_received:,} | {'yes' if r.supports_payloads else 'no'} |"
        )
    return "\n".join(lines)
