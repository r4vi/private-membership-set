"""Command-line interface for the canonical ``pmset`` library."""

from __future__ import annotations

import argparse
import sys

import pmset
from pmset.benchmarks import benchmark_protocols, format_benchmark_table
from pmset.verification import verify_all_protocols, verify_protocol


def _cmd_list(_args: argparse.Namespace) -> int:
    print(f"Registered PMSet protocols ({len(pmset.list_protocols())}):\n")
    for meta in pmset.protocol_catalog():
        caps = meta.capabilities
        flags = []
        flags.append(f"{caps.rounds}R")
        if caps.supports_payloads:
            flags.append("payloads")
        if caps.post_quantum_pir:
            flags.append("PQ-PIR")
        if caps.multi_server:
            flags.append(f"{caps.num_servers}-server")
        print(f"  - {meta.name:28s} [{', '.join(flags)}]")
        print(f"      {meta.display_name}")
        print(f"      Assumptions: {', '.join(meta.assumptions)}")
        print(f"      Formal: TLA+={meta.tla_spec}, Lean={meta.lean_theorem}")
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    proto = pmset.get_protocol(args.protocol)
    dataset = {
        "alice@example.com": b"tier=gold",
        "bob@example.com": b"tier=silver",
        "charlie@example.com": b"tier=bronze",
    }
    print(f"Protocol: {proto.metadata.display_name} ({proto.name})")
    server = proto.create_server(dataset)
    client = proto.create_client(server.public_params())
    for q in ("alice@example.com", "eve@example.com", "bob@example.com"):
        res = client.query_detailed(server, q, verify_wire_roundtrip=True)
        stats = res.stats
        extra = f", payload={res.payload!r}" if res.payload is not None else ""
        wire = (
            f" ({stats.rounds} round(s), {stats.bytes_sent}B up / {stats.bytes_received}B down)"
            if stats
            else ""
        )
        print(f"  query({q!r}) -> member={res.is_member}{extra}{wire}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    backends = ["z3", "tla", "lean"] if args.backend == "all" else [args.backend]
    all_ok = True
    if args.protocol:
        reports = verify_protocol(args.protocol, backends=backends)
        for rep in reports.values():
            print(rep.summary())
            for prop in rep.properties:
                mark = "PASS" if prop.passed else "FAIL"
                print(f"    [{mark}] {prop.name} ({prop.category}): {prop.detail}")
            if not rep.all_passed:
                all_ok = False
    else:
        all_reports = verify_all_protocols(backends=backends)
        for proto_name, by_backend in all_reports.items():
            for rep in by_backend.values():
                print(rep.summary())
                if not rep.all_passed:
                    all_ok = False
                    for prop in rep.properties:
                        if not prop.passed:
                            print(f"    [FAIL] {prop.name}: {prop.detail}")
    return 0 if all_ok else 1


def _cmd_benchmark(args: argparse.Namespace) -> int:
    rows = benchmark_protocols(set_size=args.size)
    print(format_benchmark_table(rows))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pmset",
        description="Canonical Python Private Set Membership (PMSet) library CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List all registered PMSet protocols and formal specs")

    p_demo = sub.add_parser("demo", help="Run a live membership query demo")
    p_demo.add_argument(
        "-p", "--protocol", default="oprf_rlwe_pir", help="Protocol name (default: oprf_rlwe_pir)"
    )

    p_ver = sub.add_parser("verify", help="Formally verify protocols in Z3, TLA+, and/or Lean 4")
    p_ver.add_argument("-p", "--protocol", default=None, help="Verify a single protocol (default: all)")
    p_ver.add_argument(
        "-b",
        "--backend",
        choices=["z3", "tla", "lean", "all"],
        default="all",
        help="Formal verification backend (default: all)",
    )

    p_bench = sub.add_parser("benchmark", help="Benchmark latency and bandwidth across all protocols")
    p_bench.add_argument("-n", "--size", type=int, default=16, help="Server set size (default: 16)")

    args = parser.parse_args(argv)
    if args.command == "list":
        return _cmd_list(args)
    if args.command == "demo":
        return _cmd_demo(args)
    if args.command == "verify":
        return _cmd_verify(args)
    if args.command == "benchmark":
        return _cmd_benchmark(args)
    return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
