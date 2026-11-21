"""Unified formal verification orchestration across Z3, TLA+, and Lean 4."""

from __future__ import annotations

from typing import Sequence

from pmset.core.interfaces import PMSetProtocol
from pmset.core.registry import all_protocols, get_protocol
from pmset.verification.base import FormalVerifier, VerificationBackend, VerificationReport
from pmset.verification.lean_verifier import LeanVerifier
from pmset.verification.tla_verifier import TLAVerifier
from pmset.verification.z3_verifier import Z3Verifier


def create_verifier(backend: str | VerificationBackend) -> FormalVerifier:
    b = VerificationBackend(backend) if isinstance(backend, str) else backend
    if b == VerificationBackend.Z3:
        return Z3Verifier()
    if b == VerificationBackend.TLA:
        return TLAVerifier()
    if b == VerificationBackend.LEAN:
        return LeanVerifier()
    raise ValueError(f"Unknown verification backend: {backend!r}")


def verify_protocol(
    protocol: str | PMSetProtocol,
    *,
    backends: Sequence[str | VerificationBackend] = ("z3", "tla", "lean"),
) -> dict[VerificationBackend, VerificationReport]:
    """Formally verify a single concrete PMSet protocol across selected backends."""
    proto = get_protocol(protocol) if isinstance(protocol, str) else protocol
    reports: dict[VerificationBackend, VerificationReport] = {}
    for b in backends:
        verifier = create_verifier(b)
        reports[verifier.backend] = verifier.verify(proto)
    return reports


def verify_all_protocols(
    *,
    backends: Sequence[str | VerificationBackend] = ("z3", "tla", "lean"),
) -> dict[str, dict[VerificationBackend, VerificationReport]]:
    """Formally verify ALL registered PMSet protocols across selected backends."""
    verifiers = [create_verifier(b) for b in backends]
    results: dict[str, dict[VerificationBackend, VerificationReport]] = {}
    for proto in all_protocols():
        results[proto.name] = {v.backend: v.verify(proto) for v in verifiers}
    return results
