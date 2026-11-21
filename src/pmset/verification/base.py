"""Generic formal verification interfaces and reporting models for pmset."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

from pmset.core.interfaces import PMSetProtocol


class VerificationBackend(str, Enum):
    """Supported formal verification backends."""

    Z3 = "z3"
    TLA = "tla"
    LEAN = "lean"


class PropertyStatus(str, Enum):
    """Result of verifying a single formal property."""

    PROVED = "proved"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class PropertyResult:
    """Outcome of a single formal check/theorem/invariant."""

    name: str
    category: str  # e.g. "correctness", "client_privacy", "server_privacy", "safety", "noise_bound"
    status: PropertyStatus
    detail: str
    backend: VerificationBackend
    duration_ms: float = 0.0

    @property
    def passed(self) -> bool:
        return self.status == PropertyStatus.PROVED


@dataclass(frozen=True)
class VerificationReport:
    """Aggregated formal verification report for a protocol on one backend."""

    protocol: str
    backend: VerificationBackend
    properties: tuple[PropertyResult, ...]
    duration_ms: float = 0.0

    @property
    def all_passed(self) -> bool:
        return len(self.properties) > 0 and all(p.passed for p in self.properties)

    def summary(self) -> str:
        passed = sum(1 for p in self.properties if p.passed)
        total = len(self.properties)
        status = "VERIFIED" if self.all_passed else "FAILED"
        return (
            f"[{self.backend.value.upper()}] {self.protocol}: {status} "
            f"({passed}/{total} properties proved in {self.duration_ms:.1f} ms)"
        )


class FormalVerifier(ABC):
    """Generic interface for a formal verification backend (Z3 / TLA+ / Lean 4)."""

    @property
    @abstractmethod
    def backend(self) -> VerificationBackend:
        """Backend identifier."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True iff the underlying solver/prover toolchain is installed."""

    @abstractmethod
    def verify(self, protocol: PMSetProtocol) -> VerificationReport:
        """Formally verify ``protocol`` and return a structured report."""
