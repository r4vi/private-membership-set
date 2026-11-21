"""Lean 4 Formal Proof Verifier runner for PMSet theorems."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from pmset.core.interfaces import PMSetProtocol
from pmset.verification.base import (
    FormalVerifier,
    PropertyResult,
    PropertyStatus,
    VerificationBackend,
    VerificationReport,
)


def _find_repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "verification" / "lean").is_dir():
            return parent
    return Path.cwd()


def find_lake_binary() -> Path | None:
    """Locate the Lean 4 ``lake`` executable on PATH or under ``~/.elan/bin``."""
    on_path = shutil.which("lake")
    if on_path:
        return Path(on_path)
    elan_lake = Path.home() / ".elan" / "bin" / "lake"
    if elan_lake.is_file():
        return elan_lake
    return None


class LeanVerifier(FormalVerifier):
    """Builds the Lean 4 verification library and checks theorem presence + zero sorry."""

    def __init__(self, lean_dir: Path | None = None) -> None:
        self._lean_dir = lean_dir or (_find_repo_root() / "verification" / "lean")
        self._lake = find_lake_binary()
        self._build_checked = False
        self._build_ok = False
        self._build_detail = ""
        self._build_ms = 0.0

    @property
    def backend(self) -> VerificationBackend:
        return VerificationBackend.LEAN

    def is_available(self) -> bool:
        return self._lake is not None and self._lean_dir.is_dir()

    def _ensure_built(self) -> PropertyResult:
        if not self._build_checked:
            assert self._lake is not None
            t0 = time.perf_counter()
            env = os.environ.copy()
            elan_bin = str(Path.home() / ".elan" / "bin")
            if elan_bin not in env.get("PATH", ""):
                env["PATH"] = f"{elan_bin}:{env.get('PATH', '')}"
            proc = subprocess.run(
                [str(self._lake), "build"],
                cwd=str(self._lean_dir),
                env=env,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            self._build_ms = (time.perf_counter() - t0) * 1000.0
            self._build_checked = True
            self._build_ok = proc.returncode == 0
            out = (proc.stdout + "\n" + proc.stderr).strip()
            self._build_detail = (
                "Lean 4 kernel verified entire PMSet library (`lake build` exit 0)"
                if self._build_ok
                else f"`lake build` failed (exit {proc.returncode}): {out[-400:]}"
            )
        return PropertyResult(
            name="lean:lake_build",
            category="kernel_proof",
            status=PropertyStatus.PROVED if self._build_ok else PropertyStatus.FAILED,
            detail=self._build_detail,
            backend=self.backend,
            duration_ms=self._build_ms,
        )

    def _check_no_sorry_or_axioms(self) -> PropertyResult:
        t0 = time.perf_counter()
        violations: list[str] = []
        for lean_file in sorted(self._lean_dir.rglob("*.lean")):
            if ".lake" in lean_file.parts:
                continue
            text = lean_file.read_text(encoding="utf-8")
            # Strip block and line comments before scanning
            cleaned = re.sub(r"/-.*?-/", "", text, flags=re.DOTALL)
            cleaned = re.sub(r"--.*", "", cleaned)
            if re.search(r"\bsorry\b", cleaned):
                violations.append(f"{lean_file.name}: contains `sorry`")
            if re.search(r"^\s*axiom\b", cleaned, flags=re.MULTILINE):
                violations.append(f"{lean_file.name}: declares custom `axiom`")
        elapsed = (time.perf_counter() - t0) * 1000.0
        if not violations:
            return PropertyResult(
                name="lean:zero_sorry_zero_axioms",
                category="soundness",
                status=PropertyStatus.PROVED,
                detail="All Lean 4 proofs are complete (0 `sorry`, 0 custom `axiom`)",
                backend=self.backend,
                duration_ms=elapsed,
            )
        return PropertyResult(
            name="lean:zero_sorry_zero_axioms",
            category="soundness",
            status=PropertyStatus.FAILED,
            detail="; ".join(violations),
            backend=self.backend,
            duration_ms=elapsed,
        )

    def _check_protocol_theorem(self, protocol: PMSetProtocol) -> PropertyResult:
        t0 = time.perf_counter()
        thm_fqn = protocol.metadata.lean_theorem
        if not thm_fqn:
            return PropertyResult(
                name=f"lean:{protocol.name}",
                category="correctness",
                status=PropertyStatus.SKIPPED,
                detail="Protocol metadata declares no Lean theorem",
                backend=self.backend,
            )
        thm_short = thm_fqn.split(".")[-1]
        protocols_file = self._lean_dir / "PMSet" / "Protocols.lean"
        text = protocols_file.read_text(encoding="utf-8") if protocols_file.is_file() else ""
        found = bool(re.search(rf"\btheorem\s+{re.escape(thm_short)}\b", text))
        elapsed = (time.perf_counter() - t0) * 1000.0
        if found and self._build_ok:
            return PropertyResult(
                name=f"lean:{thm_fqn}",
                category="correctness",
                status=PropertyStatus.PROVED,
                detail=f"Kernel-verified theorem `{thm_fqn}` in PMSet/Protocols.lean",
                backend=self.backend,
                duration_ms=elapsed,
            )
        return PropertyResult(
            name=f"lean:{thm_fqn}",
            category="correctness",
            status=PropertyStatus.FAILED,
            detail=f"Theorem `{thm_fqn}` not found or build failed",
            backend=self.backend,
            duration_ms=elapsed,
        )

    def verify(self, protocol: PMSetProtocol) -> VerificationReport:
        if not self.is_available():
            return VerificationReport(
                protocol=protocol.name,
                backend=self.backend,
                properties=(
                    PropertyResult(
                        name="lean_available",
                        category="toolchain",
                        status=PropertyStatus.UNAVAILABLE,
                        detail="Lean 4 (`lake`) toolchain not found",
                        backend=self.backend,
                    ),
                ),
            )
        t0 = time.perf_counter()
        build_res = self._ensure_built()
        audit_res = self._check_no_sorry_or_axioms()
        thm_res = self._check_protocol_theorem(protocol)
        return VerificationReport(
            protocol=protocol.name,
            backend=self.backend,
            properties=(build_res, audit_res, thm_res),
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )
