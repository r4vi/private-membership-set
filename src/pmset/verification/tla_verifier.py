"""TLA+ / TLC Formal Model Checker runner for PMSet protocol specifications."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
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
        if (parent / "verification" / "tla").is_dir():
            return parent
    return Path.cwd()


def _find_tla_dir() -> Path:
    repo_tla = _find_repo_root() / "verification" / "tla"
    if repo_tla.is_dir():
        return repo_tla
    bundled_tla = Path(__file__).resolve().parent.parent / "_verification_assets" / "tla"
    if bundled_tla.is_dir():
        return bundled_tla
    return repo_tla


def find_tla2tools_jar() -> Path | None:
    """Locate ``tla2tools.jar`` via env var or standard local paths."""
    env_path = os.environ.get("TLA2TOOLS_JAR")
    candidates = [
        Path(env_path) if env_path else None,
        Path.home() / ".local" / "share" / "pmset-tools" / "tla2tools.jar",
        _find_repo_root() / "tools" / "tla2tools.jar",
        Path("/usr/local/share/tla2tools.jar"),
        Path("/opt/tla/tla2tools.jar"),
    ]
    for path in candidates:
        if path is not None and path.is_file():
            return path
    return None


class TLAVerifier(FormalVerifier):
    """Runs the TLA+ TLC model checker on each protocol's formal state-machine spec."""

    def __init__(
        self,
        tla_dir: Path | None = None,
        tla2tools_jar: Path | None = None,
    ) -> None:
        self._tla_dir = tla_dir or _find_tla_dir()
        self._jar = tla2tools_jar or find_tla2tools_jar()
        self._spec_cache: dict[str, PropertyResult] = {}

    @property
    def backend(self) -> VerificationBackend:
        return VerificationBackend.TLA

    def is_available(self) -> bool:
        return (
            shutil.which("java") is not None
            and self._jar is not None
            and self._jar.is_file()
            and self._tla_dir.is_dir()
        )

    def run_spec(self, spec_filename: str, *, use_cache: bool = True) -> PropertyResult:
        """Execute TLC on a single ``*.tla`` specification and parse its result."""
        if use_cache and spec_filename in self._spec_cache:
            return self._spec_cache[spec_filename]
        t0 = time.perf_counter()
        spec_path = self._tla_dir / spec_filename
        cfg_path = spec_path.with_suffix(".cfg")
        if not spec_path.is_file() or not cfg_path.is_file():
            return PropertyResult(
                name=f"tla:{spec_filename}",
                category="state_machine",
                status=PropertyStatus.FAILED,
                detail=f"Missing TLA+ spec or cfg: {spec_path}",
                backend=self.backend,
            )

        assert self._jar is not None
        with tempfile.TemporaryDirectory(prefix="pmset-tlc-") as metadir:
            cmd = [
                "java",
                "-XX:+UseParallelGC",
                "-cp",
                str(self._jar),
                "tlc2.TLC",
                "-cleanup",
                "-metadir",
                metadir,
                "-workers",
                "2",
                "-config",
                str(cfg_path),
                str(spec_path),
            ]
            proc = subprocess.run(
                cmd,
                cwd=str(self._tla_dir),
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

        elapsed = (time.perf_counter() - t0) * 1000.0
        output = proc.stdout + "\n" + proc.stderr
        states_match = re.search(
            r"(\d+) states generated, (\d+) distinct states found", output
        )
        states_info = (
            f"{states_match.group(1)} states generated, {states_match.group(2)} distinct"
            if states_match
            else "completed"
        )
        ok = (
            proc.returncode == 0
            and "Model checking completed. No error has been found." in output
        )
        if ok:
            res = PropertyResult(
                name=f"tla:{spec_filename}",
                category="state_machine",
                status=PropertyStatus.PROVED,
                detail=f"TLC verified with 0 errors ({states_info})",
                backend=self.backend,
                duration_ms=elapsed,
            )
        else:
            res = PropertyResult(
                name=f"tla:{spec_filename}",
                category="state_machine",
                status=PropertyStatus.FAILED,
                detail=f"TLC failed (exit {proc.returncode}): {output[-400:].strip()}",
                backend=self.backend,
                duration_ms=elapsed,
            )
        self._spec_cache[spec_filename] = res
        return res

    def verify(self, protocol: PMSetProtocol) -> VerificationReport:
        if not self.is_available():
            return VerificationReport(
                protocol=protocol.name,
                backend=self.backend,
                properties=(
                    PropertyResult(
                        name="tla_available",
                        category="toolchain",
                        status=PropertyStatus.UNAVAILABLE,
                        detail="Java or tla2tools.jar not found",
                        backend=self.backend,
                    ),
                ),
            )

        t0 = time.perf_counter()
        specs = ["PMSetGeneric.tla"]
        if protocol.metadata.tla_spec and protocol.metadata.tla_spec not in specs:
            specs.append(protocol.metadata.tla_spec)
        results = tuple(self.run_spec(s) for s in specs)
        return VerificationReport(
            protocol=protocol.name,
            backend=self.backend,
            properties=results,
            duration_ms=(time.perf_counter() - t0) * 1000.0,
        )
