"""Hatchling build hook that compiles the constant-time native C backend (libpmset_ct)."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    """Compiles ``src/pmset/_native/pmset_ct.c`` into a shared library during packaging."""

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        root = Path(self.root)
        ndir = root / "src" / "pmset" / "_native"
        src = ndir / "pmset_ct.c"
        sys_name = platform.system()
        lib_name = (
            "libpmset_ct.dylib"
            if sys_name == "Darwin"
            else "pmset_ct.dll"
            if sys_name == "Windows"
            else "libpmset_ct.so"
        )
        out = ndir / lib_name
        compiler = os.environ.get("CC") or shutil.which("gcc") or shutil.which("clang")
        if not compiler or not src.is_file():
            return

        cmd = [
            compiler,
            "-O2",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-fPIC",
            "-shared",
            str(src),
            "-o",
            str(out),
            "-lcrypto",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode == 0 and out.is_file():
            build_data.setdefault("force_include", {})[str(out)] = f"pmset/_native/{lib_name}"
