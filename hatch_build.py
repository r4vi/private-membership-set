"""Hatchling build hook compiling all available constant-time native backends (OpenSSL & AWS-LC)."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


def _find_awslc_prefix() -> Path | None:
    env_prefix = os.environ.get("AWSLC_PREFIX")
    candidates = [
        Path(env_prefix) if env_prefix else None,
        Path.home() / ".local" / "share" / "pmset-tools" / "aws-lc",
        Path("/opt/aws-lc"),
        Path("/usr/local/aws-lc"),
        Path("/usr/local"),
    ]
    for prefix in candidates:
        if prefix is None:
            continue
        marker = prefix / "include" / "openssl" / "is_awslc.h"
        if marker.is_file() and (
            (prefix / "lib" / "libcrypto.a").is_file()
            or (prefix / "lib64" / "libcrypto.a").is_file()
        ):
            return prefix
    return None


class CustomBuildHook(BuildHookInterface):
    """Compiles OpenSSL and (when present) AWS-LC constant-time shared libraries."""

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        root = Path(self.root)
        ndir = root / "src" / "pmset" / "_native"
        common = ndir / "pmset_ct_common.c"
        compiler = os.environ.get("CC") or shutil.which("gcc") or shutil.which("clang")
        if not compiler or not common.is_file():
            return

        sys_name = platform.system()
        ext = ".dylib" if sys_name == "Darwin" else ".dll" if sys_name == "Windows" else ".so"
        force_include = build_data.setdefault("force_include", {})

        # 1. Build OpenSSL backend
        ossl_src = ndir / "pmset_ct_openssl.c"
        ossl_out = ndir / f"libpmset_ct_openssl{ext}"
        if ossl_src.is_file():
            cmd = [
                compiler, "-O2", "-std=c11", "-Wall", "-Wextra",
                "-fPIC", "-fvisibility=hidden", "-shared",
                str(common), str(ossl_src), "-o", str(ossl_out), "-lcrypto",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode == 0 and ossl_out.is_file():
                force_include[str(ossl_out)] = f"pmset/_native/{ossl_out.name}"

        # 2. Build AWS-LC backend (statically linked & symbol-isolated) when AWS-LC is present
        awslc_src = ndir / "pmset_ct_awslc.c"
        awslc_out = ndir / f"libpmset_ct_awslc{ext}"
        prefix = _find_awslc_prefix()
        if awslc_src.is_file() and prefix is not None:
            lib_a = (
                prefix / "lib" / "libcrypto.a"
                if (prefix / "lib" / "libcrypto.a").is_file()
                else prefix / "lib64" / "libcrypto.a"
            )
            cmd = [
                compiler, "-O2", "-std=c11", "-Wall", "-Wextra",
                "-fPIC", "-fvisibility=hidden", "-shared",
                f"-I{prefix / 'include'}",
                str(common), str(awslc_src), str(lib_a), "-lpthread",
                "-o", str(awslc_out),
            ]
            if sys_name == "Linux":
                cmd.extend(["-Wl,-Bsymbolic", "-Wl,--exclude-libs,ALL"])
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode == 0 and awslc_out.is_file():
                force_include[str(awslc_out)] = f"pmset/_native/{awslc_out.name}"
