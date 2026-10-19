"""ilspycmd wrappers for managed assemblies."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .util import OmniError

TYPE_FILTER = "c,i,s,d,e"  # classes, interfaces, structs, delegates, enums


def _ilspycmd() -> str:
    found = shutil.which("ilspycmd")
    if found:
        return found
    suffix = ".exe" if os.name == "nt" else ""
    candidate = Path.home() / ".dotnet" / "tools" / f"ilspycmd{suffix}"
    if candidate.is_file():
        return str(candidate)
    raise OmniError(
        "ilspycmd not found — install with: dotnet tool install -g ilspycmd"
    )


def _run(cmd: list[str], timeout_s: float = 300.0) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise OmniError("ilspycmd timed out") from exc
    if proc.returncode != 0:
        raise OmniError(f"ilspycmd failed: {proc.stderr.strip()[:400]}")
    return proc


def dotnet_types(asm: str, pattern: str | None = None, limit: int = 5000) -> dict:
    """List types (and filter by substring) in a managed assembly."""
    if not Path(asm).is_file():
        raise OmniError(f"assembly not found: {asm}")
    proc = _run([_ilspycmd(), "-l", TYPE_FILTER, asm])
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if pattern:
        lowered = pattern.casefold()
        lines = [line for line in lines if lowered in line.casefold()]
    return {
        "assembly": asm,
        "total": len(lines),
        "types": lines[:limit],
        "truncated": len(lines) > limit,
    }


def dotnet_type(asm: str, type_name: str) -> dict:
    """Decompile a single type to C#."""
    if not Path(asm).is_file():
        raise OmniError(f"assembly not found: {asm}")
    proc = _run([_ilspycmd(), "-t", type_name, asm])
    return {"assembly": asm, "type": type_name, "code": proc.stdout}
