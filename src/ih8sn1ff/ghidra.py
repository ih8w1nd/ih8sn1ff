"""Ghidra headless orchestration (import, decompile, function listing).

Requires ``GHIDRA_INSTALL_DIR`` pointing at an extracted Ghidra release.
The bundled Java postScripts live in ``ih8sn1ff/scripts/ghidra`` and are passed
via ``-scriptPath``.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .util import OmniError, parse_int

DEFAULT_TIMEOUT_MIN = 30


def _headless() -> str:
    root = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    if not root:
        raise OmniError("GHIDRA_INSTALL_DIR is not set (point it at an extracted Ghidra)")
    base = Path(root)
    for candidate in (
        base / "support" / "analyzeHeadless.bat",
        base / "support" / "analyzeHeadless",
    ):
        if candidate.is_file():
            return str(candidate)
    raise OmniError(f"analyzeHeadless not found under {base}")


def _script_dir() -> str:
    return str(Path(__file__).parent / "scripts" / "ghidra")


def _split_project(project: str) -> tuple[str, str]:
    p = Path(project)
    if p.suffix == ".gpr":
        return str(p.parent), p.stem
    name = p.name or "ih8sn1ff_project"
    return str(p), name


def _run(cmd: list[str], timeout_min: float) -> dict:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(30.0, timeout_min * 60.0),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise OmniError(f"Ghidra headless timed out after {timeout_min} min") from exc
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def ghidra_import(
    binary: str,
    project: str,
    analysis: str = "full",
    timeout_min: float = DEFAULT_TIMEOUT_MIN,
) -> dict:
    """Import a binary into a Ghidra project (optionally skipping analysis).

    The project is kept: import and later decompile runs share it. If a
    program with the same name already exists Ghidra appends a suffix, so
    re-importing never destroys earlier state.
    """
    if analysis not in {"full", "none"}:
        raise OmniError("analysis must be 'full' or 'none'")
    if not Path(binary).is_file():
        raise OmniError(f"binary not found: {binary}")
    proj_dir, proj_name = _split_project(project)
    Path(proj_dir).mkdir(parents=True, exist_ok=True)
    cmd = [
        _headless(),
        proj_dir,
        proj_name,
        "-import",
        str(Path(binary).resolve()),
        "-scriptPath",
        _script_dir(),
    ]
    if analysis == "none":
        cmd.append("-noanalysis")
    result = _run(cmd, timeout_min)
    result.update({"project": project, "binary": str(binary), "analysis": analysis})
    return result


def _post_script(project: str, script: str, args: list[str], timeout_min: float,
                 program: str | None) -> dict:
    proj_dir, proj_name = _split_project(project)
    cmd = [
        _headless(),
        proj_dir,
        proj_name,
        "-process",
        program or "*",
        "-noanalysis",
        "-scriptPath",
        _script_dir(),
        "-postScript",
        script,
        *args,
    ]
    return _run(cmd, timeout_min)


def ghidra_decompile(
    project: str,
    program: str | None = None,
    rvas: list[int | str] | None = None,
    keywords: list[str] | None = None,
    limit: int = 40,
    timeout_min: float = DEFAULT_TIMEOUT_MIN,
) -> dict:
    """Decompile functions by RVA list and/or string keywords."""
    if not rvas and not keywords:
        raise OmniError("provide rvas=[...] and/or keywords=[...]")
    outputs: list[dict] = []
    if rvas:
        args = [hex(parse_int(rva)) for rva in rvas]
        outputs.append(
            {
                "script": "DecompileTargets.java",
                "result": _post_script(
                    project, "DecompileTargets.java", args, timeout_min, program
                ),
            }
        )
    if keywords:
        outputs.append(
            {
                "script": "DecompileByStrings.java",
                "result": _post_script(
                    project,
                    "DecompileByStrings.java",
                    [*keywords, str(limit)],
                    timeout_min,
                    program,
                ),
            }
        )
    return {"project": project, "program": program or "*", "runs": outputs}


def ghidra_funcs(
    project: str,
    program: str | None = None,
    limit: int = 20000,
    timeout_min: float = DEFAULT_TIMEOUT_MIN,
) -> dict:
    """List analyzed functions from a project."""
    result = _post_script(
        project, "ListFunctions.java", [str(limit)], timeout_min, program
    )
    return {"project": project, "program": program or "*", "result": result}
