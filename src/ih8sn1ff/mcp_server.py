"""ih8Sn1ff MCP server (stdio).

Every capability is a thin wrapper over the same functions the CLI uses, so
behavior is identical across transports. Tool docstrings are the MCP
descriptions an agent sees. Successful calls are journaled by ``evidence``.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import bininfo as _bininfo
from . import blobs as _blobs
from . import debugger as _debugger
from . import delphi as _delphi
from . import disasm as _disasm
from . import dotnet as _dotnet
from . import dumpwin as _dumpwin
from . import emulate as _emulate
from . import evidence as _evidence
from . import flow as _flow
from . import ghidra as _ghidra
from . import imports as _imports
from . import pefix as _pefix
from . import strings_scan as _strings
from . import xrefs as _xrefs
from . import yara_tool as _yara

mcp = FastMCP(
    "ih8sn1ff",
    instructions=(
        "Reverse-engineering toolkit. Packed-target workflow: run_and_dump -> "
        "rebuild_pe -> rebuild_imports -> trim_pe -> strings_scan/delphi_methods -> "
        "ghidra_import/ghidra_decompile. Live x64 debugging: debug_launch -> "
        "debug_registers/debug_read_memory -> debug_dump -> debug_continue. "
        "All offsets inside dumps equal RVAs. Analysis calls are journaled; use evidence_list."
    ),
)


def _capture(tool: str, params: dict, result):
    return _evidence.capture(tool, params, result)


# --------------------------------------------------------------------- static


@mcp.tool()
def bin_info(path: str) -> dict:
    """PE/ELF metadata: arch, image base, entry RVA, sections, entropy, packer hints."""
    return _capture("bin_info", {"path": path}, _bininfo.bin_info(path))


@mcp.tool()
def strings_scan(
    path: str,
    regex: str | None = None,
    min_len: int = 6,
    encoding: str = "ascii",
    limit: int = 2000,
) -> dict:
    """Extract printable strings with file offsets. encoding: ascii, utf16, both."""
    return _capture(
        "strings_scan",
        {"path": path, "regex": regex, "encoding": encoding, "limit": limit},
        _strings.strings_scan(path, regex=regex, min_len=min_len, encoding=encoding, limit=limit),
    )


@mcp.tool()
def entropy_map(path: str, window: int = 1048576, step: int | None = None) -> dict:
    """Windowed Shannon entropy: packed/encrypted vs plaintext regions."""
    return _capture(
        "entropy_map",
        {"path": path, "window": window, "step": step},
        _blobs.entropy_map(path, window=window, step=step),
    )


@mcp.tool()
def find_blobs(path: str, kind: str = "zip", limit: int = 40, outdir: str | None = None) -> dict:
    """Carve embedded archives or PEs by signature (kind: zip, pe, gzip)."""
    return _capture(
        "find_blobs",
        {"path": path, "kind": kind, "limit": limit},
        _blobs.find_blobs(path, kind=kind, limit=limit, outdir=outdir),
    )


# -------------------------------------------------------------------- runtime


@mcp.tool()
def run_and_dump(
    exe: str,
    wait_ms: int = 15000,
    outdir: str = "dumps",
    elevated: bool = True,
    include_main: bool = True,
) -> dict:
    """Launch a target (optionally elevated), wait, dump all module images, terminate it."""
    return _capture(
        "run_and_dump",
        {"exe": exe, "wait_ms": wait_ms, "outdir": outdir, "elevated": elevated},
        _dumpwin.run_and_dump(
            exe, wait_ms=wait_ms, outdir=outdir, elevated=elevated, include_main=include_main
        ),
    )


@mcp.tool()
def dump_process(
    pid: int, outdir: str = "dumps", include_main: bool = True, skip_system: bool = True
) -> dict:
    """Dump every module image of a running process; writes dump_meta.json."""
    return _capture(
        "dump_process",
        {"pid": pid, "outdir": outdir, "include_main": include_main},
        _dumpwin.dump_process(
            pid, outdir=outdir, include_main=include_main, skip_system=skip_system
        ),
    )


# ------------------------------------------------------------------ PE tools


@mcp.tool()
def rebuild_pe(dump_path: str, out: str, image_base_guess: int | None = None) -> dict:
    """Rebuild a file-aligned PE from a runtime memory image (Scylla-style unmap)."""
    return _capture(
        "rebuild_pe",
        {"dump_path": dump_path, "out": out},
        _pefix.rebuild_pe(dump_path, out, image_base_guess=image_base_guess),
    )


@mcp.tool()
def trim_pe(
    rebuilt_path: str,
    out: str,
    scratch_prefix_end: int = 0x1A00000,
    huge_section_threshold: int = 0x10000000,
    entry_rva: int = 0x1000,
) -> dict:
    """Shrink an unpacked PE for analysis: huge protector arenas keep only a prefix."""
    return _capture(
        "trim_pe",
        {"rebuilt_path": rebuilt_path, "out": out},
        _pefix.trim_pe(
            rebuilt_path,
            out,
            scratch_prefix_end=scratch_prefix_end,
            huge_section_threshold=huge_section_threshold,
            entry_rva=entry_rva,
        ),
    )


@mcp.tool()
def rebuild_imports(dump_path: str, out: str, dump_meta: str) -> dict:
    """Rebuild a dump's IAT/import directory from dump_meta.json module metadata."""
    return _capture(
        "rebuild_imports",
        {"dump_path": dump_path, "out": out, "dump_meta": dump_meta},
        _imports.rebuild_imports(dump_path, out, dump_meta),
    )


# -------------------------------------------------------------------- Delphi


@mcp.tool()
def delphi_methods(
    dump_path: str,
    names: list[str] | None = None,
    names_file: str | None = None,
    max_occurrences: int = 4,
) -> dict:
    """Map Delphi published-method names to code RVAs."""
    return _capture(
        "delphi_methods",
        {"dump_path": dump_path, "names": names, "names_file": names_file},
        _delphi.delphi_methods(
            dump_path, names=names, names_file=names_file, max_occurrences=max_occurrences
        ),
    )


@mcp.tool()
def delphi_units(dump_path: str, top: int = 200) -> dict:
    """Frequency-ranked Delphi unit (a.b.c) and TClass inventory."""
    return _capture(
        "delphi_units", {"dump_path": dump_path, "top": top}, _delphi.delphi_units(dump_path, top=top)
    )


# -------------------------------------------------------------- disassembly


@mcp.tool()
def disasm(path: str, addr: str, count: int = 200, span: int = 8192, base: str = "file") -> dict:
    """Capstone x86/x64 listing at addr (hex string). base: file or rva."""
    return _capture(
        "disasm",
        {"path": path, "addr": addr, "count": count, "base": base},
        _disasm.disasm(path, addr=addr, count=count, span=span, base=base),
    )


@mcp.tool()
def xrefs(path: str, target: str | None = None, string: str | None = None, limit: int = 40) -> dict:
    """Find absolute-immediate references to a value or string."""
    return _capture(
        "xrefs",
        {"path": path, "target": target, "string": string},
        _xrefs.xrefs(path, target=target, string=string, limit=limit),
    )


@mcp.tool()
def xrefs_rip(
    path: str,
    string: str | None = None,
    target: str | None = None,
    limit: int = 40,
    layout: str = "auto",
) -> dict:
    """Find RIP-relative memory refs and direct branches (RVA space; layout auto/dump/file)."""
    return _capture(
        "xrefs_rip",
        {"path": path, "string": string, "target": target, "layout": layout},
        _flow.xrefs_rip(path, string=string, target=target, limit=limit, layout=layout),
    )


@mcp.tool()
def callgraph(
    path: str, root: str, depth: int = 2, max_nodes: int = 200, layout: str = "auto"
) -> dict:
    """Breadth-first direct-call graph from an RVA/VA (indirect calls unresolved)."""
    return _capture(
        "callgraph",
        {"path": path, "root": root, "depth": depth, "layout": layout},
        _flow.callgraph(path, root, depth=depth, max_nodes=max_nodes, layout=layout),
    )


@mcp.tool()
def emulate(
    path: str,
    entry: str | None = None,
    max_instructions: int = 1000,
    layout: str = "auto",
    trace_limit: int = 256,
) -> dict:
    """Bounded Unicorn emulation in RVA space with an execution trace."""
    return _capture(
        "emulate",
        {"path": path, "entry": entry, "max_instructions": max_instructions, "layout": layout},
        _emulate.emulate(
            path, entry=entry, max_instructions=max_instructions, layout=layout,
            trace_limit=trace_limit,
        ),
    )


# -------------------------------------------------------------------- debug


@mcp.tool()
def debug_launch(
    exe: str,
    args: list[str] | None = None,
    breakpoints: list[str] | None = None,
    stop_at_entry: bool = False,
    timeout_ms: int = 15000,
) -> dict:
    """Launch a Windows target (x64 or WOW64 x86) under the debugger; specs 'module:0xRVA' or '0xVA'."""
    return _capture(
        "debug_launch",
        {"exe": exe, "args": args, "stop_at_entry": stop_at_entry},
        _debugger.debug_launch(
            exe,
            args=args,
            breakpoints=breakpoints,
            stop_at_entry=stop_at_entry,
            timeout_ms=timeout_ms,
        ),
    )


@mcp.tool()
def debug_continue(session_id: str, timeout_ms: int = 15000) -> dict:
    """Resume a debug session and wait for the next stop or timeout."""
    return _capture(
        "debug_continue",
        {"session_id": session_id},
        _debugger.debug_continue(session_id, timeout_ms=timeout_ms),
    )


@mcp.tool()
def debug_state(session_id: str) -> dict:
    """Return the debug session summary without touching the target."""
    return _debugger.debug_state(session_id)


@mcp.tool()
def debug_registers(session_id: str) -> dict:
    """Read x64 general-purpose registers of the last stopped thread."""
    return _debugger.debug_registers(session_id)


@mcp.tool()
def debug_read_memory(session_id: str, address: str, size: int = 64) -> dict:
    """Read target memory (hex) at an absolute address."""
    return _debugger.debug_read_memory(session_id, address, size)


@mcp.tool()
def debug_write_memory(session_id: str, address: str, data_hex: str) -> dict:
    """Write bytes (hex string) into target memory."""
    return _debugger.debug_write_memory(session_id, address, data_hex)


@mcp.tool()
def debug_breakpoint_add(
    session_id: str,
    va: str | None = None,
    module: str | None = None,
    rva: str | None = None,
) -> dict:
    """Add a software breakpoint by absolute VA or module + RVA."""
    spec: dict | str = {"va": va} if va else {"module": module, "rva": rva}
    return _debugger.debug_breakpoint_add(session_id, spec)


@mcp.tool()
def debug_breakpoint_remove(session_id: str, address: str) -> dict:
    """Remove a breakpoint and restore the original byte."""
    return _debugger.debug_breakpoint_remove(session_id, address)


@mcp.tool()
def debug_dump(session_id: str, outdir: str = "dumps") -> dict:
    """Dump module images of the stopped process (dump offset == RVA)."""
    return _capture(
        "debug_dump",
        {"session_id": session_id, "outdir": outdir},
        _debugger.debug_dump(session_id, outdir=outdir),
    )


@mcp.tool()
def debug_close(session_id: str) -> dict:
    """Terminate the target (if alive) and release the debug session."""
    return _debugger.debug_close(session_id)


# -------------------------------------------------------------------- ghidra


@mcp.tool()
def ghidra_import(binary: str, project: str, analysis: str = "full", timeout_min: float = 30) -> dict:
    """Headless Ghidra import into a project (analysis: full or none)."""
    return _capture(
        "ghidra_import",
        {"binary": binary, "project": project, "analysis": analysis},
        _ghidra.ghidra_import(binary, project, analysis=analysis, timeout_min=timeout_min),
    )


@mcp.tool()
def ghidra_decompile(
    project: str,
    program: str | None = None,
    rvas: list[str] | None = None,
    keywords: list[str] | None = None,
    limit: int = 40,
    timeout_min: float = 30,
) -> dict:
    """Decompile functions by RVA list and/or by string keywords."""
    return _capture(
        "ghidra_decompile",
        {"project": project, "rvas": rvas, "keywords": keywords},
        _ghidra.ghidra_decompile(
            project,
            program=program,
            rvas=rvas,
            keywords=keywords,
            limit=limit,
            timeout_min=timeout_min,
        ),
    )


@mcp.tool()
def ghidra_funcs(project: str, program: str | None = None, limit: int = 20000) -> dict:
    """List analyzed functions (address + name) from a Ghidra project."""
    return _capture(
        "ghidra_funcs",
        {"project": project, "program": program},
        _ghidra.ghidra_funcs(project, program=program, limit=limit),
    )


# -------------------------------------------------------------------- dotnet


@mcp.tool()
def dotnet_types(asm: str, pattern: str | None = None, limit: int = 5000) -> dict:
    """List types in a managed assembly via ilspycmd, optionally filtered."""
    return _capture(
        "dotnet_types",
        {"asm": asm, "pattern": pattern},
        _dotnet.dotnet_types(asm, pattern=pattern, limit=limit),
    )


@mcp.tool()
def dotnet_type(asm: str, type_name: str) -> dict:
    """Decompile one managed type to C# via ilspycmd."""
    return _capture(
        "dotnet_type", {"asm": asm, "type_name": type_name}, _dotnet.dotnet_type(asm, type_name)
    )


# ---------------------------------------------------------------------- yara


@mcp.tool()
def yara_scan(path: str, rules_file: str | None = None) -> dict:
    """Run YARA rules; without rules_file the bundled packer/anti-debug pack is used."""
    return _capture(
        "yara_scan",
        {"path": path, "rules_file": rules_file},
        _yara.yara_scan(path, rules_file),
    )


@mcp.tool()
def yara_pack(path: str, rules_file: str | None = None) -> dict:
    """Alias for yara_scan with the bundled packer profiles."""
    return _capture(
        "yara_pack",
        {"path": path, "rules_file": rules_file},
        _yara.yara_pack(path, rules_file),
    )


# ------------------------------------------------------------------ evidence


@mcp.tool()
def evidence_list(limit: int = 50) -> dict:
    """List journaled tool calls (newest first) with ids and digests."""
    return _evidence.list_records(limit=limit)


@mcp.tool()
def evidence_read(evidence_id: str) -> dict:
    """Read one full evidence record by id."""
    return _evidence.read_record(evidence_id)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
