"""ih8Sn1ff command-line interface (mirror of the MCP tool surface)."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import (
    bininfo,
    blobs,
    debugger,
    delphi,
    disasm,
    dotnet,
    dumpwin,
    emulate,
    evidence,
    flow,
    ghidra,
    imports,
    pefix,
    strings_scan,
    yara_tool,
)
from . import xrefs as xrefs_mod
from .util import OmniError, parse_size


def _emit(payload: Any) -> None:
    if isinstance(payload, str):
        print(payload)
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def _comma_list(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ih8sn1ff", description="Agent-first reverse-engineering toolkit"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("info", help="binary metadata")
    p.add_argument("path")

    p = sub.add_parser("strings", help="extract strings")
    p.add_argument("path")
    p.add_argument("--regex")
    p.add_argument("--min-len", type=int, default=6)
    p.add_argument("--utf16", action="store_true")
    p.add_argument("--encoding", choices=["ascii", "utf16", "both"])
    p.add_argument("--limit", type=int, default=2000)

    p = sub.add_parser("entropy", help="windowed entropy map")
    p.add_argument("path")
    p.add_argument("--window", default="1M")
    p.add_argument("--step")

    p = sub.add_parser("blobs", help="carve embedded blobs")
    p.add_argument("path")
    p.add_argument("--kind", default="zip", choices=["zip", "pe", "gzip"])
    p.add_argument("--limit", type=int, default=40)
    p.add_argument("--outdir")

    p = sub.add_parser("dump", help="dump modules of a running PID")
    p.add_argument("pid", type=int)
    p.add_argument("--out", default="dumps")
    p.add_argument("--no-main", action="store_true")
    p.add_argument("--keep-system", action="store_true")

    p = sub.add_parser("run", help="launch target and dump modules")
    p.add_argument("exe")
    p.add_argument("--wait-ms", type=int, default=15000)
    p.add_argument("--out", default="dumps")
    p.add_argument("--no-elevate", action="store_true")
    p.add_argument("--args", nargs=argparse.REMAINDER)

    p = sub.add_parser("rebuild", help="memory image -> file-aligned PE")
    p.add_argument("dump_path")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--image-base", type=lambda s: int(s, 0))

    p = sub.add_parser("trim", help="analysis-sized PE")
    p.add_argument("rebuilt_path")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--scratch-prefix-end", default="0x1A00000")
    p.add_argument("--huge-threshold", default="0x10000000")
    p.add_argument("--entry-rva", default="0x1000")

    p = sub.add_parser("imports", help="rebuild IAT/import directory of a dump")
    p.add_argument("dump_path")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--meta", required=True, help="dump_meta.json from dump/run")

    p = sub.add_parser("delphi", help="Delphi published-method name -> RVA")
    p.add_argument("dump_path")
    p.add_argument("--names")
    p.add_argument("--names-file")
    p.add_argument("--max-occurrences", type=int, default=4)

    p = sub.add_parser("delphi-units", help="Delphi unit/class inventory")
    p.add_argument("dump_path")
    p.add_argument("--top", type=int, default=200)

    p = sub.add_parser("disasm", help="capstone listing")
    p.add_argument("path")
    p.add_argument("--addr", required=True)
    p.add_argument("--count", type=int, default=200)
    p.add_argument("--span", type=int, default=8192)
    p.add_argument("--base", choices=["file", "rva"], default="file")

    p = sub.add_parser("xrefs", help="absolute-immediate xrefs")
    p.add_argument("path")
    p.add_argument("--target")
    p.add_argument("--string")
    p.add_argument("--limit", type=int, default=40)

    p = sub.add_parser("xrefs-rip", help="RIP-relative xrefs and direct branches")
    p.add_argument("path")
    p.add_argument("--target")
    p.add_argument("--string")
    p.add_argument("--limit", type=int, default=40)
    p.add_argument("--layout", choices=["auto", "dump", "file"], default="auto")

    p = sub.add_parser("callgraph", help="direct-call graph from a root RVA")
    p.add_argument("path")
    p.add_argument("--root", required=True)
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--max-nodes", type=int, default=200)
    p.add_argument("--layout", choices=["auto", "dump", "file"], default="auto")

    p = sub.add_parser("emulate", help="bounded Unicorn emulation")
    p.add_argument("path")
    p.add_argument("--entry")
    p.add_argument("--max-instructions", type=int, default=1000)
    p.add_argument("--trace-limit", type=int, default=256)
    p.add_argument("--layout", choices=["auto", "dump", "file"], default="auto")

    p = sub.add_parser("dbg", help="live x64 debugging (interactive or one-shot)")
    dsub = p.add_subparsers(dest="dbg_command", required=True)
    ds = dsub.add_parser("shell", help="interactive session; debug state stays alive")
    ds.add_argument("exe")
    ds.add_argument("--args", nargs=argparse.REMAINDER)
    ds.add_argument("--breakpoint", action="append", default=[])
    ds.add_argument("--stop-at-entry", action="store_true")
    ds.add_argument("--timeout-ms", type=int, default=15000)
    do = dsub.add_parser("once", help="launch, stop at entry, print state, close")
    do.add_argument("exe")
    do.add_argument("--dump", help="dump modules before closing")
    do.add_argument("--timeout-ms", type=int, default=15000)

    g = sub.add_parser("ghidra", help="Ghidra headless")
    gsub = g.add_subparsers(dest="ghidra_command", required=True)
    gi = gsub.add_parser("import")
    gi.add_argument("binary")
    gi.add_argument("--project", required=True)
    gi.add_argument("--analysis", choices=["full", "none"], default="full")
    gi.add_argument("--timeout-min", type=float, default=30)
    gd = gsub.add_parser("decompile")
    gd.add_argument("project")
    gd.add_argument("--program")
    gd.add_argument("--rva", action="append", default=[])
    gd.add_argument("--keyword", action="append", default=[])
    gd.add_argument("--limit", type=int, default=40)
    gd.add_argument("--timeout-min", type=float, default=30)
    gf = gsub.add_parser("funcs")
    gf.add_argument("project")
    gf.add_argument("--program")
    gf.add_argument("--limit", type=int, default=20000)

    d = sub.add_parser("dotnet", help="managed assembly tools")
    dsub = d.add_subparsers(dest="dotnet_command", required=True)
    dt = dsub.add_parser("types")
    dt.add_argument("asm")
    dt.add_argument("--pattern")
    dt.add_argument("--limit", type=int, default=5000)
    dty = dsub.add_parser("type")
    dty.add_argument("asm")
    dty.add_argument("type_name")

    p = sub.add_parser("yara", help="YARA scan (bundled rules by default)")
    p.add_argument("path")
    p.add_argument("--rules")

    e = sub.add_parser("evidence", help="evidence journal")
    esub = e.add_subparsers(dest="evidence_command", required=True)
    el = esub.add_parser("list")
    el.add_argument("--limit", type=int, default=50)
    er = esub.add_parser("read")
    er.add_argument("evidence_id")

    return parser


def _dbg_dispatch(args) -> None:
    if args.dbg_command == "once":
        _dbg_once(args)
    else:
        _dbg_shell(args)


def _dbg_once(args) -> None:
    result = debugger.debug_launch(
        args.exe, stop_at_entry=True, timeout_ms=args.timeout_ms
    )
    session_id = result["session_id"]
    try:
        _emit(result)
        if result["state"] == "breakpoint":
            _emit(debugger.debug_registers(session_id))
            if args.dump:
                _emit(debugger.debug_dump(session_id, outdir=args.dump))
    finally:
        _emit(debugger.debug_close(session_id))


def _dbg_shell(args) -> None:
    import shlex

    result = debugger.debug_launch(
        args.exe,
        args=args.args or [],
        breakpoints=args.breakpoint,
        stop_at_entry=args.stop_at_entry,
        timeout_ms=args.timeout_ms,
    )
    session_id = result["session_id"]
    _emit(result)
    print(
        "commands: state | regs | read ADDR [SIZE] | write ADDR HEX | "
        "bp-add VA | bp-add MODULE RVA | bp-remove ADDR | continue [MS] | "
        "dump OUTDIR | close | quit",
        file=sys.stderr,
    )
    try:
        while True:
            try:
                line = input("dbg> ").strip()
            except (EOFError, KeyboardInterrupt):
                print(file=sys.stderr)
                break
            if not line:
                continue
            parts = shlex.split(line)
            cmd = parts[0].lower()
            try:
                if cmd in {"quit", "exit"}:
                    break
                if cmd == "state":
                    _emit(debugger.debug_state(session_id))
                elif cmd in {"regs", "registers"}:
                    _emit(debugger.debug_registers(session_id))
                elif cmd == "read" and len(parts) >= 2:
                    size = int(parts[2], 0) if len(parts) > 2 else 64
                    _emit(debugger.debug_read_memory(session_id, parts[1], size))
                elif cmd == "write" and len(parts) >= 3:
                    _emit(debugger.debug_write_memory(session_id, parts[1], parts[2]))
                elif cmd == "bp-add" and len(parts) == 2:
                    _emit(debugger.debug_breakpoint_add(session_id, parts[1]))
                elif cmd == "bp-add" and len(parts) >= 3:
                    _emit(
                        debugger.debug_breakpoint_add(
                            session_id, {"module": parts[1], "rva": parts[2]}
                        )
                    )
                elif cmd == "bp-remove" and len(parts) >= 2:
                    _emit(debugger.debug_breakpoint_remove(session_id, parts[1]))
                elif cmd == "continue":
                    timeout = int(parts[1], 0) if len(parts) > 1 else args.timeout_ms
                    _emit(debugger.debug_continue(session_id, timeout_ms=timeout))
                elif cmd == "dump":
                    outdir = parts[1] if len(parts) > 1 else "dumps"
                    _emit(debugger.debug_dump(session_id, outdir=outdir))
                elif cmd == "help":
                    print(
                        "state | regs | read ADDR [SIZE] | write ADDR HEX | "
                        "bp-add VA | bp-add MODULE RVA | bp-remove ADDR | "
                        "continue [MS] | dump OUTDIR | close | quit",
                        file=sys.stderr,
                    )
                else:
                    print(f"unknown command: {line}", file=sys.stderr)
            except OmniError as exc:
                print(f"error: {exc}", file=sys.stderr)
    finally:
        _emit(debugger.debug_close(session_id))


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "info":
            _emit(bininfo.bin_info(args.path))
        elif args.command == "strings":
            _emit(
                strings_scan.strings_scan(
                    args.path,
                    regex=args.regex,
                    min_len=args.min_len,
                    utf16=args.utf16,
                    encoding=args.encoding,
                    limit=args.limit,
                )
            )
        elif args.command == "entropy":
            _emit(
                blobs.entropy_map(
                    args.path,
                    window=parse_size(args.window),
                    step=parse_size(args.step) if args.step else None,
                )
            )
        elif args.command == "blobs":
            _emit(
                blobs.find_blobs(
                    args.path, kind=args.kind, limit=args.limit, outdir=args.outdir
                )
            )
        elif args.command == "dump":
            _emit(
                dumpwin.dump_process(
                    args.pid,
                    outdir=args.out,
                    include_main=not args.no_main,
                    skip_system=not args.keep_system,
                )
            )
        elif args.command == "run":
            _emit(
                dumpwin.run_and_dump(
                    args.exe,
                    wait_ms=args.wait_ms,
                    outdir=args.out,
                    elevated=not args.no_elevate,
                    args=args.args or [],
                )
            )
        elif args.command == "rebuild":
            _emit(
                pefix.rebuild_pe(args.dump_path, args.out, image_base_guess=args.image_base)
            )
        elif args.command == "trim":
            _emit(
                pefix.trim_pe(
                    args.rebuilt_path,
                    args.out,
                    scratch_prefix_end=int(args.scratch_prefix_end, 0),
                    huge_section_threshold=int(args.huge_threshold, 0),
                    entry_rva=int(args.entry_rva, 0),
                )
            )
        elif args.command == "imports":
            _emit(imports.rebuild_imports(args.dump_path, args.out, args.meta))
        elif args.command == "delphi":
            _emit(
                delphi.delphi_methods(
                    args.dump_path,
                    names=_comma_list(args.names),
                    names_file=args.names_file,
                    max_occurrences=args.max_occurrences,
                )
            )
        elif args.command == "delphi-units":
            _emit(delphi.delphi_units(args.dump_path, top=args.top))
        elif args.command == "disasm":
            _emit(
                disasm.disasm(
                    args.path,
                    args.addr,
                    count=args.count,
                    span=args.span,
                    base=args.base,
                )
            )
        elif args.command == "xrefs":
            _emit(
                xrefs_mod.xrefs(
                    args.path, target=args.target, string=args.string, limit=args.limit
                )
            )
        elif args.command == "xrefs-rip":
            _emit(
                flow.xrefs_rip(
                    args.path,
                    string=args.string,
                    target=args.target,
                    limit=args.limit,
                    layout=args.layout,
                )
            )
        elif args.command == "callgraph":
            _emit(
                flow.callgraph(
                    args.path,
                    args.root,
                    depth=args.depth,
                    max_nodes=args.max_nodes,
                    layout=args.layout,
                )
            )
        elif args.command == "emulate":
            _emit(
                emulate.emulate(
                    args.path,
                    entry=args.entry,
                    max_instructions=args.max_instructions,
                    trace_limit=args.trace_limit,
                    layout=args.layout,
                )
            )
        elif args.command == "dbg":
            _dbg_dispatch(args)
        elif args.command == "ghidra":
            if args.ghidra_command == "import":
                _emit(
                    ghidra.ghidra_import(
                        args.binary,
                        args.project,
                        analysis=args.analysis,
                        timeout_min=args.timeout_min,
                    )
                )
            elif args.ghidra_command == "decompile":
                _emit(
                    ghidra.ghidra_decompile(
                        args.project,
                        program=args.program,
                        rvas=args.rva or None,
                        keywords=args.keyword or None,
                        limit=args.limit,
                        timeout_min=args.timeout_min,
                    )
                )
            else:
                _emit(
                    ghidra.ghidra_funcs(
                        args.project, program=args.program, limit=args.limit
                    )
                )
        elif args.command == "dotnet":
            if args.dotnet_command == "types":
                _emit(dotnet.dotnet_types(args.asm, pattern=args.pattern, limit=args.limit))
            else:
                _emit(dotnet.dotnet_type(args.asm, args.type_name))
        elif args.command == "yara":
            _emit(yara_tool.yara_scan(args.path, args.rules))
        elif args.command == "evidence":
            if args.evidence_command == "list":
                _emit(evidence.list_records(limit=args.limit))
            else:
                _emit(evidence.read_record(args.evidence_id))
        else:  # pragma: no cover - argparse guarantees a command
            raise OmniError(f"unknown command {args.command}")
    except OmniError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
