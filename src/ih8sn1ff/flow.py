"""Control-flow scanning: RIP-relative xrefs and direct-call graphs."""

from __future__ import annotations

import capstone

from .pemap import Image, load, normalize_rva
from .util import OmniError, parse_int

MAX_SECTION_INSTRUCTIONS = 2_000_000
FUNCTION_SCAN_BYTES = 0x10000


def _wanted_rvas(image: Image, string: str | None, target: int | str | None) -> set[int]:
    wanted: set[int] = set()
    if target is not None:
        wanted.add(normalize_rva(image, parse_int(target)))
    if string is not None:
        encoded = string.encode("utf-8")
        start = 0
        while True:
            offset = image.data.find(encoded, start)
            if offset == -1:
                break
            start = offset + 1
            rva = image.file_to_rva(offset)
            if rva is None:
                continue
            for shift in (0, -2, -4, -8):
                if rva + shift >= 0:
                    wanted.add(rva + shift)
    return wanted


def _disassembler(image: Image):
    mode = capstone.CS_MODE_64 if image.bits == 64 else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    md.detail = True
    md.skipdata = True
    return md


def xrefs_rip(
    path: str,
    string: str | None = None,
    target: int | str | None = None,
    limit: int = 40,
    layout: str = "auto",
) -> dict:
    """Find RIP-relative memory references and direct branches to a target.

    Works in RVA space, so both on-disk PEs and runtime dumps are supported.
    Reports ``kind``: ``rip`` for ``[rip+disp]`` operands, ``branch`` for
    direct call/jmp immediates.
    """
    if string is None and target is None:
        raise OmniError("provide string=<text> or target=<rva|va>")
    image = load(path, layout)
    wanted = _wanted_rvas(image, string, target)
    if not wanted:
        return {
            "path": str(path),
            "layout": image.layout,
            "hits": [],
            "total": 0,
            "truncated": False,
        }
    md = _disassembler(image)

    hits: list[dict] = []
    total = 0
    scanned = 0
    truncated = False
    for _sec, code in image.exec_sections():
        for insn in md.disasm(code, _sec.va):
            scanned += 1
            if scanned > MAX_SECTION_INSTRUCTIONS:
                truncated = True
                break
            candidates: list[tuple[str, int]] = []
            if insn.mnemonic.startswith(("call", "jmp")) and len(insn.operands) == 1:
                op = insn.operands[0]
                if op.type == capstone.x86.X86_OP_IMM:
                    candidates.append(("branch", int(op.imm)))
            for op in insn.operands:
                if (
                    op.type == capstone.x86.X86_OP_MEM
                    and op.mem.base == capstone.x86.X86_REG_RIP
                    and op.mem.index == 0
                ):
                    candidates.append(
                        ("rip", insn.address + insn.size + int(op.mem.disp))
                    )
            for kind, value in candidates:
                if value not in wanted:
                    continue
                total += 1
                if len(hits) < limit:
                    hits.append(
                        {
                            "kind": kind,
                            "rva": insn.address,
                            "target_rva": value,
                            "text": f"{insn.mnemonic} {insn.op_str}",
                        }
                    )
        if truncated:
            break

    return {
        "path": str(path),
        "layout": image.layout,
        "string": string,
        "values": sorted(wanted),
        "hits": hits,
        "total": total,
        "truncated": truncated or total > len(hits),
    }


def _scan_function(image: Image, md, start_rva: int) -> list[dict]:
    offset = image.rva_to_file(start_rva)
    if offset is None:
        return []
    code = image.data[offset : offset + FUNCTION_SCAN_BYTES]
    edges: list[dict] = []
    for insn in md.disasm(code, start_rva):
        if insn.mnemonic.startswith("ret") or insn.mnemonic == "int3":
            break
        if insn.mnemonic.startswith(("call", "jmp")) and len(insn.operands) == 1:
            op = insn.operands[0]
            if op.type == capstone.x86.X86_OP_IMM:
                target = int(op.imm)
                if image.in_exec_rva(target):
                    edges.append(
                        {
                            "site": insn.address,
                            "target": target,
                            "kind": insn.mnemonic,
                            "text": f"{insn.mnemonic} {insn.op_str}",
                        }
                    )
    return edges


def callgraph(
    path: str,
    root: int | str,
    depth: int = 2,
    max_nodes: int = 200,
    layout: str = "auto",
) -> dict:
    """Breadth-first direct-call graph from ``root`` (RVA or VA).

    Indirect calls are not resolved; linear sweep stops at the first return.
    """
    image = load(path, layout)
    root_rva = normalize_rva(image, parse_int(root))
    if depth < 0:
        raise OmniError("depth must be >= 0")
    md = _disassembler(image)

    depth_of: dict[int, int] = {root_rva: 0}
    edges: list[dict] = []
    queue = [root_rva]
    truncated = False

    while queue:
        current = queue.pop(0)
        current_depth = depth_of[current]
        if current_depth >= depth:
            continue
        for edge in _scan_function(image, md, current):
            target = edge["target"]
            edges.append(
                {
                    "from": current,
                    "to": target,
                    "site": edge["site"],
                    "kind": edge["kind"],
                }
            )
            if target not in depth_of:
                if len(depth_of) >= max_nodes:
                    truncated = True
                    continue
                depth_of[target] = current_depth + 1
                queue.append(target)

    return {
        "path": str(path),
        "layout": image.layout,
        "root": root_rva,
        "nodes": [
            {"rva": rva, "depth": level}
            for rva, level in sorted(depth_of.items(), key=lambda item: (item[1], item[0]))
        ],
        "edges": edges,
        "truncated": truncated,
    }
