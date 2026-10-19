"""Capstone-based x86/x64 disassembly with inline string annotations."""

from __future__ import annotations

from pathlib import Path

from .bininfo import pe_bits
from .util import OmniError, parse_int, read_cstring, read_file, u16, u32


def _rva_to_offset(data: bytes, rva: int) -> int | None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = u32(data, 0x3C)
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    coff = e_lfanew + 4
    num = u16(data, coff + 2)
    opt_size = u16(data, coff + 16)
    table = coff + 20 + opt_size
    for i in range(num):
        hdr = table + i * 40
        va = u32(data, hdr + 12)
        vsize = u32(data, hdr + 8)
        raw_size = u32(data, hdr + 16)
        raw_ptr = u32(data, hdr + 20)
        if va <= rva < va + max(vsize, raw_size):
            delta = rva - va
            return raw_ptr + delta if delta < raw_size else None
    return None


def disasm(
    path: str,
    addr: int | str,
    count: int = 200,
    span: int = 8192,
    base: str = "file",
) -> dict:
    """Disassemble x86/x64 starting at ``addr``.

    ``base="file"``: addr is a file offset (dumps: offset == RVA).
    ``base="rva"``: addr is an RVA, translated through the PE section map.
    Immediate operands pointing at printable bytes get a ``; "..."`` comment.
    """
    import capstone

    data = read_file(path)
    start = parse_int(addr)
    if start < 0 or start >= len(data):
        raise OmniError(f"address 0x{start:x} outside file (size 0x{len(data):x})")
    if count < 1:
        raise OmniError("count must be >= 1")

    bits = pe_bits(path) or 64
    mode = capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    md.detail = True
    md.skipdata = True

    file_start = start
    if base == "rva":
        mapped = _rva_to_offset(data, start)
        if mapped is None:
            raise OmniError(f"RVA 0x{start:x} is not file-backed")
        file_start = mapped
    elif base != "file":
        raise OmniError("base must be 'file' or 'rva'")

    code = data[file_start : file_start + span]
    lines: list[dict] = []
    for insn in md.disasm(code, file_start):
        if len(lines) >= count:
            break
        text = f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}".rstrip()
        comment = None
        for op in insn.operands:
            candidate = None
            if op.type == capstone.x86.X86_OP_IMM:
                candidate = int(op.imm)
            elif op.type == capstone.x86.X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                candidate = int(op.mem.disp)
            if candidate is None:
                continue
            readable = read_cstring(data, candidate, 80)
            if readable and len(readable) >= 4:
                comment = f'"{readable}"'
                break
        lines.append(
            {
                "address": insn.address,
                "bytes": bytes(insn.bytes).hex(),
                "text": text,
                "comment": comment,
            }
        )

    return {
        "path": str(Path(path)),
        "bits": bits,
        "start": file_start,
        "count": len(lines),
        "instructions": lines,
    }
