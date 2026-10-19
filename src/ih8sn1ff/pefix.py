"""Memory-image to file-aligned PE rebuild, and analysis-sized trimming.

A runtime dump starts at the module base, so ``file offset == RVA`` inside the
dump and every section is present with its *virtual* size. ``rebuild_pe``
converts that layout to a normal PE (raw sections chained after the headers)
without touching RVAs, so embedded RTTI/pointers remain valid.

``trim_pe`` produces a smaller analysis PE: huge protector arenas keep only a
prefix (method code frequently lands just past their start), the rest is
reduced to a 0x1000-byte placeholder so Ghidra analysis stays fast.
"""

from __future__ import annotations

import struct
from pathlib import Path

from .util import OmniError, align_up, read_file, u16, u32

_LARGE_SECTION = 0x10000000


def _parse_pe(data: bytes) -> dict:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise OmniError("not a PE image (missing MZ)")
    e_lfanew = u32(data, 0x3C)
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise OmniError("not a PE image (missing PE signature)")
    coff = e_lfanew + 4
    num_sections = u16(data, coff + 2)
    opt_size = u16(data, coff + 16)
    opt = coff + 20
    magic = u16(data, opt)
    if magic not in (0x10B, 0x20B):
        raise OmniError(f"unsupported optional header magic {hex(magic)}")
    file_align = u32(data, opt + 0x24) or 0x200
    section_align = u32(data, opt + 0x20) or 0x1000
    size_headers = u32(data, opt + 0x3C)
    entry_rva = u32(data, opt + 0x10)
    section_table = opt + opt_size
    if section_table + num_sections * 40 > len(data):
        raise OmniError("truncated section table in image")
    if size_headers == 0:
        size_headers = align_up(section_table + num_sections * 40, file_align)
    sections = []
    for i in range(num_sections):
        hdr = section_table + i * 40
        sections.append(
            {
                "header_off": hdr,
                "name": data[hdr : hdr + 8].rstrip(b"\x00").decode("latin-1", "replace"),
                "vsize": u32(data, hdr + 8),
                "va": u32(data, hdr + 12),
                "raw_size": u32(data, hdr + 16),
                "raw_ptr": u32(data, hdr + 20),
                "characteristics": u32(data, hdr + 36),
            }
        )
    return {
        "e_lfanew": e_lfanew,
        "opt": opt,
        "opt_size": opt_size,
        "file_align": file_align,
        "section_align": section_align,
        "size_headers": size_headers,
        "entry_rva": entry_rva,
        "size_image": u32(data, opt + 0x38),
        "sections": sections,
    }


def rebuild_pe(dump_path: str, out: str, image_base_guess: int | None = None) -> dict:
    """Rebuild a file-aligned PE from a runtime memory image.

    ``image_base_guess`` is informational only (the in-memory header already
    carries the real base). Returns layout stats and per-section warnings.
    """
    data = read_file(dump_path)
    layout = _parse_pe(data)
    file_align = layout["file_align"]
    header_len = align_up(layout["size_headers"], file_align)
    header = bytearray(data[:header_len])
    if len(header) < header_len:
        header.extend(b"\x00" * (header_len - len(header)))

    warnings: list[str] = []
    out_buf = bytearray(header)
    new_ptr = header_len
    section_stats = []

    for sec in layout["sections"]:
        va = sec["va"]
        vsize = sec["vsize"]
        if va >= len(data) or (vsize and va == 0):
            warnings.append(f"section {sec['name']!r} VA 0x{va:x} outside dump")
            content = b""
        else:
            content = data[va : va + vsize]
            if len(content) < vsize:
                missing = vsize - len(content)
                if missing > 64 * 1024 * 1024:
                    # Never materialize gigabytes of zeros from a corrupt or
                    # synthetic header; keep only bytes actually present.
                    warnings.append(
                        f"section {sec['name']!r} declares {vsize} bytes but only "
                        f"{len(content)} are present (kept present bytes)"
                    )
                else:
                    warnings.append(
                        f"section {sec['name']!r} short by {missing} bytes (zero-filled)"
                    )
                    content = bytes(content) + b"\x00" * missing
        materialized = len(content)
        raw_size = align_up(materialized, file_align) if materialized else 0
        if vsize == 0:
            content = b""
        struct.pack_into("<I", out_buf, sec["header_off"] + 16, raw_size)
        struct.pack_into("<I", out_buf, sec["header_off"] + 20, new_ptr if raw_size else 0)
        out_buf.extend(content)
        pad = raw_size - len(content)
        if pad > 0:
            out_buf.extend(b"\x00" * pad)
        new_ptr += raw_size
        section_stats.append(
            {
                "name": sec["name"],
                "va": va,
                "vsize": vsize,
                "raw_size": raw_size,
                "new_raw_ptr": sec["raw_ptr"] if raw_size == 0 else new_ptr - raw_size,
            }
        )

    # Headers now end where the first section begins.
    struct.pack_into("<I", out_buf, layout["opt"] + 0x3C, header_len)
    if image_base_guess is not None and u32(out_buf, layout["opt"] + 0x28) == 0:
        struct.pack_into("<I", out_buf, layout["opt"] + 0x28, image_base_guess)

    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_bytes(bytes(out_buf))
    return {
        "input": str(dump_path),
        "output": str(out),
        "input_size": len(data),
        "output_size": len(out_buf),
        "image_base": u32(out_buf, layout["opt"] + 0x28),
        "entry_rva": layout["entry_rva"],
        "sections": section_stats,
        "warnings": warnings,
    }


def trim_pe(
    rebuilt_path: str,
    out: str,
    scratch_prefix_end: int = 0x1A00000,
    huge_section_threshold: int = _LARGE_SECTION,
    entry_rva: int = 0x1000,
) -> dict:
    """Shrink an unpacked PE for static analysis.

    Sections at or above ``huge_section_threshold`` are protector arenas: only
    the byte prefix before ``scratch_prefix_end`` is kept, and their virtual
    size is reduced accordingly. All normal sections are kept in full.
    """
    data = read_file(rebuilt_path)
    layout = _parse_pe(data)
    file_align = layout["file_align"]
    section_align = layout["section_align"]
    header_len = align_up(layout["size_headers"], file_align)
    header = bytearray(data[:header_len])
    if len(header) < header_len:
        header.extend(b"\x00" * (header_len - len(header)))

    out_buf = bytearray(header)
    new_ptr = header_len
    max_end = layout["size_image"]
    stats = []

    for sec in layout["sections"]:
        if sec["vsize"] < huge_section_threshold:
            take = sec["vsize"]
            trimmed = False
        else:
            take = min(sec["vsize"], max(0, scratch_prefix_end - sec["va"]))
            trimmed = True
        raw_start = sec["raw_ptr"]
        chunk = data[raw_start : raw_start + take] if take and raw_start else b""
        if len(chunk) < take:
            chunk = bytes(chunk) + b"\x00" * (take - len(chunk))
        if take == 0:
            chunk = b""
            new_vsize = 0x1000 if trimmed else 0
        else:
            new_vsize = align_up(take, section_align)
        raw_size = align_up(take, file_align) if take else 0
        struct.pack_into("<I", out_buf, sec["header_off"] + 8, new_vsize)
        struct.pack_into("<I", out_buf, sec["header_off"] + 16, raw_size)
        struct.pack_into("<I", out_buf, sec["header_off"] + 20, new_ptr if raw_size else 0)
        out_buf.extend(chunk)
        pad = raw_size - len(chunk)
        if pad > 0:
            out_buf.extend(b"\x00" * pad)
        new_ptr += raw_size
        stats.append(
            {
                "name": sec["name"],
                "va": sec["va"],
                "old_vsize": sec["vsize"],
                "new_vsize": new_vsize,
                "trimmed": trimmed,
            }
        )
        if new_vsize:
            max_end = max(max_end, sec["va"] + new_vsize)

    if entry_rva:
        struct.pack_into("<I", out_buf, layout["opt"] + 0x10, entry_rva)
    struct.pack_into("<I", out_buf, layout["opt"] + 0x38, align_up(max_end, section_align))
    struct.pack_into("<I", out_buf, layout["opt"] + 0x3C, header_len)

    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_bytes(bytes(out_buf))
    return {
        "input": str(rebuilt_path),
        "output": str(out),
        "input_size": len(data),
        "output_size": len(out_buf),
        "sections": stats,
    }
