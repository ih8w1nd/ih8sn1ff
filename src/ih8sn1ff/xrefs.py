"""Absolute-immediate xref scanning (string constants and raw values).

Values are searched with ``bytes.find`` so unaligned immediates (the common
``mov reg, imm32`` / ``push imm32`` placement right after an opcode) are found
too, without a byte-by-byte Python scan.
"""

from __future__ import annotations

import struct

from .util import OmniError, find_function_start, parse_int, read_file, u16, u32


def _exec_ranges(data: bytes) -> list[tuple[int, int]]:
    """File ranges of executable PE sections; whole file when not a PE."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return [(0, len(data))]
    e_lfanew = u32(data, 0x3C)
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return [(0, len(data))]
    coff = e_lfanew + 4
    num = u16(data, coff + 2)
    opt_size = u16(data, coff + 16)
    table = coff + 20 + opt_size
    ranges: list[tuple[int, int]] = []
    for i in range(num):
        hdr = table + i * 40
        chars = u32(data, hdr + 36)
        if not chars & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            continue
        raw_size = u32(data, hdr + 16)
        raw_ptr = u32(data, hdr + 20)
        if raw_size:
            ranges.append((raw_ptr, raw_ptr + raw_size))
    return ranges or [(0, len(data))]


def _in_ranges(ranges: list[tuple[int, int]], offset: int) -> bool:
    for lo, hi in ranges:
        if lo <= offset < hi:
            return True
    return False


def _string_offsets(data: bytes, needle: bytes) -> list[int]:
    offsets = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            return offsets
        offsets.append(idx)
        start = idx + 1


def xrefs(
    path: str,
    target: int | str | None = None,
    string: str | None = None,
    limit: int = 40,
) -> dict:
    """Find absolute-immediate references to a value or string.

    For strings, the exact address plus Delphi ShortString shifts (-2/-4/-8)
    are matched. Hits are restricted to executable ranges and annotated with
    the nearest plausible function prologue.
    """
    data = read_file(path)
    if target is None and string is None:
        raise OmniError("provide target=<int> or string=<text>")

    wanted: set[int] = set()
    if target is not None:
        wanted.add(parse_int(target))
    if string is not None:
        encoded = string.encode("utf-8")
        offsets = _string_offsets(data, encoded)
        if not offsets:
            return {
                "path": str(path),
                "string": string,
                "values": [],
                "hits": [],
                "total": 0,
                "truncated": False,
            }
        for off in offsets[:200]:
            for shift in (0, -2, -4, -8):
                value = off + shift
                if 0 <= value <= 0xFFFFFFFF:
                    wanted.add(value)

    if not wanted:
        raise OmniError("no searchable values (target must fit in 32 bits)")

    exec_ranges = _exec_ranges(data)
    hits: list[dict] = []
    total = 0
    seen: set[tuple[int, int]] = set()

    for value in sorted(wanted):
        packed = struct.pack("<I", value)
        pos = 0
        while True:
            idx = data.find(packed, pos)
            if idx == -1:
                break
            pos = idx + 1
            if not _in_ranges(exec_ranges, idx):
                continue
            if (value, idx) in seen:
                continue
            seen.add((value, idx))
            total += 1
            if len(hits) < limit:
                hits.append(
                    {
                        "ref_offset": idx,
                        "value": value,
                        "string": string,
                        "function_start": find_function_start(data, idx),
                    }
                )

    hits.sort(key=lambda hit: hit["ref_offset"])
    return {
        "path": str(path),
        "string": string,
        "values": sorted(wanted),
        "hits": hits,
        "total": total,
        "truncated": total > len(hits),
    }
