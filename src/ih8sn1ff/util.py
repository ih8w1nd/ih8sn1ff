"""Shared helpers for ih8Sn1ff.

Everything here is deterministic and side-effect free: parsing, entropy,
prologue hunting and printable-string reads used by the higher-level tools.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path


class OmniError(RuntimeError):
    """Actionable error surfaced to MCP/CLI callers."""


def parse_int(value: int | str) -> int:
    """Parse ``0x``-prefixed hex or decimal input into an int."""
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        raise OmniError("empty integer value")
    sign = 1
    if text[0] in "+-":
        if text[0] == "-":
            sign = -1
        text = text[1:]
    base = 16 if text.lower().startswith("0x") else 10
    try:
        return sign * int(text, base)
    except ValueError as exc:
        raise OmniError(f"not an integer: {value!r}") from exc


def parse_size(value: int | str) -> int:
    """Parse ``8192``, ``0x2000``, ``16K`` or ``1M`` into bytes."""
    if isinstance(value, int):
        return value
    text = str(value).strip().upper().replace(" ", "")
    mult = 1
    if text.endswith("K"):
        mult, text = 1024, text[:-1]
    elif text.endswith("M"):
        mult, text = 1024 * 1024, text[:-1]
    elif text.endswith("G"):
        mult, text = 1024 * 1024 * 1024, text[:-1]
    try:
        return parse_int(text) * mult
    except OmniError as exc:
        raise OmniError(f"not a size: {value!r}") from exc


def read_file(path: str | Path) -> bytes:
    p = Path(path)
    if not p.is_file():
        raise OmniError(f"file not found: {p}")
    return p.read_bytes()


def u16(data: bytes | bytearray, off: int) -> int:
    return int.from_bytes(data[off : off + 2], "little")


def u32(data: bytes | bytearray, off: int) -> int:
    return int.from_bytes(data[off : off + 4], "little")


def u64(data: bytes | bytearray, off: int) -> int:
    return int.from_bytes(data[off : off + 8], "little")


def align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


def entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0.0 empty, max 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e\t]{4,}")


def read_cstring(data: bytes | bytearray, offset: int, max_len: int = 160) -> str | None:
    """Return the printable ASCII run starting at ``offset`` or None."""
    if offset < 0 or offset >= len(data):
        return None
    chunk = bytes(data[offset : offset + max_len])
    run = _PRINTABLE_RUN.match(chunk)
    if not run:
        return None
    return run.group().decode("ascii", "replace")


PROLOGUES: tuple[bytes, ...] = (
    b"\x55\x8b\xec",              # push ebp; mov ebp, esp (32-bit)
    b"\x55\x89\xe5",              # push ebp; mov ebp, esp (GCC 32-bit)
    b"\x8b\xff\x55\x8b\xec",      # mov edi,edi; push ebp; mov ebp,esp (hotpatch)
    b"\x48\x89\x5c\x24",          # mov [rsp+x], rbx (MSVC x64)
    b"\x48\x83\xec",              # sub rsp, imm (x64 leaf-ish)
    b"\x55\x48\x89\xe5",          # push rbp; mov rbp, rsp (x64)
    b"\x40\x53",                  # push rbx (x64 REX)
    b"\x53\x56\x57",              # push rbx; push rsi; push rdi
)


def find_function_start(data: bytes | bytearray, offset: int, limit: int = 0x2000) -> int | None:
    """Nearest plausible function prologue at or before ``offset``."""
    start = max(0, offset - limit)
    best: int | None = None
    for pat in PROLOGUES:
        idx = data.rfind(pat, start, offset)
        if idx != -1 and (best is None or idx > best):
            best = idx
    return best


def hexs(value: int) -> str:
    return f"0x{value:x}"
