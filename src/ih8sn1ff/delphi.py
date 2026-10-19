"""Delphi RTTI helpers: published-method name mapping and unit inventory.

Delphi published-method tables store entries inline as::

    { dword code_ptr; byte name_len; char name[name_len] }

so for a name found at dump offset ``off`` the code pointer sits at
``off - 5`` (validated against the preceding length byte). Pointer-form tables
(dword pointer to ShortString) are also accepted.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from .util import OmniError, read_file, u32

_DOTTED = re.compile(rb"\b[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){2,}\b")
_TCLASS = re.compile(rb"\bT[A-Z][A-Za-z0-9_]{2,40}\b")


def _plausible_code_ptr(ptr: int, size: int) -> bool:
    return 0x1000 <= ptr < max(size, 0x1000)


def _try_pointer_form(data: bytes, name: bytes) -> list[dict]:
    hits = []
    for off in _find_all(data, name):
        # Pointer-form: the dword immediately before the name points at the bytes.
        if off < 8:
            continue
        ptr = u32(data, off - 4)
        if ptr and ptr + len(name) < len(data) and data[ptr : ptr + len(name)] == name:
            code = u32(data, off - 8)
            hits.append({"name_offset": ptr, "entry_offset": off - 8, "code_ptr": code})
    return hits


def _find_all(data: bytes, needle: bytes) -> list[int]:
    hits: list[int] = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            return hits
        hits.append(idx)
        start = idx + 1


def delphi_methods(
    dump_path: str,
    names: list[str] | None = None,
    names_file: str | None = None,
    max_occurrences: int = 4,
) -> dict:
    """Map Delphi method names to code RVAs (dump offset == RVA)."""
    data = read_file(dump_path)
    wanted = list(names or [])
    if names_file:
        text = Path(names_file).read_text("utf-8", "replace")
        wanted.extend(line.strip() for line in text.splitlines() if line.strip())
    if not wanted:
        raise OmniError("provide names=[...] or names_file=... to resolve")

    rows: list[dict] = []
    missed: list[str] = []
    for name in wanted:
        encoded = name.encode("ascii", "ignore")
        if not encoded:
            missed.append(name)
            continue
        found = 0
        for off in _find_all(data, encoded):
            if off < 5:
                continue
            if data[off - 1] != len(encoded):
                continue
            code_ptr = u32(data, off - 5)
            if not _plausible_code_ptr(code_ptr, len(data)):
                continue
            rows.append(
                {
                    "name": name,
                    "occurrence": found,
                    "entry_offset": off - 5,
                    "name_offset": off,
                    "code_rva": code_ptr,
                }
            )
            found += 1
            if found >= max_occurrences:
                break
        if not found:
            for hit in _try_pointer_form(data, encoded)[:max_occurrences]:
                rows.append(
                    {
                        "name": name,
                        "occurrence": found,
                        "entry_offset": hit["entry_offset"],
                        "name_offset": hit["name_offset"],
                        "code_rva": hit["code_ptr"],
                        "form": "pointer",
                    }
                )
                found += 1
        if not found:
            missed.append(name)

    return {
        "path": str(dump_path),
        "resolved": len(rows),
        "missed": missed,
        "methods": rows,
    }


def delphi_units(dump_path: str, top: int = 200) -> dict:
    """Frequency-ranked unit and TClass inventory from ASCII runs."""
    data = read_file(dump_path)
    units = Counter(m.group().decode("ascii") for m in _DOTTED.finditer(data))
    classes = Counter(m.group().decode("ascii") for m in _TCLASS.finditer(data))
    return {
        "path": str(dump_path),
        "units": [{"name": name, "count": count} for name, count in units.most_common(top)],
        "classes": [
            {"name": name, "count": count} for name, count in classes.most_common(top)
        ],
    }
