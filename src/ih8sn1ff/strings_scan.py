"""String extraction with offsets, regex filtering and encoding choice."""

from __future__ import annotations

import re

from .util import OmniError, read_file

_ASCII_RUN = re.compile(rb"[\x20-\x7e\t]{4,}")
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def strings_scan(
    path: str,
    regex: str | None = None,
    min_len: int = 6,
    utf16: bool = False,
    encoding: str | None = None,
    limit: int = 2000,
) -> dict:
    """Scan a file for printable strings.

    ``encoding``: ``"ascii"`` (default), ``"utf16"`` or ``"both"``.
    ``utf16=True`` is kept as a convenience alias for ``encoding="utf16"``.
    Returns ``{matches: [{offset, text}], total, truncated, encoding}``.
    """
    data = read_file(path)
    enc = (encoding or ("utf16" if utf16 else "ascii")).lower()
    if enc not in {"ascii", "utf16", "both"}:
        raise OmniError("encoding must be ascii, utf16 or both")

    if min_len < 1:
        raise OmniError("min_len must be >= 1")
    pattern = re.compile(regex) if regex else None

    matches: list[dict] = []
    total = 0

    def consider(text: str, offset: int) -> None:
        nonlocal total
        if len(text) < min_len:
            return
        if pattern and not pattern.search(text):
            return
        total += 1
        if len(matches) < limit:
            matches.append({"offset": offset, "text": text})

    if enc in {"ascii", "both"}:
        for m in _ASCII_RUN.finditer(data):
            consider(m.group().decode("ascii", "replace"), m.start())

    if enc in {"utf16", "both"}:
        for m in _UTF16_RUN.finditer(data):
            text = m.group().decode("utf-16le", "replace")
            offset = m.start()
            if (
                len(text) > 1
                and offset >= 2
                and 0x20 <= data[offset - 1] <= 0x7E
                and 0x20 <= data[offset - 2] <= 0x7E
            ):
                # A printable ASCII tail immediately before the run means the
                # leading pair is that ASCII string's terminator, not UTF-16.
                text = text[1:]
                offset += 2
            consider(text, offset)

    if enc == "both":
        matches.sort(key=lambda item: item["offset"])

    return {
        "path": path,
        "encoding": enc,
        "matches": matches,
        "total": total,
        "truncated": total > len(matches),
    }
