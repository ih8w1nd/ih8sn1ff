"""Entropy mapping and embedded-blob carving."""

from __future__ import annotations

from pathlib import Path

from .util import OmniError, entropy, parse_size, read_file, u32


def entropy_map(path: str, window: int = 1024 * 1024, step: int | None = None) -> dict:
    """Windowed Shannon entropy — packed/encrypted vs plain regions."""
    data = read_file(path)
    win = parse_size(window)
    stride = parse_size(step) if step else win
    if win <= 0:
        raise OmniError("window must be positive")
    windows = []
    for off in range(0, len(data), stride):
        chunk = data[off : off + win]
        if not chunk:
            break
        windows.append(
            {
                "offset": off,
                "size": len(chunk),
                "entropy": round(entropy(chunk), 3),
                "packed": entropy(chunk) >= 7.5,
            }
        )
    return {"path": path, "window": win, "windows": windows, "size": len(data)}


def _zip_valid(data: bytes, off: int) -> bool:
    return data.find(b"PK\x05\x06", off) != -1


def _pe_valid(data: bytes, off: int) -> bool:
    if off + 0x40 > len(data):
        return False
    e_lfanew = u32(data, off + 0x3C)
    if e_lfanew <= 0 or e_lfanew > 0x10000000:
        return False
    return data[off + e_lfanew : off + e_lfanew + 4] == b"PE\x00\x00"


def find_blobs(
    path: str,
    kind: str = "zip",
    limit: int = 40,
    outdir: str | None = None,
    max_blob: int = 64 * 1024 * 1024,
) -> dict:
    """Carve embedded archives / PEs by signature.

    kind: ``zip``, ``pe`` or ``gzip``. When ``outdir`` is set, candidates are
    written as ``blob_NN_<off>.bin`` and the paths are returned.
    """
    data = read_file(path)
    kind = kind.lower()
    sigs = {
        "zip": (b"PK\x03\x04", _zip_valid),
        "pe": (b"MZ", _pe_valid),
        "gzip": (b"\x1f\x8b\x08", None),
    }
    if kind not in sigs:
        raise OmniError("kind must be zip, pe or gzip")
    sig, validate = sigs[kind]

    found: list[dict] = []
    start = 0
    while len(found) < limit:
        off = data.find(sig, start)
        if off == -1:
            break
        start = off + 1
        if validate and not validate(data, off):
            continue
        found.append({"kind": kind, "offset": off})
        if outdir:
            out = Path(outdir)
            out.mkdir(parents=True, exist_ok=True)
            target = out / f"blob_{len(found) - 1:02d}_{off:x}.bin"
            target.write_bytes(data[off : off + max_blob])
            found[-1]["written"] = str(target)

    return {"path": path, "kind": kind, "count": len(found), "blobs": found}
