"""Scylla-style IAT rebuild for runtime dumps.

The dumped image keeps resolved absolute addresses in its import thunks, so
the original import directory is only partially useful. This module walks the
FirstThunk arrays, maps every address back to a module (using ``dump_meta``
written by :func:`dumpwin.dump_process`), resolves the export name from the
module file on disk, and appends a fresh import directory as a new section.
"""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path

from .pemap import load
from .util import OmniError, align_up, u16, u32

IMPORT_DIR_INDEX = 1
DESCRIPTOR_SIZE = 20
MAX_THUNKS = 4096
MAX_DESCRIPTORS = 1024


def _module_for(address: int, modules: list[dict]) -> dict | None:
    best = None
    for module in modules:
        base = int(module.get("base") or 0)
        size = int(module.get("size") or 0)
        if (
            base
            and size
            and base <= address < base + size
            and (best is None or base > int(best.get("base") or 0))
        ):
            best = module
    return best


def _module_file(module: dict) -> Path | None:
    path = module.get("path") or ""
    if path and Path(path).is_file():
        return Path(path)
    name = module.get("name") or ""
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    fallback = Path(system_root) / "System32" / name
    return fallback if name and fallback.is_file() else None


class _ExportCache:
    def __init__(self) -> None:
        self._cache: dict[str, dict[int, tuple[str, int]]] = {}

    def get(self, path: Path) -> dict[int, tuple[str, int]]:
        key = str(path).casefold()
        if key in self._cache:
            return self._cache[key]
        import pefile

        mapping: dict[int, tuple[str, int]] = {}
        try:
            pe = pefile.PE(str(path), fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
            )
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if not symbol.address:
                        continue
                    name = (
                        symbol.name.decode("utf-8", "replace") if symbol.name else ""
                    )
                    mapping[symbol.address] = (name, int(symbol.ordinal))
        except pefile.PEFormatError:
            mapping = {}
        self._cache[key] = mapping
        return mapping


def _cstring(image, rva: int, limit: int = 512) -> str:
    raw = image.read(rva, limit) or b""
    return raw.split(b"\x00", 1)[0].decode("latin-1", "replace")


def _import_descriptors(image, import_rva: int, import_size: int) -> list[dict]:
    descriptors = []
    offset = image.rva_to_file(import_rva)
    if offset is None:
        raise OmniError(f"import directory RVA 0x{import_rva:x} is not file-backed")
    raw = image.data
    for index in range(min(MAX_DESCRIPTORS, import_size // DESCRIPTOR_SIZE + 1)):
        entry_off = offset + index * DESCRIPTOR_SIZE
        if entry_off + DESCRIPTOR_SIZE > len(raw):
            break
        original, _stamp, _forward, name_rva, first = struct.unpack_from(
            "<IIIII", raw, entry_off
        )
        if not (original or name_rva or first):
            break
        descriptors.append(
            {"original": original, "name_rva": name_rva, "first_thunk": first}
        )
    return descriptors


def rebuild_imports(
    dump_path: str,
    out: str,
    dump_meta: str,
    max_thunks: int = MAX_THUNKS,
) -> dict:
    """Rebuild the import directory of a dumped PE from module metadata."""
    image = load(dump_path, "dump")
    meta_path = Path(dump_meta)
    if not meta_path.is_file():
        raise OmniError(f"dump metadata not found: {meta_path}")
    meta = json.loads(meta_path.read_text("utf-8"))
    modules = meta.get("modules") or []

    e_lfanew = u32(image.data, 0x3C)
    opt = e_lfanew + 24
    data_dir = opt + (0x60 if image.bits == 32 else 0x70)
    import_rva = u32(image.data, data_dir + IMPORT_DIR_INDEX * 8)
    import_size = u32(image.data, data_dir + IMPORT_DIR_INDEX * 8 + 4)
    if import_rva == 0 or import_size == 0:
        raise OmniError("dump has no import directory to rebuild")

    descriptors = _import_descriptors(image, import_rva, import_size)
    if not descriptors:
        raise OmniError("import descriptor list is empty")

    thunk_size = 8 if image.bits == 64 else 4
    exports = _ExportCache()
    warnings: list[str] = []
    unresolved = 0
    imported = 0
    unresolved_samples: list[dict] = []
    entries: list[dict] = []

    for descriptor in descriptors:
        dll_name = _cstring(image, descriptor["name_rva"]) if descriptor["name_rva"] else ""
        if not dll_name:
            warnings.append("descriptor without a module name skipped")
            continue
        thunks: list[tuple[str, object]] = []
        first = descriptor["first_thunk"]
        for index in range(max_thunks):
            raw = image.read(first + index * thunk_size, thunk_size)
            if not raw or len(raw) < thunk_size:
                break
            value = int.from_bytes(raw, "little")
            if value == 0:
                break
            module = _module_for(value, modules)
            if module is None:
                unresolved += 1
                if len(unresolved_samples) < 25:
                    unresolved_samples.append({"address": value, "module": None, "rva": None})
                thunks.append(("name", f"UNK_{value:x}"))
                continue
            module_path = _module_file(module)
            export_map = exports.get(module_path) if module_path else {}
            export_rva = value - int(module["base"])
            info = export_map.get(export_rva)
            if info is None:
                unresolved += 1
                if len(unresolved_samples) < 25:
                    unresolved_samples.append(
                        {
                            "address": value,
                            "module": module.get("name"),
                            "rva": export_rva,
                        }
                    )
                thunks.append(
                    ("name", f"UNK_{module.get('name', '?')}_{export_rva:x}")
                )
                continue
            name, ordinal = info
            if name:
                thunks.append(("name", name))
                imported += 1
            elif ordinal:
                thunks.append(("ordinal", ordinal))
                imported += 1
            else:
                unresolved += 1
                thunks.append(
                    ("name", f"UNK_{module.get('name', '?')}_{export_rva:x}")
                )
        entries.append({"dll": dll_name, "thunks": thunks})

    if not entries:
        raise OmniError("no usable import descriptors after resolution")

    # Layout: descriptors, INT arrays, hint/name entries, DLL names.
    # Offsets are payload-relative here; RVAs written into the image add
    # section_rva because PE descriptor and thunk fields demand absolute RVAs.
    position = DESCRIPTOR_SIZE * (len(entries) + 1)
    for entry in entries:
        entry["int_offset"] = position
        position += (len(entry["thunks"]) + 1) * thunk_size
    for entry in entries:
        entry["name_offsets"] = []
        for kind, value in entry["thunks"]:
            if kind != "name":
                entry["name_offsets"].append(None)
                continue
            entry["name_offsets"].append(position)
            position += align_up(2 + len(value) + 1, 2)
    for entry in entries:
        entry["dll_offset"] = position
        position += len(entry["dll"].encode("latin-1", "replace")) + 1

    section_rva = align_up(
        max((sec.va + sec.virtual_size for sec in image.sections), default=0x1000),
        image.section_align,
    )
    payload = bytearray(position)

    def write_offset(offset: int, data: bytes) -> None:
        payload[offset : offset + len(data)] = data

    for index, entry in enumerate(entries):
        struct.pack_into(
            "<IIIII",
            payload,
            index * DESCRIPTOR_SIZE,
            section_rva + entry["int_offset"],
            0,
            0,
            section_rva + entry["dll_offset"],
            section_rva + entry["int_offset"],
        )
        write_offset(entry["dll_offset"], entry["dll"].encode("latin-1", "replace") + b"\x00")
        for slot, (thunk, name_offset) in enumerate(
            zip(entry["thunks"], entry["name_offsets"])
        ):
            kind, value = thunk
            slot_offset = entry["int_offset"] + slot * thunk_size
            if kind == "name":
                write_offset(
                    slot_offset,
                    (section_rva + name_offset).to_bytes(thunk_size, "little"),
                )
                hint_name = b"\x00\x00" + value.encode("latin-1", "replace") + b"\x00"
                write_offset(name_offset, hint_name)
            else:
                ordinal_flag = (
                    0x8000000000000000 if thunk_size == 8 else 0x80000000
                )
                write_offset(
                    slot_offset,
                    (ordinal_flag | int(value)).to_bytes(thunk_size, "little"),
                )

    data = bytearray(image.data)
    file_align = image.file_align
    table = opt + u16(image.data, e_lfanew + 20)
    num_sections = u16(image.data, e_lfanew + 6)
    new_header = table + num_sections * 40
    first_raw = min(
        (sec.raw_ptr for sec in image.sections if sec.raw_ptr), default=len(data)
    )
    if new_header + 40 > first_raw:
        raise OmniError("no room for a new section header; rebuild the PE first")
    raw_ptr = align_up(len(data), file_align)
    raw_size = align_up(len(payload), file_align)
    data.extend(b"\x00" * (raw_ptr - len(data)))
    data.extend(payload)
    data.extend(b"\x00" * (raw_size - len(payload)))

    struct.pack_into(
        "<8sIIIIIIHHI",
        data,
        new_header,
        b".idata2",
        len(payload),
        section_rva,
        raw_size,
        raw_ptr,
        0,
        0,
        0,
        0,
        0xC0000040,
    )
    struct.pack_into("<H", data, e_lfanew + 6, num_sections + 1)
    struct.pack_into(
        "<I",
        data,
        opt + 0x38,
        align_up(section_rva + len(payload), image.section_align),
    )
    struct.pack_into(
        "<II",
        data,
        data_dir + IMPORT_DIR_INDEX * 8,
        section_rva,
        DESCRIPTOR_SIZE * (len(entries) + 1),
    )

    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_bytes(bytes(data))
    return {
        "input": str(dump_path),
        "output": str(out),
        "descriptors": len(entries),
        "imported_functions": imported,
        "unresolved": unresolved,
        "unresolved_samples": unresolved_samples,
        "warnings": warnings,
        "new_section_rva": section_rva,
        "new_section_size": len(payload),
    }
