"""Binary metadata for PE and ELF files.

PE goes through ``pefile``; ELF uses ``pyelftools`` when installed and
degrades to header-only facts otherwise. All outputs are plain dicts so both
the MCP layer and the CLI can serialize them unchanged.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

from .util import OmniError, entropy, read_file, u16, u32

MACHINES = {
    0x14C: "x86",
    0x8664: "x86_64",
    0xAA64: "arm64",
    0x1C0: "arm",
    0x1C4: "armnt",
    0x200: "ia64",
}

STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".bss", ".rsrc", ".reloc", ".tls", ".pdata",
    ".idata", ".edata", ".didat", ".gfids", ".00cfg", ".CRT", ".debug",
}


def _pe_info(data: bytes, path: str) -> dict:
    import pefile

    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        raise OmniError(f"not a valid PE: {exc}") from exc

    ts = getattr(pe.FILE_HEADER, "TimeDateStamp", 0)
    try:
        compiled = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        compiled = None

    sections = []
    hints: list[str] = []
    for sec in pe.sections:
        name = sec.Name.rstrip(b"\x00").decode("latin-1", "replace")
        raw = sec.SizeOfRawData
        virt = sec.Misc_VirtualSize
        ent = round(entropy(sec.get_data()[: min(virt, 8 * 1024 * 1024)]), 3) if raw else 0.0
        executable = bool(sec.Characteristics & 0x20000000)
        sections.append(
            {
                "name": name,
                "va": sec.VirtualAddress,
                "vsize": virt,
                "raw_size": raw,
                "raw_ptr": sec.PointerToRawData,
                "entropy": ent,
                "executable": executable,
            }
        )
        if name not in STANDARD_SECTIONS and name.strip():
            hints.append(f"non-standard section name {name!r}")
        if ent >= 7.85 and raw > 0x2000:
            hints.append(f"high entropy in {name!r} ({ent})")
        if raw == 0 and virt > 0x10000:
            hints.append(f"virtual-only section {name!r} (loader materializes it)")

    is_dotnet = False
    try:
        is_dotnet = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0
    except (IndexError, AttributeError):
        pass

    return {
        "path": path,
        "format": "PE",
        "machine": MACHINES.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)),
        "image_base": pe.OPTIONAL_HEADER.ImageBase,
        "entry_rva": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "size_of_image": pe.OPTIONAL_HEADER.SizeOfImage,
        "file_alignment": pe.OPTIONAL_HEADER.FileAlignment,
        "section_alignment": pe.OPTIONAL_HEADER.SectionAlignment,
        "compiled_utc": compiled,
        "dotnet": is_dotnet,
        "sections": sections,
        "size": len(data),
        "packer_hints": hints,
    }


def _elf_info(data: bytes, path: str) -> dict:
    info: dict = {
        "path": path,
        "format": "ELF",
        "class": "64-bit" if data[4] == 2 else "32-bit",
        "endian": "little" if data[5] == 1 else "big",
        "size": len(data),
    }
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore
    except ImportError:
        info["note"] = "install ih8sn1ff[elf] (pyelftools) for full ELF metadata"
        return info
    import io

    with ELFFile(io.BytesIO(data)) as elf:  # type: ignore[attr-defined]
        info["machine"] = elf.get_machine_arch()
        info["entry"] = elf.header.e_entry
        sections = []
        for sec in elf.iter_sections():
            if not sec["sh_size"]:
                continue
            chunk = sec.data()[: min(sec["sh_size"], 8 * 1024 * 1024)]
            sections.append(
                {
                    "name": sec.name,
                    "addr": sec["sh_addr"],
                    "size": sec["sh_size"],
                    "offset": sec["sh_offset"],
                    "entropy": round(entropy(chunk), 3),
                }
            )
        info["sections"] = sections
        if not sections:
            # Firmware loaders are frequently section-stripped; fall back to
            # PT_LOAD program headers so the layout is still visible.
            segments = []
            for seg in elf.iter_segments():
                if seg["p_type"] != "PT_LOAD":
                    continue
                chunk = seg.data()[: min(seg["p_filesz"], 8 * 1024 * 1024)]
                segments.append(
                    {
                        "type": "PT_LOAD",
                        "vaddr": seg["p_vaddr"],
                        "offset": seg["p_offset"],
                        "filesz": seg["p_filesz"],
                        "memsz": seg["p_memsz"],
                        "entropy": round(entropy(chunk), 3),
                    }
                )
            info["segments"] = segments
    return info


def bin_info(path: str) -> dict:
    """Return format, arch, sections, entropy and packer hints for a binary."""
    data = read_file(path)
    if len(data) < 0x40:
        raise OmniError("file too small to be a binary")
    if data[:2] == b"MZ":
        return _pe_info(data, str(Path(path)))
    if data[:4] == b"\x7fELF":
        return _elf_info(data, str(Path(path)))
    raise OmniError("unsupported format (expected PE 'MZ' or ELF magic)")


def pe_bits(path: str) -> int | None:
    """Return 32/64 for PE files, None otherwise."""
    try:
        data = read_file(path)
    except OmniError:
        return None
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    e_lfanew = u32(data, 0x3C)
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    magic = u16(data, e_lfanew + 24)
    return 64 if magic == 0x20B else 32
