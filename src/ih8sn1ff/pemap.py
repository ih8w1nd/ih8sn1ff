"""Shared PE layout mapping used by flow, emulation and import tools.

All analysis tools work in RVA space. A *dump* image is a snapshot that starts
at the module base, so inside it ``file offset == RVA``. A *file* image is a
normal on-disk PE where raw sections are chained after the headers and RVAs
must be translated through the section table.
"""

from __future__ import annotations

from dataclasses import dataclass

from .util import OmniError, read_file, u16, u32, u64

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


@dataclass
class Section:
    name: str
    va: int
    vsize: int
    raw_ptr: int
    raw_size: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_WRITE)

    @property
    def virtual_size(self) -> int:
        return max(self.vsize, self.raw_size)


@dataclass
class Image:
    path: str
    data: bytes
    layout: str
    image_base: int
    entry_rva: int
    size_image: int
    section_align: int
    file_align: int
    bits: int
    sections: list[Section]

    def rva_to_file(self, rva: int) -> int | None:
        if self.layout == "dump":
            return rva if 0 <= rva < len(self.data) else None
        for sec in self.sections:
            if sec.va <= rva < sec.va + sec.virtual_size:
                delta = rva - sec.va
                if delta < sec.raw_size:
                    offset = sec.raw_ptr + delta
                    return offset if offset < len(self.data) else None
        return None

    def file_to_rva(self, offset: int) -> int | None:
        if self.layout == "dump":
            return offset if 0 <= offset < len(self.data) else None
        for sec in self.sections:
            if sec.raw_ptr <= offset < sec.raw_ptr + sec.raw_size:
                return sec.va + (offset - sec.raw_ptr)
        return None

    def read(self, rva: int, size: int) -> bytes | None:
        offset = self.rva_to_file(rva)
        if offset is None:
            return None
        return self.data[offset : offset + size]

    def in_exec_rva(self, rva: int) -> bool:
        return any(
            sec.executable and sec.va <= rva < sec.va + sec.virtual_size
            for sec in self.sections
        )

    def exec_sections(self):
        for sec in self.sections:
            if not sec.executable or sec.virtual_size == 0:
                continue
            offset = self.rva_to_file(sec.va)
            if offset is None:
                continue
            length = (
                sec.vsize if self.layout == "dump" and sec.vsize else sec.raw_size
            )
            yield sec, self.data[offset : offset + length]


def normalize_rva(image: Image, value: int) -> int:
    """Accept either an RVA or a full VA and return the RVA."""
    return value - image.image_base if value >= image.image_base else value


def load(path: str, layout: str = "auto") -> Image:
    """Parse a PE and return its mapping. ``layout``: auto, dump or file."""
    data = read_file(path)
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise OmniError("pemap supports PE images only (missing MZ)")
    e_lfanew = u32(data, 0x3C)
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise OmniError("not a PE (missing PE signature)")
    coff = e_lfanew + 4
    num_sections = u16(data, coff + 2)
    opt_size = u16(data, coff + 16)
    opt = coff + 20
    magic = u16(data, opt)
    if magic not in (0x10B, 0x20B):
        raise OmniError(f"unsupported optional header magic {hex(magic)}")
    bits = 64 if magic == 0x20B else 32
    image_base = u64(data, opt + 0x18) if bits == 64 else u32(data, opt + 0x1C)
    section_align = u32(data, opt + 0x20) or 0x1000
    file_align = u32(data, opt + 0x24) or 0x200
    entry_rva = u32(data, opt + 0x10)
    size_image = u32(data, opt + 0x38)
    table = opt + opt_size
    sections: list[Section] = []
    for i in range(num_sections):
        hdr = table + i * 40
        sections.append(
            Section(
                name=data[hdr : hdr + 8].rstrip(b"\x00").decode("latin-1", "replace"),
                vsize=u32(data, hdr + 8),
                va=u32(data, hdr + 12),
                raw_size=u32(data, hdr + 16),
                raw_ptr=u32(data, hdr + 20),
                characteristics=u32(data, hdr + 36),
            )
        )
    if layout == "auto":
        layout = "dump" if len(data) >= size_image else "file"
    if layout not in {"dump", "file"}:
        raise OmniError("layout must be auto, dump or file")
    return Image(
        path=str(path),
        data=data,
        layout=layout,
        image_base=image_base,
        entry_rva=entry_rva,
        size_image=size_image,
        section_align=section_align,
        file_align=file_align,
        bits=bits,
        sections=sections,
    )
