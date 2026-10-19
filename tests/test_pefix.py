import struct

from ih8sn1ff.pefix import _parse_pe, rebuild_pe, trim_pe


def make_tiny_pe(section_data: bytes = b"\x90" * 0x200, bits: int = 32) -> bytes:
    """Minimal valid PE with one .text section (VA 0x1000)."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    if bits == 64:
        coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x0102)
        opt = bytearray(0xF0)
        struct.pack_into("<H", opt, 0, 0x20B)
        struct.pack_into("<Q", opt, 0x18, 0x140000000)  # image base (PE32+)
    else:
        coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
        opt = bytearray(0xE0)
        struct.pack_into("<H", opt, 0, 0x10B)
        struct.pack_into("<I", opt, 0x1C, 0x400000)    # image base (PE32)
    struct.pack_into("<I", opt, 0x10, 0x1000)          # entry
    struct.pack_into("<I", opt, 0x20, 0x1000)          # section align
    struct.pack_into("<I", opt, 0x24, 0x200)           # file align
    struct.pack_into("<I", opt, 0x38, 0x2000)          # size of image
    struct.pack_into("<I", opt, 0x3C, 0x200)           # size of headers
    section = struct.pack(
        "<8sIIIIIIHHI", b".text", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020
    )
    header = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + section
    return header + b"\x00" * (0x200 - len(header)) + section_data


def make_memory_image(pe: bytes, vsize: int = 0x200) -> bytes:
    image = bytearray(0x1000 + vsize)
    image[0:0x200] = pe[0:0x200]
    image[0x1000 : 0x1000 + 0x200] = pe[0x200:0x400]
    return bytes(image)


def test_rebuild_pe_unchains_sections(tmp_path):
    pe = make_tiny_pe()
    image_path = tmp_path / "main.bin"
    image_path.write_bytes(make_memory_image(pe))
    out = tmp_path / "rebuilt.exe"
    result = rebuild_pe(str(image_path), str(out))
    assert result["output_size"] > 0x200
    rebuilt = out.read_bytes()
    layout = _parse_pe(rebuilt)
    section = layout["sections"][0]
    assert section["raw_ptr"] == 0x200
    assert section["raw_size"] == 0x200
    assert rebuilt[0x200:0x210] == b"\x90" * 0x10
    assert layout["size_headers"] == 0x200


def test_trim_pe_cuts_huge_sections(tmp_path):
    section_data = b"\xCC" * 0x400
    pe = make_tiny_pe(section_data)
    # Rewrite the section header to look like a 0x20000000-byte protector arena.
    patched = bytearray(pe)
    layout_in = _parse_pe(bytes(patched))
    header_off = layout_in["sections"][0]["header_off"]
    struct.pack_into("<I", patched, header_off + 8, 0x20000000)
    image_path = tmp_path / "main.bin"
    image = bytearray(0x1000 + 0x400)
    image[0:0x200] = patched[0:0x200]
    image[0x1000:0x1400] = section_data
    image_path.write_bytes(bytes(image))
    rebuilt = tmp_path / "rebuilt.exe"
    rebuild_pe(str(image_path), str(rebuilt))

    trimmed_path = tmp_path / "trimmed.exe"
    result = trim_pe(
        str(rebuilt), str(trimmed_path), scratch_prefix_end=0x800, huge_section_threshold=0x1000
    )
    # Arena starts at VA 0x1000, past the 0x800 prefix end: fully trimmed.
    section = result["sections"][0]
    assert section["trimmed"] is True
    assert section["new_vsize"] == 0x1000
    assert result["output_size"] < len(rebuilt.read_bytes())
    layout = _parse_pe(trimmed_path.read_bytes())
    assert layout["entry_rva"] == 0x1000
