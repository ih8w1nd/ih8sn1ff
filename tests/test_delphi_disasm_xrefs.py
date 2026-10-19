import struct

from ih8sn1ff.delphi import delphi_methods
from ih8sn1ff.disasm import disasm
from ih8sn1ff.xrefs import xrefs

from .test_pefix import make_tiny_pe


def test_delphi_methods_inline_table(tmp_path):
    name = b"ErasePartition"
    code_rva = 0x1234
    buffer = bytearray(0x5000)
    entry_off = 0x100
    struct.pack_into("<I", buffer, entry_off, code_rva)
    buffer[entry_off + 4] = len(name)
    buffer[entry_off + 5 : entry_off + 5 + len(name)] = name
    dump = tmp_path / "dump.bin"
    dump.write_bytes(bytes(buffer))

    result = delphi_methods(str(dump), names=["ErasePartition"])
    assert result["resolved"] == 1
    row = result["methods"][0]
    assert row["code_rva"] == code_rva
    assert row["entry_offset"] == entry_off


def _pe_with_string_and_ref(tmp_path):
    data = bytearray(0x200)
    # mov eax, 0x300 ; string constant lives at file offset 0x300.
    data[0:5] = b"\xB8" + struct.pack("<I", 0x300)
    data[0x100:0x10A] = b"HELLO_XREF"
    pe = bytearray(make_tiny_pe(bytes(data)))
    path = tmp_path / "sample.exe"
    path.write_bytes(bytes(pe))
    return path


def test_disasm_annotates_string_refs(tmp_path):
    path = _pe_with_string_and_ref(tmp_path)
    result = disasm(str(path), "0x200", count=1)
    assert result["count"] == 1
    instruction = result["instructions"][0]
    assert instruction["text"].startswith("0x200:")
    assert instruction["comment"] == '"HELLO_XREF"'


def test_xrefs_finds_immediate(tmp_path):
    path = _pe_with_string_and_ref(tmp_path)
    result = xrefs(str(path), string="HELLO_XREF")
    assert result["total"] >= 1
    assert any(hit["ref_offset"] == 0x201 for hit in result["hits"])
