import pytest

from ih8sn1ff.emulate import emulate

from .test_pefix import make_tiny_pe

pytest.importorskip("unicorn")


def _emu_fixture(tmp_path):
    data = bytearray(0x200)
    # 0x1000: mov eax, 1 ; nop ; ret
    data[0:7] = b"\xB8\x01\x00\x00\x00\x90\xC3"
    path = tmp_path / "emu.exe"
    path.write_bytes(make_tiny_pe(bytes(data)))
    return path


def test_emulate_executes_entry_and_records_registers(tmp_path):
    path = _emu_fixture(tmp_path)
    result = emulate(str(path), entry="0x1000", max_instructions=20, layout="file")
    assert result["trace"][0]["rva"] == 0x1000
    assert result["executed"] >= 3
    assert result["registers"].get("eax") == 1
    assert result["stop_reason"] in {"unmapped_memory", "instruction_limit", "emulation_error"}


def test_emulate_respects_instruction_budget(tmp_path):
    path = _emu_fixture(tmp_path)
    result = emulate(str(path), entry="0x1000", max_instructions=2, layout="file")
    assert result["executed"] == 2
    assert result["stop_reason"] == "instruction_limit"
