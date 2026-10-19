from ih8sn1ff.flow import callgraph, xrefs_rip

from .test_pefix import make_tiny_pe


def _flow_fixture(tmp_path):
    data = bytearray(0x200)
    # 0x1000: lea rcx, [rip+0xF9] -> 0x1100 (string)
    data[0x00:0x07] = b"\x48\x8D\x0D\xF9\x00\x00\x00"
    # 0x1007: call 0x1020  (next ip 0x100C, rel = 0x14)
    data[0x07:0x0C] = b"\xE8\x14\x00\x00\x00"
    # 0x100C: ret
    data[0x0C] = 0xC3
    # 0x1020: ret
    data[0x20] = 0xC3
    # 0x1100: string
    data[0x100:0x10A] = b"RIP_TARGET"
    path = tmp_path / "flow.exe"
    path.write_bytes(make_tiny_pe(bytes(data), bits=64))
    return path


def test_xrefs_rip_finds_rip_relative_string(tmp_path):
    path = _flow_fixture(tmp_path)
    result = xrefs_rip(str(path), string="RIP_TARGET", layout="file")
    assert result["total"] >= 1
    hit = result["hits"][0]
    assert hit["kind"] == "rip"
    assert hit["rva"] == 0x1000
    assert hit["target_rva"] == 0x1100


def test_callgraph_follows_direct_call(tmp_path):
    path = _flow_fixture(tmp_path)
    result = callgraph(str(path), "0x1000", depth=1, layout="file")
    assert {"from": 0x1000, "to": 0x1020}.items() <= result["edges"][0].items()
    rvas = {node["rva"] for node in result["nodes"]}
    assert {0x1000, 0x1020} <= rvas
