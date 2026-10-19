import pytest

from ih8sn1ff import evidence
from ih8sn1ff.yara_tool import yara_scan

yara = pytest.importorskip("yara")


def test_bundled_yara_profiles_match(tmp_path):
    sample = tmp_path / "packed.bin"
    sample.write_bytes(
        b"\x00.vmp0\x00IsDebuggerPresent\x00CheckRemoteDebuggerPresent\x00"
    )
    result = yara_scan(str(sample))
    names = {match["rule"] for match in result["matches"]}
    assert "Packer_VMProtect_Sections" in names
    assert "AntiDebug_Common_APIs" in names


def test_evidence_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("IH8SN1FF_EVIDENCE_DIR", str(tmp_path))
    entry = evidence.record("bin_info", {"path": "x"}, {"ok": True})
    listed = evidence.list_records(limit=5)
    assert listed["records"][0]["id"] == entry["id"]
    full = evidence.read_record(entry["id"])
    assert full["tool"] == "bin_info"
    assert full["result"] == {"ok": True}
