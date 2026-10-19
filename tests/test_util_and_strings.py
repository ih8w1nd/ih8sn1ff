import io
import zipfile

from ih8sn1ff.blobs import entropy_map, find_blobs
from ih8sn1ff.strings_scan import strings_scan
from ih8sn1ff.util import entropy, parse_int, parse_size


def test_parse_int_forms():
    assert parse_int("0x1A") == 26
    assert parse_int("26") == 26
    assert parse_int("-0x10") == -16
    assert parse_int(7) == 7


def test_parse_size_suffixes():
    assert parse_size("1M") == 1024 * 1024
    assert parse_size("16K") == 16 * 1024
    assert parse_size("0x2000") == 0x2000


def test_entropy_extremes():
    assert entropy(b"") == 0.0
    assert entropy(b"\x00" * 4096) == 0.0
    assert entropy(bytes(range(256)) * 4) > 7.9


def test_strings_ascii_and_utf16(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x00\x00HelloWorld\x00" + "Secret".encode("utf-16le") + b"\x00")
    ascii_hits = strings_scan(str(target), encoding="ascii")
    assert any(m["text"] == "HelloWorld" for m in ascii_hits["matches"])
    utf16_hits = strings_scan(str(target), encoding="utf16")
    assert any(m["text"] == "Secret" for m in utf16_hits["matches"])
    filtered = strings_scan(str(target), regex="^Hello", encoding="ascii")
    assert filtered["total"] == 1


def test_entropy_map_windows(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x00" * 2048 + bytes(range(256)) * 8)
    result = entropy_map(str(target), window=2048)
    assert len(result["windows"]) == 2
    assert result["windows"][0]["entropy"] == 0.0
    assert result["windows"][1]["packed"] is True


def test_find_blobs_carves_zip(tmp_path):
    archive = tmp_path / "embedded.bin"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("a.txt", "hello")
    archive.write_bytes(b"\x00" * 100 + buffer.getvalue())
    result = find_blobs(str(archive), kind="zip")
    assert result["count"] >= 1
    assert result["blobs"][0]["offset"] == 100
