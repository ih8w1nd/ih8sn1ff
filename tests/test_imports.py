import os
import subprocess
import sys

import pytest

from ih8sn1ff.imports import rebuild_imports

pytestmark = pytest.mark.skipif(os.name != "nt", reason="process dump is Windows-only")


def test_rebuild_imports_from_own_process_dump(tmp_path):
    from ih8sn1ff.dumpwin import dump_process

    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(6)"])
    try:
        import time

        time.sleep(0.8)
        dump = dump_process(child.pid, outdir=str(tmp_path / "dump"))
        main_module = next(m for m in dump["modules"] if m["main"])
        assert dump["meta_file"]
        out = tmp_path / "rebuilt_imports.exe"
        result = rebuild_imports(main_module["file"], str(out), dump["meta_file"])
        assert result["descriptors"] >= 1
        assert result["imported_functions"] >= 1
        assert out.is_file() and out.stat().st_size > 0

        import pefile

        pe = pefile.PE(str(out), fast_load=False)
        assert hasattr(pe, "DIRECTORY_ENTRY_IMPORT")
        names = {
            entry.dll.decode("utf-8", "replace").casefold()
            for entry in pe.DIRECTORY_ENTRY_IMPORT
        }
        assert names
    finally:
        child.terminate()
