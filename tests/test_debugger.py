import os
import sys

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="live debugging is Windows-only")


def test_debugger_stops_at_entry_and_reads_state():
    from ih8sn1ff.debugger import (
        debug_close,
        debug_launch,
        debug_read_memory,
        debug_registers,
    )

    result = debug_launch(
        sys.executable,
        args=["-c", "import time; time.sleep(3)"],
        stop_at_entry=True,
        timeout_ms=20000,
    )
    try:
        assert result["state"] == "breakpoint", result
        assert result["errors"] == []
        hit = result["event"]["address"]
        registers = debug_registers(result["session_id"])["registers"]
        assert registers["rip"] == hit
        memory = debug_read_memory(result["session_id"], hit, 4)["hex"]
        assert len(memory) == 8
    finally:
        debug_close(result["session_id"])


def test_debugger_supports_wow64_x86_target():
    from ih8sn1ff.debugger import debug_close, debug_launch, debug_registers
    from ih8sn1ff.pemap import load

    target = r"C:/Windows/SysWOW64/cmd.exe"
    if not os.path.isfile(target):
        pytest.skip("WOW64 cmd.exe not present")
    if load(target, "file").bits != 32:
        pytest.skip("target is not a 32-bit image")
    result = debug_launch(
        target,
        args=["/c", "exit"],
        stop_at_entry=True,
        timeout_ms=20000,
    )
    try:
        assert result["state"] == "breakpoint", result
        hit = result["event"]["address"]
        registers = debug_registers(result["session_id"])["registers"]
        assert registers["eip"] == hit
    finally:
        debug_close(result["session_id"])
