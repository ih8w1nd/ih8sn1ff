"""Windows process/module memory dumping — the runtime unpacking primitive.

Dumps start at each module base, so inside a dump file ``offset == RVA``.
Works on an already-running PID (``dump_process``) or launches the target and
snapshots it (``run_and_dump``). Elevated targets require an elevated host.
"""

from __future__ import annotations

import ctypes
import json
import os
import time
from pathlib import Path

from .util import OmniError

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_TERMINATE = 0x0001
LIST_MODULES_ALL = 0x03
TH32CS_SNAPPROCESS = 0x00000002

if os.name == "nt":  # pragma: no cover - Windows-only paths
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _psapi = ctypes.WinDLL("psapi", use_last_error=True)
    _shell32 = ctypes.WinDLL("shell32", use_last_error=True)

    class MODULEINFO(ctypes.Structure):
        _fields_ = [
            ("lpBaseOfDll", ctypes.c_void_p),
            ("SizeOfImage", wintypes.DWORD),
            ("EntryPoint", ctypes.c_void_p),
        ]

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    # Explicit signatures: without them ctypes converts handles and module
    # pointers through a 32-bit default and overflows on x64.
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    _kernel32.ReadProcessMemory.restype = wintypes.BOOL
    _kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _kernel32.TerminateProcess.restype = wintypes.BOOL
    _kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    _kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    _kernel32.Process32FirstW.restype = wintypes.BOOL
    _kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    _kernel32.Process32NextW.restype = wintypes.BOOL
    _kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    _kernel32.GetProcessTimes.restype = wintypes.BOOL
    _psapi.EnumProcessModulesEx.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_void_p),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.DWORD,
    ]
    _psapi.EnumProcessModulesEx.restype = wintypes.BOOL
    _psapi.GetModuleInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(MODULEINFO),
        wintypes.DWORD,
    ]
    _psapi.GetModuleInformation.restype = wintypes.BOOL
    _psapi.GetModuleBaseNameW.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    _psapi.GetModuleBaseNameW.restype = wintypes.DWORD
    _psapi.GetModuleFileNameExW.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    _psapi.GetModuleFileNameExW.restype = wintypes.DWORD
    _shell32.ShellExecuteW.argtypes = [
        wintypes.HWND,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_int,
    ]
    _shell32.ShellExecuteW.restype = wintypes.HINSTANCE


def _require_windows() -> None:
    if os.name != "nt":
        raise OmniError("process dumping is Windows-only")


def _is_system_module_path(path: str) -> bool:
    """True only for modules under %SystemRoot%, not any 'windows' segment.

    GitHub's Windows runners place Python under
    ``C:\\hostedtoolcache\\windows\\...``; a naive ``\\windows\\`` substring
    check would wrongly skip the target executable there.
    """
    if not path:
        return False
    lowered = path.replace("/", "\\").casefold().strip()
    lowered = lowered.removeprefix("\\\\?\\")
    system_root = (
        os.environ.get("SystemRoot", r"C:\Windows")
        .replace("/", "\\")
        .casefold()
        .rstrip("\\")
    )
    return lowered.startswith(system_root + "\\")


def _open_process(pid: int, access: int):
    handle = _kernel32.OpenProcess(access, False, pid)  # type: ignore[attr-defined]
    if not handle:
        err = ctypes.get_last_error()  # type: ignore[attr-defined]
        if err == 5:
            raise OmniError(
                f"access denied opening PID {pid} — target is elevated; "
                "run ih8Sn1ff (MCP server) elevated and retry"
            )
        raise OmniError(f"OpenProcess(PID {pid}) failed with error {err}")
    return handle


def _process_image_path(pid: int) -> str | None:
    handle = None
    try:
        handle = _open_process(pid, PROCESS_QUERY_INFORMATION)
        buf = ctypes.create_unicode_buffer(32768)  # type: ignore[attr-defined]
        size = ctypes.c_ulong(len(buf))  # type: ignore[attr-defined]
        if _kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):  # type: ignore[attr-defined]
            return buf.value
    except OmniError:
        return None
    finally:
        if handle:
            _kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
    return None


def _find_pid_by_name(exe_name: str, created_after: float | None) -> int | None:
    snapshot = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)  # type: ignore[attr-defined]
    if not snapshot:
        return None
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)  # type: ignore[attr-defined]
    newest: tuple[float, int] | None = None
    try:
        ok = _kernel32.Process32FirstW(snapshot, ctypes.byref(entry))  # type: ignore[attr-defined]
        while ok:
            if entry.szExeFile.casefold() == exe_name.casefold():
                handle = _kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, entry.th32ProcessID)  # type: ignore[attr-defined]
                if handle:
                    created = [wintypes.FILETIME(), wintypes.FILETIME(),
                               wintypes.FILETIME(), wintypes.FILETIME()]
                    if _kernel32.GetProcessTimes(  # type: ignore[attr-defined]
                        handle,
                        ctypes.byref(created[0]),
                        ctypes.byref(created[1]),
                        ctypes.byref(created[2]),
                        ctypes.byref(created[3]),
                    ):
                        ts = (
                            (created[0].dwHighDateTime << 32) | created[0].dwLowDateTime
                        ) / 10_000_000 - 11644473600
                        recent = created_after is None or ts >= created_after - 2
                        if recent and (newest is None or ts > newest[0]):
                            newest = (ts, entry.th32ProcessID)
                    _kernel32.CloseHandle(handle)  # type: ignore[attr-defined]
            ok = _kernel32.Process32NextW(snapshot, ctypes.byref(entry))  # type: ignore[attr-defined]
    finally:
        _kernel32.CloseHandle(snapshot)  # type: ignore[attr-defined]
    return newest[1] if newest else None


def _terminate(pid: int) -> None:
    handle = None
    try:
        handle = _kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)  # type: ignore[attr-defined]
        if handle:
            _kernel32.TerminateProcess(handle, 1)  # type: ignore[attr-defined]
    except OSError:
        # Best-effort: the target may already have exited.
        return
    finally:
        if handle:
            _kernel32.CloseHandle(handle)  # type: ignore[attr-defined]


def _read_memory(handle, base: int, size: int) -> tuple[bytes, int]:
    """Read ``size`` bytes; returns (data, failed_chunk_count)."""
    chunk = 1024 * 1024
    out = bytearray()
    failed = 0
    offset = 0
    while offset < size:
        want = min(chunk, size - offset)
        buf = ctypes.create_string_buffer(want)  # type: ignore[attr-defined]
        got = ctypes.c_size_t(0)  # type: ignore[attr-defined]
        ok = _kernel32.ReadProcessMemory(  # type: ignore[attr-defined]
            handle,
            ctypes.c_void_p(base + offset),
            ctypes.cast(buf, ctypes.c_void_p),  # type: ignore[attr-defined]
            want,
            ctypes.byref(got),
        )
        if ok and got.value:
            out.extend(buf.raw[: got.value])
            offset += got.value
        else:
            failed += 1
            out.extend(b"\x00" * want)
            offset += want
    return bytes(out), failed


def dump_process(
    pid: int,
    outdir: str = "dumps",
    include_main: bool = True,
    skip_system: bool = True,
) -> dict:
    """Snapshot every module image of a running process into ``outdir``."""
    _require_windows()
    pid = int(pid)
    if pid <= 0:
        raise OmniError("pid must be positive")

    handle = _open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    exe_path = _process_image_path(pid)
    target = Path(outdir)
    target.mkdir(parents=True, exist_ok=True)

    modules: list[dict] = []
    log_lines: list[str] = []
    try:
        count = 1024
        arr = (ctypes.c_void_p * count)()  # type: ignore[attr-defined]
        needed = ctypes.c_ulong(0)  # type: ignore[attr-defined]
        if not _psapi.EnumProcessModulesEx(  # type: ignore[attr-defined]
            handle, arr, ctypes.sizeof(arr), ctypes.byref(needed), LIST_MODULES_ALL
        ):
            err = ctypes.get_last_error()  # type: ignore[attr-defined]
            raise OmniError(f"EnumProcessModulesEx failed (error {err})")

        total = min(needed.value // ctypes.sizeof(ctypes.c_void_p), count)  # type: ignore[attr-defined]
        index = 0
        all_modules: list[dict] = []
        for i in range(total):
            hmod = arr[i]
            info = MODULEINFO()
            if not _psapi.GetModuleInformation(  # type: ignore[attr-defined]
                handle, hmod, ctypes.byref(info), ctypes.sizeof(info)  # type: ignore[attr-defined]
            ):
                continue
            base = int(info.lpBaseOfDll or 0)
            size = int(info.SizeOfImage)
            if base == 0 or size == 0:
                continue

            name_buf = ctypes.create_unicode_buffer(260)  # type: ignore[attr-defined]
            _psapi.GetModuleBaseNameW(handle, hmod, name_buf, len(name_buf))  # type: ignore[attr-defined]
            path_buf = ctypes.create_unicode_buffer(32768)  # type: ignore[attr-defined]
            _psapi.GetModuleFileNameExW(handle, hmod, path_buf, len(path_buf))  # type: ignore[attr-defined]
            mod_name = name_buf.value or f"module_{i}"
            mod_path = path_buf.value

            is_main = bool(exe_path and mod_path and mod_path.casefold() == exe_path.casefold())
            meta = {
                "name": mod_name,
                "path": mod_path,
                "base": base,
                "size": size,
                "main": is_main,
                "dumped": False,
                "file": None,
            }
            all_modules.append(meta)
            if is_main and not include_main:
                continue
            if skip_system and _is_system_module_path(mod_path):
                continue

            data, failed = _read_memory(handle, base, size)
            safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in mod_name)
            out_path = target / f"{index:02d}_{safe_name}.bin"
            out_path.write_bytes(data)
            meta.update({"dumped": True, "file": str(out_path), "failed_chunks": failed})
            modules.append(meta)
            log_lines.append(
                f"{index:02d} base=0x{base:x} size=0x{size:x} read={len(data)} "
                f"failed={failed} path={mod_path} name={mod_name}"
            )
            index += 1
    finally:
        _kernel32.CloseHandle(handle)  # type: ignore[attr-defined]

    (target / "dump_log.txt").write_text("\n".join(log_lines) + "\n", "utf-8")
    meta_path = target / "dump_meta.json"
    meta_path.write_text(
        json.dumps({"pid": pid, "exe": exe_path, "modules": all_modules}, indent=2),
        "utf-8",
    )
    return {
        "pid": pid,
        "exe": exe_path,
        "outdir": str(target),
        "module_count": len(modules),
        "module_metadata_count": len(all_modules),
        "total_bytes": sum(m["size"] for m in modules),
        "modules": modules,
        "meta_file": str(meta_path),
    }


def run_and_dump(
    exe: str,
    wait_ms: int = 15000,
    outdir: str = "dumps",
    elevated: bool = True,
    args: list[str] | None = None,
    include_main: bool = True,
    skip_system: bool = True,
) -> dict:
    """Launch a target, wait, snapshot its modules, then terminate it."""
    _require_windows()
    exe_path = Path(exe)
    if not exe_path.is_file():
        raise OmniError(f"executable not found: {exe_path}")
    exe_path = exe_path.resolve()
    arg_list = list(args or [])
    wait_s = max(0.0, wait_ms / 1000.0)

    if elevated:
        start_marker = time.time()
        params = " ".join(f'"{a}"' for a in arg_list)
        rc = _shell32.ShellExecuteW(None, "runas", str(exe_path), params, None, 1)  # type: ignore[attr-defined]
        rc_value = int(rc or 0)
        if rc_value <= 32:
            raise OmniError(f"ShellExecuteW(runas) failed with code {rc_value}")
        deadline = start_marker + wait_s
        pid = None
        while time.time() < deadline:
            pid = _find_pid_by_name(exe_path.name, start_marker)
            if pid:
                break
            time.sleep(0.25)
        if not pid:
            raise OmniError("target did not appear after elevation (UAC declined or slow start)")
        remaining = deadline - time.time()
        if remaining > 0:
            time.sleep(remaining)
    else:
        import subprocess

        proc = subprocess.Popen([str(exe_path), *arg_list])
        pid = proc.pid
        try:
            proc.wait(timeout=wait_s)
        except subprocess.TimeoutExpired:
            pass

    try:
        result = dump_process(
            pid, outdir=outdir, include_main=include_main, skip_system=skip_system
        )
    finally:
        _terminate(pid)
    result["launched"] = str(exe_path)
    return result
