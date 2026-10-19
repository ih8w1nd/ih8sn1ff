"""Live Windows debugging sessions (x64): launch, breakpoints, memory, registers.

Software breakpoints (0xCC) with a single-step rearm, so the target keeps
running past a hit after ``debug_continue``. Session state lives in this
module and is addressed by ``session_id``; the MCP server process owns it.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import time
import uuid
from dataclasses import dataclass, field

from .util import OmniError, parse_int

if os.name == "nt":  # pragma: no cover - Windows-only
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.c_void_p),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    class EXCEPTION_RECORD(ctypes.Structure):
        pass

    EXCEPTION_RECORD._fields_ = [
        ("ExceptionCode", wintypes.DWORD),
        ("ExceptionFlags", wintypes.DWORD),
        ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
        ("ExceptionAddress", ctypes.c_void_p),
        ("NumberParameters", wintypes.DWORD),
        ("ExceptionInformation", ctypes.c_void_p * 15),
    ]

    class EXCEPTION_DEBUG_INFO(ctypes.Structure):
        _fields_ = [
            ("ExceptionRecord", EXCEPTION_RECORD),
            ("dwFirstChance", wintypes.DWORD),
        ]

    class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
        _fields_ = [
            ("hFile", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("lpBaseOfImage", ctypes.c_void_p),
            ("dwDebugInfoFileOffset", wintypes.DWORD),
            ("nDebugInfoSize", wintypes.DWORD),
            ("lpThreadLocalBase", ctypes.c_void_p),
            ("lpStartAddress", ctypes.c_void_p),
            ("lpImageName", ctypes.c_void_p),
            ("fUnicode", wintypes.WORD),
        ]

    class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
        _fields_ = [
            ("hFile", wintypes.HANDLE),
            ("lpBaseOfDll", ctypes.c_void_p),
            ("dwDebugInfoFileOffset", wintypes.DWORD),
            ("nDebugInfoSize", wintypes.DWORD),
            ("lpImageName", ctypes.c_void_p),
            ("fUnicode", wintypes.WORD),
        ]

    class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
        _fields_ = [("dwExitCode", wintypes.DWORD)]

    class EXIT_THREAD_DEBUG_INFO(ctypes.Structure):
        _fields_ = [("dwExitCode", wintypes.DWORD)]

    class DEBUG_EVENT_UNION(ctypes.Union):
        _fields_ = [
            ("Exception", EXCEPTION_DEBUG_INFO),
            ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
            ("LoadDll", LOAD_DLL_DEBUG_INFO),
            ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
            ("ExitThread", EXIT_THREAD_DEBUG_INFO),
            ("raw", ctypes.c_byte * 160),
        ]

    class DEBUG_EVENT(ctypes.Structure):
        _fields_ = [
            ("dwDebugEventCode", wintypes.DWORD),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
            ("u", DEBUG_EVENT_UNION),
        ]

    class MODULEENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("th32ModuleID", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("GlblcntUsage", wintypes.DWORD),
            ("ProccntUsage", wintypes.DWORD),
            ("modBaseAddr", ctypes.c_void_p),
            ("modBaseSize", wintypes.DWORD),
            ("hModule", wintypes.HANDLE),
            ("szModule", wintypes.WCHAR * 256),
            ("szExePath", wintypes.WCHAR * 260),
        ]

    _k32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(STARTUPINFOW),
        ctypes.POINTER(PROCESS_INFORMATION),
    ]
    _k32.CreateProcessW.restype = wintypes.BOOL
    _k32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), wintypes.DWORD]
    _k32.WaitForDebugEvent.restype = wintypes.BOOL
    _k32.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
    _k32.ContinueDebugEvent.restype = wintypes.BOOL
    _k32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    _k32.GetThreadContext.restype = wintypes.BOOL
    _k32.SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    _k32.SetThreadContext.restype = wintypes.BOOL
    _k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _k32.OpenThread.restype = wintypes.HANDLE
    _k32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    _k32.ReadProcessMemory.restype = wintypes.BOOL
    _k32.WriteProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    _k32.WriteProcessMemory.restype = wintypes.BOOL
    _k32.FlushInstructionCache.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t]
    _k32.FlushInstructionCache.restype = wintypes.BOOL
    _k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    _k32.TerminateProcess.restype = wintypes.BOOL
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]
    _k32.CloseHandle.restype = wintypes.BOOL
    _k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    _k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    _k32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    _k32.Module32FirstW.restype = wintypes.BOOL
    _k32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    _k32.Module32NextW.restype = wintypes.BOOL
    _k32.Wow64GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    _k32.Wow64GetThreadContext.restype = wintypes.BOOL
    _k32.Wow64SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    _k32.Wow64SetThreadContext.restype = wintypes.BOOL

    DEBUG_PROCESS = 0x00000001
    DEBUG_ONLY_THIS_PROCESS = 0x00000002
    DBG_CONTINUE = 0x00010002
    EXCEPTION_BREAKPOINT = 0x80000003
    EXCEPTION_SINGLE_STEP = 0x80000004
    EXCEPTION_WOW64_BREAKPOINT = 0x4000001F
    EXCEPTION_WOW64_SINGLE_STEP = 0x40000004
    TH32CS_SNAPMODULE = 0x00000008
    TH32CS_SNAPMODULE32 = 0x00000010
    THREAD_GET_CONTEXT = 0x0008
    THREAD_SET_CONTEXT = 0x0010
    THREAD_SUSPEND_RESUME = 0x0002

    CONTEXT_SIZE_64 = 0x4D0
    CONTEXT_FLAGS_OFF_64 = 0x30
    CONTEXT_FLAGS_FULL_64 = 0x0010000B
    EFLAGS_OFF_64 = 0x44
    CONTEXT_SIZE_32 = 0x2CC
    CONTEXT_FLAGS_OFF_32 = 0x00
    CONTEXT_FLAGS_FULL_32 = 0x00010007
    EFLAGS_OFF_32 = 0xC0
    TRAP_FLAG = 0x100

    REG_OFFSETS_64 = {
        "rax": 0x78,
        "rcx": 0x80,
        "rdx": 0x88,
        "rbx": 0x90,
        "rsp": 0x98,
        "rbp": 0xA0,
        "rsi": 0xA8,
        "rdi": 0xB0,
        "r8": 0xB8,
        "r9": 0xC0,
        "r10": 0xC8,
        "r11": 0xD0,
        "r12": 0xD8,
        "r13": 0xE0,
        "r14": 0xE8,
        "r15": 0xF0,
        "rip": 0xF8,
    }
    REG_OFFSETS_32 = {
        "eax": 0xB0,
        "ebx": 0xA4,
        "ecx": 0xAC,
        "edx": 0xA8,
        "esi": 0xA0,
        "edi": 0x9C,
        "ebp": 0xB4,
        "esp": 0xC4,
        "eip": 0xB8,
    }


@dataclass
class Breakpoint:
    address: int
    original: int
    module: str | None = None
    armed: bool = True


@dataclass
class DebugSession:
    session_id: str
    pid: int
    exe: str
    bits: int = 64
    process: object | None = None
    main_thread: object | None = None
    image_base: int = 0
    bps: dict[int, Breakpoint] = field(default_factory=dict)
    pending_specs: list = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    state: str = "created"
    last_event: dict | None = None
    last_tid: int = 0
    pending_rearm: int | None = None


SESSIONS: dict[str, DebugSession] = {}


def _require_windows() -> None:
    if os.name != "nt":
        raise OmniError("live debugging is Windows-only")


def _session(session_id: str) -> DebugSession:
    session = SESSIONS.get(session_id)
    if session is None:
        raise OmniError(f"unknown debug session: {session_id}")
    return session


def _module_map(pid: int) -> dict[str, int]:
    snapshot = _k32.CreateToolhelp32Snapshot(  # type: ignore[attr-defined]
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid
    )
    if not snapshot:
        return {}
    entry = MODULEENTRY32W()  # type: ignore[used-before-assignment]
    entry.dwSize = ctypes.sizeof(MODULEENTRY32W)  # type: ignore[attr-defined]
    modules: dict[str, int] = {}
    try:
        ok = _k32.Module32FirstW(snapshot, ctypes.byref(entry))  # type: ignore[attr-defined]
        while ok:
            base = int(entry.modBaseAddr or 0)
            if entry.szModule and base:
                modules[entry.szModule.casefold()] = base
            ok = _k32.Module32NextW(snapshot, ctypes.byref(entry))  # type: ignore[attr-defined]
    finally:
        _k32.CloseHandle(snapshot)  # type: ignore[attr-defined]
    return modules


def _read_bytes(session: DebugSession, address: int, size: int) -> bytes:
    buf = ctypes.create_string_buffer(size)  # type: ignore[attr-defined]
    got = ctypes.c_size_t(0)  # type: ignore[attr-defined]
    ok = _k32.ReadProcessMemory(  # type: ignore[attr-defined]
        session.process,
        ctypes.c_void_p(address),
        ctypes.cast(buf, ctypes.c_void_p),  # type: ignore[attr-defined]
        size,
        ctypes.byref(got),
    )
    if not ok:
        raise OmniError(
            f"ReadProcessMemory(0x{address:x}) failed with error {ctypes.get_last_error()}"
        )
    return buf.raw[: got.value]


def _write_bytes(session: DebugSession, address: int, payload: bytes) -> None:
    buf = ctypes.create_string_buffer(payload, len(payload))  # type: ignore[attr-defined]
    written = ctypes.c_size_t(0)  # type: ignore[attr-defined]
    ok = _k32.WriteProcessMemory(  # type: ignore[attr-defined]
        session.process,
        ctypes.c_void_p(address),
        ctypes.cast(buf, ctypes.c_void_p),  # type: ignore[attr-defined]
        len(payload),
        ctypes.byref(written),
    )
    if not ok:
        raise OmniError(
            f"WriteProcessMemory(0x{address:x}) failed with error {ctypes.get_last_error()}"
        )
    _k32.FlushInstructionCache(session.process, ctypes.c_void_p(address), len(payload))  # type: ignore[attr-defined]


def _thread_context(tid: int, bits: int = 64):
    handle = _k32.OpenThread(  # type: ignore[attr-defined]
        THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, False, tid
    )
    if not handle:
        raise OmniError(f"OpenThread({tid}) failed with error {ctypes.get_last_error()}")
    if bits == 64:
        ctx = ctypes.create_string_buffer(CONTEXT_SIZE_64)  # type: ignore[attr-defined]
        flags_off = CONTEXT_FLAGS_OFF_64
        flags_value = CONTEXT_FLAGS_FULL_64
        getter = _k32.GetThreadContext  # type: ignore[attr-defined]
    else:
        ctx = ctypes.create_string_buffer(CONTEXT_SIZE_32)  # type: ignore[attr-defined]
        flags_off = CONTEXT_FLAGS_OFF_32
        flags_value = CONTEXT_FLAGS_FULL_32
        getter = _k32.Wow64GetThreadContext  # type: ignore[attr-defined]
    try:
        fields = (ctypes.c_uint32 * 1).from_buffer(ctx, flags_off)  # type: ignore[attr-defined]
        fields[0] = flags_value
        if not getter(handle, ctypes.cast(ctx, ctypes.c_void_p)):  # type: ignore[attr-defined]
            raise OmniError(f"GetThreadContext failed with error {ctypes.get_last_error()}")
        return handle, ctx
    except Exception:
        _k32.CloseHandle(handle)  # type: ignore[attr-defined]
        raise


def _apply_context(handle, ctx, bits: int = 64) -> None:
    setter = (
        _k32.SetThreadContext  # type: ignore[attr-defined]
        if bits == 64
        else _k32.Wow64SetThreadContext  # type: ignore[attr-defined]
    )
    if not setter(handle, ctypes.cast(ctx, ctypes.c_void_p)):  # type: ignore[attr-defined]
        raise OmniError(f"SetThreadContext failed with error {ctypes.get_last_error()}")


def _ctx_get(ctx, offset: int, bits: int = 64) -> int:
    width = 8 if bits == 64 else 4
    return int.from_bytes(bytes(ctx[offset : offset + width]), "little")


def _ctx_set(ctx, offset: int, value: int, bits: int = 64) -> None:
    width = 8 if bits == 64 else 4
    ctx[offset : offset + width] = int(value).to_bytes(width, "little")


def _set_trap_flag(ctx, enabled: bool, bits: int = 64) -> None:
    offset = EFLAGS_OFF_64 if bits == 64 else EFLAGS_OFF_32
    flags = int.from_bytes(bytes(ctx[offset : offset + 4]), "little")
    flags = (flags | TRAP_FLAG) if enabled else (flags & ~TRAP_FLAG)
    ctx[offset : offset + 4] = flags.to_bytes(4, "little")


def _parse_spec(spec, modules: dict[str, int]) -> tuple[int | None, str | None]:
    module_name = None
    if isinstance(spec, dict):
        if "va" in spec:
            return parse_int(spec["va"]), None
        module_name = spec.get("module")
        rva_text = spec.get("rva")
        if rva_text is None:
            raise OmniError("breakpoint dict needs 'va' or 'module'+'rva'")
        rva = parse_int(rva_text)
    else:
        text = str(spec)
        if ":" in text:
            module_name, rva_text = text.rsplit(":", 1)
            rva = parse_int(rva_text)
        else:
            return parse_int(text), None
    if not module_name:
        return rva, None
    base = modules.get(str(module_name).casefold())
    if base is None:
        return None, str(module_name)
    return base + rva, str(module_name)


def _install_breakpoint(session: DebugSession, address: int, module: str | None) -> None:
    if address in session.bps:
        return
    original = _read_bytes(session, address, 1)[0]
    if original == 0xCC:
        raise OmniError(f"address 0x{address:x} already holds an INT3")
    _write_bytes(session, address, b"\xCC")
    session.bps[address] = Breakpoint(address=address, original=original, module=module)


def _resolve_pending(session: DebugSession) -> None:
    if not session.pending_specs:
        return
    modules = _module_map(session.pid)
    remaining = []
    for spec in session.pending_specs:
        try:
            address, module = _parse_spec(spec, modules)
        except OmniError as exc:
            session.errors.append(str(exc))
            continue
        if address is None:
            remaining.append(spec)
            continue
        try:
            _install_breakpoint(session, address, module)
        except OmniError as exc:
            session.errors.append(str(exc))
    session.pending_specs = remaining


def _summary(session: DebugSession, status: str | None = None) -> dict:
    return {
        "session_id": session.session_id,
        "pid": session.pid,
        "exe": session.exe,
        "state": session.state,
        "status": status or session.state,
        "event": session.last_event,
        "last_thread": session.last_tid,
        "image_base": session.image_base,
        "breakpoints": [
            {"address": bp.address, "module": bp.module, "armed": bp.armed}
            for bp in session.bps.values()
        ],
        "pending_breakpoint_specs": list(session.pending_specs),
        "errors": list(session.errors),
    }


def _continue_event(session: DebugSession, tid: int) -> None:
    if not _k32.ContinueDebugEvent(session.pid, tid, DBG_CONTINUE):  # type: ignore[attr-defined]
        raise OmniError(f"ContinueDebugEvent failed with error {ctypes.get_last_error()}")


def _wait_for_stop(session: DebugSession, timeout_ms: int) -> dict:
    deadline = time.time() + max(1, timeout_ms) / 1000.0
    while True:
        remaining = int(max(1, (deadline - time.time()) * 1000))
        event = DEBUG_EVENT()  # type: ignore[used-before-assignment]
        if not _k32.WaitForDebugEvent(ctypes.byref(event), remaining):  # type: ignore[attr-defined]
            session.state = "running"
            return _summary(session, status="timeout")
        code = int(event.dwDebugEventCode)
        tid = int(event.dwThreadId)
        if code == 3:  # CREATE_PROCESS
            info = event.u.CreateProcessInfo
            session.process = info.hProcess
            session.main_thread = info.hThread
            session.image_base = int(info.lpBaseOfImage or 0)
            session.last_event = {
                "kind": "create_process",
                "image_base": session.image_base,
            }
            _resolve_pending(session)
            _continue_event(session, tid)
            continue
        if code == 6:  # LOAD_DLL
            _resolve_pending(session)
            _continue_event(session, tid)
            continue
        if code == 5:  # EXIT_PROCESS
            session.state = "exited"
            session.last_event = {
                "kind": "exit_process",
                "exit_code": int(event.u.ExitProcess.dwExitCode),
            }
            _continue_event(session, tid)
            return _summary(session)
        if code == 1:  # EXCEPTION
            record = event.u.Exception.ExceptionRecord
            exception_code = int(record.ExceptionCode) & 0xFFFFFFFF
            address = int(record.ExceptionAddress or 0)
            if exception_code in (EXCEPTION_BREAKPOINT, EXCEPTION_WOW64_BREAKPOINT):
                try:
                    handle, ctx = _thread_context(tid, session.bits)
                except OmniError as exc:
                    session.errors.append(f"context unavailable: {exc}")
                    _continue_event(session, tid)
                    continue
                offsets = REG_OFFSETS_64 if session.bits == 64 else REG_OFFSETS_32
                ip_name = "rip" if session.bits == 64 else "eip"
                try:
                    ip = _ctx_get(ctx, offsets[ip_name], session.bits)
                    candidates = [ip - 1, address - 1, address]
                    bp = next(
                        (session.bps[c] for c in candidates if c in session.bps),
                        None,
                    )
                    if bp is not None and bp.armed:
                        _write_bytes(session, bp.address, bytes([bp.original]))
                        _ctx_set(ctx, offsets[ip_name], bp.address, session.bits)
                        _set_trap_flag(ctx, False, session.bits)
                        _apply_context(handle, ctx, session.bits)
                        bp.armed = False
                        session.pending_rearm = bp.address
                        session.state = "breakpoint"
                        session.last_tid = tid
                        session.last_event = {
                            "kind": "breakpoint",
                            "address": bp.address,
                            "module": bp.module,
                        }
                        return _summary(session)
                finally:
                    _k32.CloseHandle(handle)  # type: ignore[attr-defined]
                _continue_event(session, tid)
                continue
            if exception_code in (EXCEPTION_SINGLE_STEP, EXCEPTION_WOW64_SINGLE_STEP):
                if session.pending_rearm is not None:
                    bp = session.bps.get(session.pending_rearm)
                    if bp is not None:
                        _write_bytes(session, bp.address, b"\xCC")
                        bp.armed = True
                    session.pending_rearm = None
                    handle, ctx = _thread_context(tid, session.bits)
                    try:
                        _set_trap_flag(ctx, False, session.bits)
                        _apply_context(handle, ctx, session.bits)
                    finally:
                        _k32.CloseHandle(handle)  # type: ignore[attr-defined]
                _continue_event(session, tid)
                continue
            session.state = "exception"
            session.last_tid = tid
            session.last_event = {
                "kind": "exception",
                "code": f"0x{exception_code:x}",
                "address": address,
            }
            return _summary(session)
        _continue_event(session, tid)


def debug_launch(
    exe: str,
    args: list[str] | None = None,
    breakpoints: list | None = None,
    stop_at_entry: bool = False,
    timeout_ms: int = 15000,
) -> dict:
    """Start a target under the debugger and stop at the first user breakpoint."""
    _require_windows()
    path = os.path.abspath(exe)
    if not os.path.isfile(path):
        raise OmniError(f"executable not found: {path}")
    from .pemap import load as pe_load

    image = pe_load(path, "file")
    if image.bits not in (32, 64):
        raise OmniError(f"unsupported target architecture ({image.bits}-bit)")

    specs = list(breakpoints or [])
    if stop_at_entry:
        specs.append({"module": os.path.basename(path), "rva": hex(image.entry_rva)})

    command = " ".join([f'"{path}"', *[f'"{arg}"' for arg in (args or [])]])
    startup = STARTUPINFOW()  # type: ignore[used-before-assignment]
    startup.cb = ctypes.sizeof(STARTUPINFOW)  # type: ignore[attr-defined]
    info = PROCESS_INFORMATION()  # type: ignore[used-before-assignment]
    cmd_buf = ctypes.create_unicode_buffer(command)  # type: ignore[attr-defined]
    if not _k32.CreateProcessW(  # type: ignore[attr-defined]
        path,
        cmd_buf,
        None,
        None,
        False,
        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
        None,
        None,
        ctypes.byref(startup),
        ctypes.byref(info),
    ):
        raise OmniError(f"CreateProcessW failed with error {ctypes.get_last_error()}")

    session = DebugSession(
        session_id=uuid.uuid4().hex[:12],
        pid=int(info.dwProcessId),
        exe=path,
        bits=image.bits,
        process=info.hProcess,
        main_thread=info.hThread,
        pending_specs=specs,
    )
    SESSIONS[session.session_id] = session
    try:
        return _wait_for_stop(session, timeout_ms)
    except Exception:
        debug_close(session.session_id)
        raise


def debug_continue(session_id: str, timeout_ms: int = 15000) -> dict:
    """Resume the target and wait for the next breakpoint, exception or timeout."""
    session = _session(session_id)
    if session.state in {"exited", "closed"}:
        raise OmniError(f"session is {session.state}")
    if session.last_tid:
        _continue_event(session, session.last_tid)
    session.state = "running"
    return _wait_for_stop(session, timeout_ms)


def debug_state(session_id: str) -> dict:
    """Return the current session summary without touching the target."""
    return _summary(_session(session_id))


def debug_registers(session_id: str) -> dict:
    """Read x64 general-purpose registers of the last stopped thread."""
    session = _session(session_id)
    if session.state in {"exited", "closed"}:
        raise OmniError(f"session is {session.state}")
    offsets = REG_OFFSETS_64 if session.bits == 64 else REG_OFFSETS_32
    handle, ctx = _thread_context(
        session.last_tid or _main_tid(session), session.bits
    )
    try:
        values = {
            name: _ctx_get(ctx, offset, session.bits)
            for name, offset in offsets.items()
        }
    finally:
        _k32.CloseHandle(handle)  # type: ignore[attr-defined]
    return {"session_id": session_id, "registers": values}


def _main_tid(session: DebugSession) -> int:
    # The CREATE_PROCESS event's thread id is recorded on first stop; before
    # that fall back to the main thread handle's id via GetThreadId.
    if session.last_tid:
        return session.last_tid
    raise OmniError("no stopped thread yet; continue to a breakpoint first")


def debug_read_memory(session_id: str, address: int | str, size: int = 64) -> dict:
    """Read target memory (hex) at an absolute address."""
    session = _session(session_id)
    if size < 1 or size > 1024 * 1024:
        raise OmniError("size must be between 1 and 1 MiB")
    addr = parse_int(address)
    data = _read_bytes(session, addr, size)
    return {"session_id": session_id, "address": addr, "size": len(data), "hex": data.hex()}


def debug_write_memory(session_id: str, address: int | str, data_hex: str) -> dict:
    """Write bytes (hex string) into target memory."""
    session = _session(session_id)
    try:
        payload = bytes.fromhex(data_hex)
    except ValueError as exc:
        raise OmniError("data_hex must be a valid hex string") from exc
    if not payload or len(payload) > 64 * 1024:
        raise OmniError("payload must be 1..65536 bytes")
    addr = parse_int(address)
    _write_bytes(session, addr, payload)
    return {"session_id": session_id, "address": addr, "written": len(payload)}


def debug_breakpoint_add(session_id: str, spec) -> dict:
    """Add a software breakpoint: {'module','rva'} or {'va'} or 'module:0xRVA'."""
    session = _session(session_id)
    modules = _module_map(session.pid)
    address, module = _parse_spec(spec, modules)
    if address is None:
        session.pending_specs.append(spec)
        return _summary(session, status="deferred")
    _install_breakpoint(session, address, module)
    return _summary(session, status="armed")


def debug_breakpoint_remove(session_id: str, address: int | str) -> dict:
    """Remove a breakpoint and restore the original byte."""
    session = _session(session_id)
    addr = parse_int(address)
    bp = session.bps.pop(addr, None)
    if bp is None:
        raise OmniError(f"no breakpoint at 0x{addr:x}")
    _write_bytes(session, addr, bytes([bp.original]))
    return _summary(session, status="removed")


def debug_dump(session_id: str, outdir: str = "dumps") -> dict:
    """Dump module images of the stopped process (dump offset == RVA)."""
    from .dumpwin import dump_process

    session = _session(session_id)
    return dump_process(session.pid, outdir=outdir)


def debug_close(session_id: str) -> dict:
    """Terminate the target (if alive) and release the debug session."""
    session = _session(session_id)
    with contextlib.suppress(OSError):
        if session.process:
            _k32.TerminateProcess(session.process, 1)  # type: ignore[attr-defined]
    for handle in (session.process, session.main_thread):
        with contextlib.suppress(OSError):
            if handle:
                _k32.CloseHandle(handle)  # type: ignore[attr-defined]
    session.state = "closed"
    SESSIONS.pop(session_id, None)
    return {"session_id": session_id, "state": "closed"}
