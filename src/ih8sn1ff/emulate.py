"""Bounded Unicorn emulation in RVA space (trace + lightweight unpacking).

Sections are mapped at their RVAs, so addresses in the trace match dumps and
Ghidra analysis. Emulation stops on the instruction budget, an unmapped memory
access, or an invalid instruction.
"""

from __future__ import annotations

from .pemap import load, normalize_rva
from .util import OmniError, align_up, parse_int

STACK_SIZE_DEFAULT = 0x100000
MAX_IMAGE_MAP = 512 * 1024 * 1024
IMAGE_MAP_MIN = 0x1000


def _read_register(uc, unicorn, const):
    try:
        return int(uc.reg_read(const))
    except (unicorn.UcError, TypeError, ValueError):
        return None


def _registers(uc, unicorn, bits: int) -> dict[str, int]:
    names = (
        ["rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi"]
        + [f"r{n}" for n in range(8, 16)]
        + ["eflags"]
        if bits == 64
        else ["eip", "esp", "ebp", "eax", "ebx", "ecx", "edx", "esi", "edi", "eflags"]
    )
    out: dict[str, int] = {}
    for name in names:
        const = getattr(unicorn.x86_const, f"UC_X86_REG_{name.upper()}", None)
        if const is None:
            continue
        value = _read_register(uc, unicorn, const)
        if value is not None:
            out[name] = value
    return out


def emulate(
    path: str,
    entry: int | str | None = None,
    max_instructions: int = 1000,
    layout: str = "auto",
    stack_size: int = STACK_SIZE_DEFAULT,
    trace_limit: int = 256,
) -> dict:
    """Emulate code starting at ``entry`` (RVA/VA) with a bounded budget."""
    try:
        import unicorn
    except ImportError as exc:
        raise OmniError("unicorn not installed — pip install ih8sn1ff[emu]") from exc

    image = load(path, layout)
    if max_instructions < 1:
        raise OmniError("max_instructions must be >= 1")
    if stack_size < 0x1000:
        raise OmniError("stack_size must be at least 0x1000")

    entry_rva = normalize_rva(
        image, parse_int(entry) if entry is not None else image.entry_rva
    )
    if not image.in_exec_rva(entry_rva):
        raise OmniError(f"entry RVA 0x{entry_rva:x} is not inside an executable section")

    if entry_rva < IMAGE_MAP_MIN:
        raise OmniError(
            f"entry RVA 0x{entry_rva:x} is below the emulation map base 0x{IMAGE_MAP_MIN:x}"
        )

    largest_end = max(
        (sec.va + sec.virtual_size for sec in image.sections), default=len(image.data)
    )
    map_end = align_up(largest_end, 0x1000)
    if map_end - IMAGE_MAP_MIN > MAX_IMAGE_MAP:
        raise OmniError(
            f"image virtual size 0x{map_end:x} exceeds emulation cap 0x{MAX_IMAGE_MAP:x}"
        )

    mode = unicorn.UC_MODE_64 if image.bits == 64 else unicorn.UC_MODE_32
    uc = unicorn.Uc(unicorn.UC_ARCH_X86, mode)
    # Mapping page zero crashes Unicorn on Windows (access violation), so the
    # image is mapped from the first PE page (0x1000) onward.
    uc.mem_map(IMAGE_MAP_MIN, map_end - IMAGE_MAP_MIN, unicorn.UC_PROT_ALL)
    for sec in image.sections:
        offset = image.rva_to_file(sec.va)
        if offset is None or sec.virtual_size == 0 or sec.va < IMAGE_MAP_MIN:
            continue
        chunk = image.data[offset : offset + sec.virtual_size]
        if chunk:
            available = max(0, map_end - sec.va)
            uc.mem_write(sec.va, chunk[:available])

    stack_base = align_up(map_end + 0x10000, 0x1000)
    uc.mem_map(stack_base, stack_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
    stack_pointer = stack_base + stack_size - 0x100

    trace: list[dict] = []
    state = {"executed": 0, "stop": None, "unmapped": None}

    def on_code(uc_ref, address, size, _user):
        state["executed"] += 1
        if len(trace) < trace_limit:
            trace.append({"rva": address, "size": size})
        if state["executed"] >= max_instructions:
            state["stop"] = "instruction_limit"
            uc_ref.emu_stop()

    def on_unmapped(uc_ref, access, address, size, value, _user):
        state["unmapped"] = address
        state["stop"] = "unmapped_memory"
        uc_ref.emu_stop()

    uc.hook_add(unicorn.UC_HOOK_CODE, on_code)
    uc.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED, on_unmapped)

    sp_const = (
        unicorn.x86_const.UC_X86_REG_RSP
        if image.bits == 64
        else unicorn.x86_const.UC_X86_REG_ESP
    )
    uc.reg_write(sp_const, stack_pointer)

    error = None
    until = 0xFFFFFFFFFFFFFFFF if image.bits == 64 else 0xFFFFFFFF
    try:
        uc.emu_start(entry_rva, until, count=max_instructions)
    except unicorn.UcError as exc:
        error = str(exc)
        state["stop"] = "emulation_error"

    if state["stop"] is None:
        state["stop"] = "completed"

    return {
        "path": str(path),
        "layout": image.layout,
        "entry_rva": entry_rva,
        "executed": state["executed"],
        "trace": trace,
        "trace_truncated": state["executed"] > len(trace),
        "stop_reason": state["stop"],
        "unmapped_address": state["unmapped"],
        "error": error,
        "registers": _registers(uc, unicorn, image.bits),
        "stack_base": stack_base,
        "map_start": IMAGE_MAP_MIN,
        "map_end": map_end,
    }
