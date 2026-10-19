# ih8Sn1ff workflows

Practical, battle-tested sequences. Everything below is orchestration — the deep
engines are Ghidra (static), the built-in x64 debugger and Unicorn (dynamic);
x64dbg/Frida remain options for manual work.

---

## 1. VMProtect / Themida-class targets: dump, rebuild, analyze

Protectors of this class do not surrender statically: the on-disk image is a
loader; the real program exists only in memory. The reliable path is runtime.

### Step 1 — run and dump

```
run_and_dump(exe="C:/target/app.exe", wait_ms=20000, outdir="dumps")
```

- The tool launches the target (elevated when requested), waits for the UI to
  settle, snapshots every non-system module, and terminates it.
- If the target requires interaction (login window), it is enough that modules
  load; payloads that decrypt only when a feature runs are covered in Step 6.

### Step 2 — rebuild the main image

```
rebuild_pe(dump_path="dumps/00_main.exe.bin", out="out/rebuilt.exe")
```

Memory layout (offset == RVA) becomes a normal file layout (raw offsets chained).
Images/sections with `rawsize=0` in the original header get their virtual content
materialized from the dump.

### Step 3 — make it manageable

```
trim_pe(rebuilt_path="out/rebuilt.exe", out="out/trimmed.exe")
```

Full unpacked images are often 200–550 MB because the protector reserves huge
scratch arenas. `trim_pe` keeps the real code sections plus a VA prefix of the
arena (method pointers frequently land just past its start) and trims the rest,
so Ghidra starts in seconds instead of hours.

### Step 4 — orient with strings and entropy

```
entropy_map("out/trimmed.exe")
strings_scan("out/trimmed.exe", regex="(?i)unpack|license|api\\.")
strings_scan("out/trimmed.exe", utf16=True, min_len=8)     # Delphi/Unicode literals
```

Plaintext islands inside packed sections tell you what already decrypted. RTTI
tables, unit names and error strings usually survive.

### Step 5 — Delphi apps: name → code in one call

```
delphi_methods("dumps/00_main.exe.bin", names=["MyFeature_Execute", "Erase"])
disasm("dumps/00_main.exe.bin", addr=0x1A3A458, count=60)
```

Published-method tables give exact code RVAs. Verify with `disasm`: a classic
prologue (`mov edi,edi; push ebp; mov ebp,esp`) confirms the entry.

### Step 6 — the per-function encryption wrinkle

Modern protectors encrypt **per function and decrypt on first execution**.
Functions the program never ran are garbage in the dump even though the loader
is unpacked. Two consequences:

- If a target method disassembles to noise (entropy >7, `halt_baddata` chunks in
  decompile), it was not executed: trigger the feature in the UI (device
  connected, menu opened, license dialog answered) and dump again.
- Compare two dumps with `bin_info`/hashes to see exactly which regions changed.

This is also why an agent loop beats one-shot RE: run → dump → analyze → adjust
what you stimulate → dump again.

### Step 7 — Ghidra headless decompile

```
ghidra_import("out/trimmed.exe", "out/proj", analysis="full")
ghidra_decompile("out/proj", rvas=[0x163A454, 0x165103C])
ghidra_decompile("out/proj", keywords=["KSTRINGB", "setprop"])
```

String-driven decompilation is the fastest path when symbol names are gone:
find the literal, follow references, read the containing function.

### Themida notes

Same runtime doctrine. Additionally: Themida virtualizes entries and checks the
debugger early; dump from a clean launch (no debugger attached) and analyze the
dump statically. If a staged sequence is needed (unpack → re-protect), keep the
x64dbg session manual and use ih8Sn1ff for the dump/analysis half.

---

## 2. PE rebuild internals (what `rebuild_pe` guarantees)

- Section content = dump bytes `[VirtualAddress, VirtualAddress+VirtualSize)`.
- `SizeOfRawData` = virtual size aligned to `FileAlignment`; `PointerToRawData`
  chained sequentially after the headers.
- `SizeOfImage`, `ImageBase`, data directories are preserved — RVA math and
  embedded RTTI pointers stay valid.
- Corrupt/zero pages are zero-filled, never skipped, so consumers see one
  contiguous image.

Limitations: overlays and TLS callbacks into the original stub remain what the
dump shows. Loader-mutated imports can be rebuilt with `rebuild_imports` using
the `dump_meta.json` written next to the dump; heavily obfuscated IATs may keep
`UNK_<address>` entries.

## 3. Delphi triage checklist

1. `strings_scan utf16=True` — Delphi stores Unicode strings inline; find units
   (`a.b.c`), method names, DFM component names (`btnXxx`).
2. `delphi_units` — inventory of classes/units, frequency-ranked.
3. `delphi_methods` — resolve name → RVA for the interesting names.
4. `disasm` at the RVAs — confirm prologues, follow call targets.
5. Ghidra import of the trimmed PE for cross-function context.

## 4. Ghidra headless tips

- Import without analysis for huge images (`analysis="none"`), then decompile
  on demand; the decompiler works per function.
- Set `GHIDRA_INSTALL_DIR`; the server shells out to `analyzeHeadless.bat`
  (Windows) or `analyzeHeadless` (POSIX).
- The bundled Java postScripts accept address lists and keyword sets — extend
  them freely; they are plain Ghidra scripts.

## 5. Live debugging (x64 and WOW64 x86)

```
debug_launch(exe="C:/target/app.exe", stop_at_entry=True, timeout_ms=20000)
debug_registers(session_id)
debug_read_memory(session_id, address="0x7ff6...", size=64)
debug_breakpoint_add(session_id, module="target.exe", rva="0x163a454")
debug_continue(session_id)
debug_dump(session_id, outdir="dumps/stopped")
debug_close(session_id)
```

- Breakpoints are software `0xCC`; on a hit the original byte is restored, the
  instruction pointer is rewound and a trap-flag single-step rearms the
  breakpoint before resuming. Both native x64 and WOW64 x86 targets are
  supported, including the WX86 breakpoint/single-step exception codes.
- Sessions are process-local. Use the MCP server for multi-step sessions, or
  `ih8sn1ff dbg shell` interactively; separate CLI invocations cannot share a
  session.
- After a stop, `debug_dump` snapshots modules exactly at the state you care
  about (e.g. after an unpacking stub ran).

## 6. Bounded emulation

```
emulate("out/trimmed.exe", entry="0x163a454", max_instructions=2000)
```

Useful for decrypt loops that touch no imports: the trace shows executed RVAs,
stop reason and final registers. Unmapped accesses stop emulation and report the
address; add real code/data around the entry if the decryptor needs it.

## 7. Import rebuild

```
rebuild_imports("dumps/00_main.exe.bin", "out/rebuilt.exe", "dumps/dump_meta.json")
```

`dump_meta.json` lists every loaded module with base and size. Each resolved IAT
slot is mapped back to its module, the export name is read from the module file
on disk, and a fresh `.idata2` section is appended. Unresolved slots are reported
as `UNK_<address>` so you can see what still needs a live session.

## 8. When to leave scripting

- Anti-debug/VM checks that fight an attached debugger: try a clean
  `run_and_dump` first; for interactive battles use manual x64dbg, then
  `dump_process` from the agent side while the target is paused.
- Kernel/firmware targets → not this toolkit; use dedicated hardware tooling.
- Anything you cannot legally own/test → stop.

## 9. Ethics reminder

Only analyze software you own, manage, or are authorized to inspect. The
toolkit refuses nothing at the tool layer, which makes your judgment the
control — use it.
