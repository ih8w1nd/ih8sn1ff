# ih8Sn1ff tool reference

All tools are available both as MCP tools (`ih8sn1ff-mcp`) and CLI subcommands
(`ih8sn1ff <tool> ...`). Every result carries explicit bounds (offsets are absolute
file offsets unless stated otherwise) so results can be chained safely.

## Static file tools

### `bin_info(path)`
PE/ELF metadata: format, machine, image base, entry point (RVA), section table
(name, VA, vsize, raw size, raw offset, entropy), compile timestamp, .NET presence,
and packer hints (section-name scrambling, zero-raw virtual sections).

### `strings_scan(path, regex=None, min_len=6, encoding="ascii", limit=2000)`
Printable-run scan returning `{offset, text}` rows. `encoding` is `"ascii"`
(default), `"utf16"` (UTF-16LE — Delphi/Unicode literals) or `"both"`;
`utf16=True` remains a convenience alias. Regexes apply to decoded strings.

### `entropy_map(path, window=1048576)`
Windowed Shannon entropy. Low-entropy windows = data/resources; ~7.9+ = packed or
encrypted; mixed windows expose plaintext islands inside packed sections.

### `find_blobs(path, kind="zip|pe|gzip", limit=40, outdir=None)`
Carves embedded archives / PEs by signature, validates them where possible
(zip EOCD walk, PE e_lfanew check), and writes candidates to `outdir`.

## Runtime tools (Windows host)

### `run_and_dump(exe, wait_ms=15000, outdir="dumps", elevated=True)`
Launches the target (optionally elevated), waits, then snapshots every
non-system module's memory image and terminates the process. This is the
unpacking primitive: protectors decrypt code/data in memory, so the dump
contains the real program.

### `dump_process(pid, outdir="dumps", include_main=True, skip_system=True)`
Same snapshot logic for an already-running process. On access-denied (elevated
target) it returns a clear error — re-run the server elevated.

Outputs: `NN_modulename.bin` per dumped module (dump offset == RVA because the
snapshot starts at the module base), `dump_log.txt`, and `dump_meta.json` with
every loaded module's name, path, base and size (system modules included even
when not dumped). `dump_meta.json` is required by `rebuild_imports`.

## Memory-image tools

### `rebuild_pe(dump_path, out, image_base_guess=None)`
Rebuilds a file-aligned PE from a memory image: parses the in-memory headers,
rewrites each section's `SizeOfRawData/PointerToRawData` to the virtual layout,
copies VA-addressed content to sequential file offsets, zero-fills gaps, and
patches the section table. Result opens in Ghidra/IDA/objdump as a normal PE.

### `trim_pe(rebuilt_path, out, scratch_prefix_end=0x1A00000, huge_section_threshold=0x10000000, entry_rva=0x1000)`
Produces an analysis-sized PE: all normal sections are kept in full; sections
at or above `huge_section_threshold` are treated as protector arenas — only the
byte prefix before `scratch_prefix_end` is kept (method code often lands just
past the arena start) and the rest is reduced to a 0x1000 virtual placeholder.
The entry point is forced to code so Ghidra starts discovery there.

### `rebuild_imports(dump_path, out, dump_meta)`
Scylla-style IAT rebuild for runtime dumps. Walks the FirstThunk arrays, maps
each resolved absolute address back to a module from `dump_meta.json`, resolves
the export name from the module file on disk (named and ordinal-only exports),
and appends a new `.idata2` section with fresh descriptors, INT arrays,
hint/name entries and DLL names. Unresolved slots keep an `UNK_<module>_<rva>`
label and are listed in `unresolved_samples` with module and RVA details. The
rebuilt import directory is patched into the optional header; descriptor and
thunk fields carry absolute RVAs.

## Flow tools

### `xrefs_rip(path, string=None, target=None, limit=40, layout="auto")`
Scans executable sections with Capstone for `[rip+disp]` memory operands and
direct `call`/`jmp` immediates that resolve to the target string/address.
Works in RVA space; `layout` auto-detects dump vs on-disk file.

### `callgraph(path, root, depth=2, max_nodes=200, layout="auto")`
Breadth-first direct-call graph from a root RVA/VA. Linear sweep stops at the
first return; indirect calls are not resolved.

### `emulate(path, entry=None, max_instructions=1000, layout="auto", trace_limit=256)`
Bounded Unicorn emulation in RVA space. Sections are mapped at their RVAs, a
stack is provided, and the result contains the executed trace (bounded),
stop reason, unmapped address and final registers.

## Delphi tools

### `delphi_methods(dump_path, names=None, names_file=None, max_occurrences=4)`
Maps Delphi **published-method** table entries: an entry is
`{code_ptr; ShortString name}`; the name text at `off` is preceded by its length
byte (`off-1`) and the code pointer (`off-5`). Also accepts pointer-form tables.
Provide known method names (from prior strings scans) to receive
`name, occurrence, entry_offset, code_rva` rows. Without names, use
`strings_scan` first, then feed interesting names back in.

### `delphi_units(dump_path, top=200)`
Heuristic unit/class inventory: `a.b.c` dotted identifiers plus `TClassName`
RTTI tokens, frequency-ranked. Useful to size up an app before decompiling.

## Disassembly tools

### `disasm(path, addr, count=200, span=8192, base="file")`
Capstone x86 listing (32/64 inferred from PE/ELF header when present). Immediate
operands that point at readable strings are annotated inline (`; "..."`).
`base="rva"` treats `addr` as an RVA using the PE section map.

### `xrefs(path, target=None, string=None, limit=40)`
Scans little-endian 32-bit absolute immediates (unaligned placements included)
for references to a value or string (exact address and Delphi string-const
shifts -2/-4/-8) and reports only hits inside executable ranges, with the
nearest plausible function prologue before each hit.

## Live debugging (Windows: x64 and WOW64 x86)

Sessions live in the MCP server process (or `ih8sn1ff dbg shell`). All session
tools take `session_id`.

### `debug_launch(exe, args=None, breakpoints=None, stop_at_entry=False, timeout_ms=15000)`
Starts the target under `DEBUG_PROCESS`, installs software breakpoints after the
loader breakpoint, and stops at the first user breakpoint. Breakpoint specs are
`"module:0xRVA"` or `"0xVA"`. x64 targets use native contexts; 32-bit targets
on 64-bit Windows use WOW64 contexts (`STATUS_WX86_BREAKPOINT` 0x4000001F and
`STATUS_WX86_SINGLE_STEP` 0x40000004 are handled like their native counterparts).

### `debug_continue(session_id, timeout_ms=15000)`
Resumes and waits for the next stop, exception, exit or timeout. A trap-flag
single-step rearms the breakpoint that was just hit.

### `debug_state`, `debug_registers`, `debug_read_memory`, `debug_write_memory`
Inspect the current session, x64 general-purpose registers of the last stopped
thread, and target memory (hex in/out).

### `debug_breakpoint_add(session_id, va=None, module=None, rva=None)`, `debug_breakpoint_remove`
Add/remove software breakpoints; unresolved module specs are deferred until the
DLL loads.

### `debug_dump(session_id, outdir="dumps")`
Dump module images while the target is stopped (writes `dump_meta.json`).

### `debug_close(session_id)`
Terminates the target if alive and releases the session.

## Evidence

### `evidence_list(limit=50)` / `evidence_read(evidence_id)`
Analysis and session-launch/dump MCP calls are journaled to
`~/.ih8sn1ff/evidence/YYYYMMDD.jsonl` (override with
`IH8SN1FF_EVIDENCE_DIR`). Lightweight session probes (`debug_state`,
`debug_registers`, memory reads/writes, breakpoint edits) are not recorded.
Each record has an id, tool, params, result and a SHA-256 digest; oversized
results store a digest and preview instead of the full payload.

## Ghidra tools

Requires `GHIDRA_INSTALL_DIR` pointing at an extracted Ghidra (12.1.x tested).

### `ghidra_import(binary, project, analysis="full", timeout_min=30)`
Runs `analyzeHeadless -import`. `analysis="none"` imports without auto-analysis
(fast; good for dumping large PEs on demand); `"full"` runs auto-analysis.

### `ghidra_decompile(project, program=None, rvas=None, keywords=None, limit=40)`
Runs bundled postScripts: `DecompileTargets.java` (explicit RVAs) and
`DecompileByStrings.java` (find string data matching keywords, follow references,
decompile the containing functions). Returns collected C text.

### `ghidra_funcs(project, program=None)`
Lists analyzed functions (address, name) from the project.

## .NET tools

### `dotnet_types(asm, pattern=None)`
`ilspycmd --list` wrapper (or `ilspycmd -t` when a single type is requested).

### `dotnet_type(asm, type_name)`
Decompiles one type to C#.

## Optional

### `yara_scan(path, rules_file=None)` / `yara_pack(path, rules_file=None)`
Runs YARA when `yara-python` is installed. Without `rules_file` the bundled
packer profiles (`packers.yar`) and `anti-debug.yar` are compiled together with
namespace names; matches include rule and namespace.

## Conventions

- Addresses in tool inputs: `0x`-prefixed hex preferred; decimal accepted.
- "RVA" = image-relative; "offset" = raw file offset; memory dumps use offset==RVA.
- Large outputs are bounded (`limit`, `top`) and report truncation explicitly.
- Every tool raises typed errors for missing files, permission problems, or
  missing optional engines — no silent fallbacks.
