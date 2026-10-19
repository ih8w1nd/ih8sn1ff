# ih8Sn1ff

[![ci](https://github.com/ih8w1nd/ih8sn1ff/actions/workflows/ci.yml/badge.svg)](https://github.com/ih8w1nd/ih8sn1ff/actions/workflows/ci.yml)
[![ci-windows](https://github.com/ih8w1nd/ih8sn1ff/actions/workflows/ci-windows.yml/badge.svg)](https://github.com/ih8w1nd/ih8sn1ff/actions/workflows/ci-windows.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Repository: https://github.com/ih8w1nd/ih8sn1ff

Agent-first reverse-engineering toolkit with a native **MCP server** and a matching CLI.
Built for the workflow that actually cracks modern protected binaries: **run → dump →
rebuild → analyze → decompile**, with every step scriptable and every result
LLM-friendly.

```
run_and_dump  →  rebuild_pe  →  trim_pe  →  delphi_methods  →  ghidra_decompile
     │                │             │              │                   │
  process           memory→file  analysis-sized  RTTI name→RVA      C pseudo-code
  modules           aligned PE   PE for Ghidra   (Delphi apps)
```

## Why another RE tool?

- **MCP-native.** Every capability is exposed as an MCP tool, so an agent (Claude,
  or any MCP host) drives the analysis loop directly: scan strings, find xrefs,
  decompile, dump the live process, re-scan.
- **Actually practical on packed binaries.** VMProtect- / Themida-class wrappers are
  beaten at runtime, not statically. ih8Sn1ff ships the operational chain used for
  that: elevated module dumping, memory-image → file-aligned PE rebuild,
  analysis-sized PE trimming, per-function "decrypt-on-execute" workflows.
- **Delphi-aware.** Most commercial RE targets in this space are Delphi; ih8Sn1ff maps
  published-method RTTI `name → code RVA` in one call — the trick that turns a
  500 MB mystery dump into a navigable program.
- **Live debugging without plugins.** Launch Windows targets (x64 or WOW64 x86)
  under a built-in debugger, set software breakpoints, read registers and memory,
  dump modules at a stop, and continue — as MCP calls or `ih8sn1ff dbg shell`
  commands.
- **Deterministic and auditable.** Plain Python, no hidden services. Every tool
  returns bounds-checked, explicitly-limited results (offsets, digests, counts).

It does not replace Ghidra — it orchestrates it. Deep static analysis stays in
Ghidra (headless scripts included). For dynamic work ih8Sn1ff ships its own x64
debugger for scripted sessions; x64dbg remains better for manual GUI exploring.

## Install

```bash
pip install ih8sn1ff            # core: capstone + pefile
pip install ih8sn1ff[elf]       # + ELF metadata (pyelftools)
pip install ih8sn1ff[emu]       # + Unicorn emulation
pip install ih8sn1ff[yara]      # + YARA (bundled packer/anti-debug rules)
pip install ih8sn1ff[all]       # everything optional
```

Until the package is published, install from a checkout:

```bash
pip install -e ".[dev,elf]"
```

External engines (optional, auto-detected):

| Engine | Enable with |
|---|---|
| Ghidra 12.x | `GHIDRA_INSTALL_DIR` pointing at the extracted release |
| .NET decompiler | `dotnet tool install -g ilspycmd` |
| x64dbg | optional manual sessions; the built-in x64 debugger needs no extra engine |

## MCP quickstart

Register the stdio server (Claude Code example, `.mcp.json`):

```json
{
  "mcpServers": {
    "ih8sn1ff": {
      "command": "ih8sn1ff-mcp",
      "env": { "GHIDRA_INSTALL_DIR": "C:/tools/ghidra_12.1.4_PUBLIC" }
    }
  }
}
```

Full setup for Claude Code, Claude Desktop, Cursor and uv lives in
[docs/MCP-SETUP.md](docs/MCP-SETUP.md). One-liner for Claude Code:

```bash
claude mcp add ih8sn1ff -e GHIDRA_INSTALL_DIR=C:/tools/ghidra_12.1.4_PUBLIC -- ih8sn1ff-mcp
```

Then ask the agent:

> Dump the modules of PID 7123, rebuild a file-aligned PE, trim it for analysis,
> map Delphi published methods, and decompile everything that references
> `KSTRINGB`.

## CLI quickstart

```bash
ih8sn1ff info sample.exe
ih8sn1ff strings sample.exe --regex "AT\\+" --min-len 6
ih8sn1ff entropy sample.exe --window 1M
ih8sn1ff dump 7123 --out dumps/ --include-main
ih8sn1ff rebuild dumps/00_main.exe.bin -o out/rebuilt.exe
ih8sn1ff trim out/rebuilt.exe -o out/trimmed.exe --scratch-prefix-end 0x1A00000
ih8sn1ff delphi out/main.bin --names-file names.txt
ih8sn1ff disasm out/main.bin --addr 0x163a454 --count 80
ih8sn1ff xrefs out/main.bin --string "KSTRINGB"
ih8sn1ff ghidra import out/trimmed.exe --project out/ghidra_proj
ih8sn1ff ghidra decompile out/ghidra_proj --rva 0x163a454 --rva 0x165103c
ih8sn1ff imports dumps/00_main.exe.bin -o out/rebuilt.exe --meta dumps/dump_meta.json
ih8sn1ff xrefs-rip out/trimmed.exe --string "KSTRINGB"
ih8sn1ff callgraph out/trimmed.exe --root 0x163a454 --depth 2
ih8sn1ff emulate out/trimmed.exe --entry 0x163a454 --max-instructions 500
ih8sn1ff dbg once C:/target/app.exe --dump out/entrydump
ih8sn1ff yara sample.exe
```

## Tools

See [docs/TOOLS.md](docs/TOOLS.md) for the full parameter/output reference.
Highlights:

| Tool | Purpose |
|---|---|
| `bin_info` | format, arch, sections, entropy, compiler/linker markers |
| `strings_scan` | ASCII/UTF-16 strings with offsets, regex, min length |
| `entropy_map` | windowed entropy to separate code/data/packed regions |
| `run_and_dump` | launch (elevated) and snapshot module images — the unpacking step |
| `dump_process` | dump modules of an already-running PID |
| `rebuild_pe` | memory image → file-aligned PE (Scylla-style unmap) |
| `trim_pe` | analysis-sized PE for Ghidra (code sections + VA prefix) |
| `delphi_methods` | published-method RTTI: `name → code RVA` |
| `disasm` | Capstone listing with inline string-ref annotations |
| `xrefs` | absolute-immediate xrefs to strings/values inside code ranges |
| `xrefs_rip` / `callgraph` | RIP-relative refs and direct-call graphs |
| `emulate` | bounded Unicorn trace at an entry RVA |
| `debug_launch` … `debug_close` | live Windows sessions (x64 or WOW64 x86): breakpoints, registers, memory, module dumps |
| `rebuild_imports` | IAT/import directory rebuild from `dump_meta.json` |
| `evidence_list` / `evidence_read` | journaled tool results with digests |
| `ghidra_import` | headless import + auto-analysis into a project |
| `ghidra_decompile` | decompile by RVA list or by string keywords |
| `dotnet_types` / `dotnet_type` | ILSpy type inventory / decompile |
| `yara_scan` / `yara_pack` | YARA scan; bundled packer/anti-debug rules by default |

## Workflows

`docs/WORKFLOWS.md` covers, step by step:

1. Unpacking VMProtect/Themida-class targets by **runtime dumping** (including the
   per-function encryption wrinkle — features must execute before their code decrypts).
2. Rebuilding PEs from memory images and rebuilding the IAT from `dump_meta.json`.
3. Delphi app triage: RTTI method tables, unit/class inventories, DFM islands.
4. Ghidra headless decompilation driven by strings, not symbol names.
5. Live x64 debugging and bounded emulation for decrypt-on-execute targets.
6. When to stop scripting and switch to manual x64dbg / Frida.

## Ethics and legal

ih8Sn1ff is a dual-use engineering toolkit for **authorized** reverse engineering:
malware analysis, interoperability, security research, CTFs, and software you own
or are licensed to inspect. Do not use it to bypass licensing, DRM, or access
controls on systems you do not own. The authors take no responsibility for misuse.

## Status

v0.3 — 35 MCP tools: runtime dump + PE/IAT rebuild, live debugger (x64 and
WOW64 x86), Unicorn emulation, Delphi RTTI, Ghidra headless, .NET, YARA,
evidence journal. The `ih8sn1ff` name was available on PyPI on 2026-10-19
(HTTP 404); publishing still needs the owner's token. Known limits: import
rebuild is experimental on heavily obfuscated/hooked IATs; VMProtect/Themida
devirtualization is not automated (the runtime-dump workflow is).
Contributions welcome; see `CONTRIBUTING.md`.
