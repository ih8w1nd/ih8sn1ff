# Changelog

All notable changes to this project are documented here.

## [0.3.0] - 2026-10-19

### Added

- 32-bit WOW64 debugging: WOW64 thread contexts, x86 register sets, and the
  `STATUS_WX86_BREAKPOINT` / `STATUS_WX86_SINGLE_STEP` exception codes.
- IAT rebuild resolves ordinal-only exports and reports `unresolved_samples`
  with module and RVA details.

### Changed

- Verified that the `ih8sn1ff` name is available on PyPI (2026-10-19, HTTP 404);
  publishing still requires the owner's token.

## [0.2.0] - 2026-10-19

### Changed

- Renamed OmniRE to **ih8Sn1ff**: package/CLI `ih8sn1ff`, MCP server
  `ih8sn1ff-mcp`. MCP surface grew from 18 to 35 tools.

### Added

- Live x64 debugger sessions (`debug_launch` through `debug_close`): software
  breakpoints with single-step rearm, register/memory access, and module dumps
  at a stop. CLI: `ih8sn1ff dbg shell` / `dbg once`.
- Scylla-style IAT rebuild (`rebuild_imports`) from `dump_meta.json`; dumps now
  write full module metadata including non-dumped system modules.
- RVA-space PE mapping (`pemap`), RIP-relative xrefs and direct-call graphs
  (`xrefs_rip`, `callgraph`).
- Bounded Unicorn emulation (`emulate`).
- Evidence journal (`evidence_list`, `evidence_read`) wrapping MCP tool calls.
- Bundled YARA packer/anti-debug profiles; `yara_pack` alias.
- Windows CI workflow; MCP setup guide for Claude Code, Desktop, Cursor, uv.

### Fixed

- Emulation maps from 0x1000: mapping page zero crashes Unicorn on Windows.
- INT3 hits derive the address from the stopped thread context, not
  `ExceptionAddress`, preventing resume-at-entry+1 access violations.
- Import descriptors/thunks store absolute RVAs in the rebuilt `.idata2`.

## [0.1.0] - 2026-10-19

### Added

- Core static tools: `bin_info`, `strings_scan`, `entropy_map`, `find_blobs`.
- Runtime tools: `dump_process`, `run_and_dump` (Windows, elevated-capable).
- PE pipeline: `rebuild_pe` (memory image -> file-aligned PE) and `trim_pe`
  (analysis-sized PE with protector-arena prefix retention).
- Delphi tools: `delphi_methods` (published-method name -> code RVA),
  `delphi_units` (unit/class inventory).
- Disassembly tools: `disasm` (Capstone with inline string annotations) and
  `xrefs` (absolute-immediate references, Delphi shifts included).
- Ghidra headless integration: `ghidra_import`, `ghidra_decompile`,
  `ghidra_funcs` with bundled `DecompileTargets`, `DecompileByStrings` and
  `ListFunctions` postScripts.
- Managed code: `dotnet_types`, `dotnet_type` via ilspycmd.
- Optional YARA scanning.
- MCP stdio server (`ih8sn1ff-mcp`) and CLI (`ih8sn1ff`) with an identical tool
  surface.
- Docs: tool reference and end-to-end workflows for VMProtect/Themida-class
  runtime dumping.
