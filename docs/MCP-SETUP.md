# MCP setup for other developers

ih8Sn1ff ships a stdio MCP server: `ih8sn1ff-mcp`. Any MCP-capable client can
use it. The server exposes 35 tools: static analysis, process dumping, PE/IAT
rebuild, live x64 debugging, emulation, Ghidra headless, .NET, YARA, evidence.

## 1. Install

From a GitHub checkout (until the PyPI name is published):

```bash
pipx install "git+https://github.com/ih8w1nd/ih8sn1ff"
```

or with extras (ELF metadata, Unicorn emulation, YARA):

```bash
pipx install "ih8sn1ff[all] @ git+https://github.com/ih8w1nd/ih8sn1ff"
```

Plain pip also works:

```bash
pip install "ih8sn1ff[all] @ git+https://github.com/ih8w1nd/ih8sn1ff"
```

Verify:

```bash
ih8sn1ff info C:/Windows/System32/notepad.exe
ih8sn1ff-mcp        # starts the stdio server; Ctrl+C to stop
```

Optional engines:

| Engine | Requirement |
|---|---|
| Ghidra headless | `GHIDRA_INSTALL_DIR` pointing at an extracted Ghidra 12.x |
| .NET decompile | `dotnet tool install -g ilspycmd` |
| YARA | `pip install ih8sn1ff[yara]` |
| Emulation | `pip install ih8sn1ff[emu]` |

## 2. Claude Code

Project-level `.mcp.json` (copy `examples/mcp.json`):

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

Or register it once for the user:

```bash
claude mcp add ih8sn1ff -- ih8sn1ff-mcp
claude mcp add ih8sn1ff -e GHIDRA_INSTALL_DIR=C:/tools/ghidra_12.1.4_PUBLIC -- ih8sn1ff-mcp
```

Restart the session, then `/mcp` should list 35 tools.

## 3. Claude Desktop

Config file:

- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

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

Restart the app after saving.

## 4. Cursor

Project file `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "ih8sn1ff": { "command": "ih8sn1ff-mcp" }
  }
}
```

## 5. uv / ephemeral runs

```bash
uvx --from "git+https://github.com/ih8w1nd/ih8sn1ff" ih8sn1ff-mcp
```

Use `uvx --from "ih8sn1ff[all]" ih8sn1ff-mcp` after PyPI publication.

## 6. Troubleshooting

- `ModuleNotFoundError: mcp.server.fastmcp` means the MCP SDK is v2; the
  package pins `mcp>=1.0,<2`. Reinstall with pip to get the pinned version.
- Access denied when dumping: the target is elevated. Start the MCP host
  (terminal/IDE) elevated only if you trust the target.
- Debugging supports x64 and 32-bit WOW64 targets on 64-bit Windows; native
  32-bit Windows is not supported.
- Unicorn on Windows may print a one-off "Windows fatal exception" line from
  inside `uc_mem_map`; it is handled by Unicorn and does not affect results.
- Evidence journal: `~/.ih8sn1ff/evidence/*.jsonl`, overridable with
  `IH8SN1FF_EVIDENCE_DIR`.
