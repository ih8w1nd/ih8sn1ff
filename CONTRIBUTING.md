# Contributing

Thanks for helping ih8Sn1ff. Keep changes small, tested and documented.

## Setup

```bash
pip install -e ".[dev,elf,yara]"
pytest -q
ruff check src tests
```

## Rules

- Every new capability gets: a core function, a thin `mcp_server.py` tool
  wrapper, a CLI subcommand, and at least one test.
- Tools must be deterministic and bounded: no unbounded loops over input,
  explicit `limit` parameters with a reported `truncated` flag.
- Errors: raise `OmniError` with an actionable message. Never swallow.
- Windows-only code paths must raise a clear `OmniError` on other platforms.
- No network access in core tools. Ghidra/ilspycmd subprocesses are allowed
  and must be timeout-bounded.
- Comments in English. Public function docstrings are MCP tool descriptions —
  write them for an agent, not for a human skimming source.

## Adding a Ghidra postScript

Java scripts live in `src/ih8sn1ff/scripts/ghidra/`, are passed via
`-scriptPath` automatically, and must print results to stdout with
`===`-style section headers so the caller can split them.

## Pull requests

1. Describe the workflow the change enables, not only the diff.
2. Include a sample command + output in the PR body.
3. Keep the ethics section of the README accurate.

## Legal

Contributions must not include code whose only purpose is license/DRM/access
control bypass, nor vendor-confidential material obtained unauthorized.
