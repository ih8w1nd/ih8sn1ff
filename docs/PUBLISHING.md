# Publishing ih8Sn1ff

This directory is ready to become a GitHub repository; no VCS metadata is
included. Run these commands yourself from the repository root.

## Push to GitHub

```bash
git init -b main
git add .
git commit -m "feat: ih8Sn1ff v0.3.0 — MCP-native reverse-engineering toolkit"
git remote add origin https://github.com/ih8w1nd/ih8sn1ff.git
git push -u origin main
```

Prefer the GitHub UI: create an empty repo, then follow its "push an existing
repository" instructions with the same commands.

If the repository does not exist yet and `gh` is authenticated:

```bash
gh repo create ih8w1nd/ih8sn1ff --public --source . --remote origin --push
```

GitHub CLI authentication (`gh auth login`) is a one-time interactive browser
step; it cannot be completed from a non-interactive script without credentials.

## Before publishing

- Add a demo GIF or screenshot of a real `run_and_dump -> rebuild_pe ->
  ghidra_decompile` session to the README.
- Confirm `.gitignore` covers your local analysis output before `git add .`
  (`dumps/`, `ghidra_proj/`, binaries).
- Review the ethics section; it defines the intended use.
- `pytest -q` and `ruff check src tests` must pass (CI runs both).

## Build a wheel

```bash
python -m pip install build
python -m build
```

Artifacts land in `dist/`. Publishing to PyPI:

```bash
python -m twine upload dist/*
```

The `ih8sn1ff` name was available on PyPI on 2026-10-19 (HTTP 404); availability
can change, so register/publish early. Publishing requires the owner's PyPI
token; the repository cannot do it.

## MCP client registration

Clients that accept `.mcp.json` can use `examples/mcp.json` as-is. For other
hosts, register a stdio server:

- command: `ih8sn1ff-mcp`
- env: `GHIDRA_INSTALL_DIR=<extracted Ghidra>`

The server depends on the MCP Python SDK v1 (`mcp>=1.0,<2`); v2 renamed
`FastMCP` and is intentionally not adopted yet.

## Versioning

Follow SemVer. The MCP tool surface is the public API: removing or renaming a
tool is a breaking change. Add new tools with additive parameters only.
