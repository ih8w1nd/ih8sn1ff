"""YARA scanning with bundled packer / anti-debug profiles."""

from __future__ import annotations

from pathlib import Path

from .util import OmniError

RULES_DIR = Path(__file__).parent / "rules"


def _compile(rules_file: str | None):
    try:
        import yara  # type: ignore
    except ImportError as exc:
        raise OmniError("yara-python not installed — pip install ih8sn1ff[yara]") from exc
    if rules_file:
        path = Path(rules_file)
        if not path.is_file():
            raise OmniError(f"rules file not found: {path}")
        try:
            return yara.compile(filepath=str(path)), str(path)
        except yara.Error as exc:  # type: ignore[attr-defined]
            raise OmniError(f"invalid YARA rules: {exc}") from exc
    files = {path.stem: str(path) for path in sorted(RULES_DIR.glob("*.yar"))}
    if not files:
        raise OmniError("bundled YARA rules are missing from the package")
    try:
        return yara.compile(filepaths=files), "bundled"
    except yara.Error as exc:  # type: ignore[attr-defined]
        raise OmniError(f"invalid bundled YARA rules: {exc}") from exc


def yara_scan(path: str, rules_file: str | None = None) -> dict:
    """Run YARA rules against a file.

    Without ``rules_file`` the bundled packers + anti-debug rules are used.
    """
    if not Path(path).is_file():
        raise OmniError(f"file not found: {path}")
    rules, source = _compile(rules_file)
    matches = rules.match(path)
    return {
        "path": path,
        "rules": source,
        "matches": [
            {"rule": match.rule, "namespace": match.namespace, "tags": list(match.tags)}
            for match in matches
        ],
    }


def yara_pack(path: str, rules_file: str | None = None) -> dict:
    """Backwards-friendly alias for :func:`yara_scan`."""
    return yara_scan(path, rules_file)
