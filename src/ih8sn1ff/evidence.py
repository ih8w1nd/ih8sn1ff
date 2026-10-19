"""Append-only evidence journal for tool calls.

Every MCP tool result can be recorded as a JSONL entry with a content digest,
so an agent can revisit earlier observations by id instead of re-running the
tool. Storage lives outside the repository (``~/.ih8sn1ff/evidence``) and is
overridable with ``IH8SN1FF_EVIDENCE_DIR``.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path

from .util import OmniError

MAX_RESULT_BYTES = 2 * 1024 * 1024


def _root() -> Path:
    root = Path(
        os.environ.get("IH8SN1FF_EVIDENCE_DIR", "")
        or (Path.home() / ".ih8sn1ff" / "evidence")
    )
    root.mkdir(parents=True, exist_ok=True)
    return root


def _serialize(payload) -> str:
    return json.dumps(payload, ensure_ascii=False, default=str)


def record(tool: str, params: dict, result) -> dict:
    """Store one tool call and return its journal entry."""
    entry_id = f"ev_{uuid.uuid4().hex[:16]}"
    rendered = _serialize(result)
    if len(rendered.encode("utf-8")) > MAX_RESULT_BYTES:
        result = {
            "_truncated": True,
            "sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
            "preview": rendered[:2000],
        }
    entry = {
        "id": entry_id,
        "tool": tool,
        "time": time.time(),
        "params": params,
        "result": result,
    }
    encoded = _serialize(entry)
    entry["sha256"] = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    path = _root() / f"{time.strftime('%Y%m%d')}.jsonl"
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(_serialize(entry) + "\n")
    return entry


def capture(tool: str, params: dict, result):
    """Record ``result`` and return it unchanged to the caller."""
    try:
        record(tool, params, result)
    except OSError:
        pass  # evidence must never break the tool call itself
    return result


def list_records(limit: int = 50) -> dict:
    """Newest-first summary of recorded evidence."""
    files = sorted(_root().glob("*.jsonl"), reverse=True)
    records = []
    for path in files:
        try:
            lines = path.read_text("utf-8").splitlines()
        except OSError:
            continue
        for line in reversed(lines):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            records.append(
                {
                    "id": entry.get("id"),
                    "tool": entry.get("tool"),
                    "time": entry.get("time"),
                    "sha256": entry.get("sha256"),
                }
            )
            if len(records) >= limit:
                return {"records": records, "truncated": True}
    return {"records": records, "truncated": False}


def read_record(evidence_id: str) -> dict:
    """Return one full evidence record by id."""
    if not evidence_id.startswith("ev_"):
        raise OmniError("evidence id must start with ev_")
    for path in sorted(_root().glob("*.jsonl"), reverse=True):
        try:
            lines = path.read_text("utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("id") == evidence_id:
                return entry
    raise OmniError(f"evidence not found: {evidence_id}")
