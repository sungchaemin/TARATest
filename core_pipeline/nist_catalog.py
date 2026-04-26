"""Small read-only lookup for NIST SP 800-53 rev5 control statements.

Source: inputs/nist_800_53_rev5.json (snapshot produced from the
official xlsx catalog). Contains {id, name, control_text} per entry —
Discussion, related_controls, and assessment objectives are intentionally
omitted to keep prompt payloads lean and on-topic.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_CATALOG_PATH = Path(__file__).resolve().parent / "inputs" / "nist_800_53_rev5.json"


@lru_cache(maxsize=1)
def _load() -> dict[str, dict]:
    if not _CATALOG_PATH.exists():
        return {}
    with _CATALOG_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def get_control(control_id: str) -> dict | None:
    """Return {id, name, control_text} for the given NIST control ID,
    or None if the ID is not in the catalog."""
    if not control_id:
        return None
    return _load().get(control_id.strip())


def render_controls(control_ids: list[str]) -> str:
    """Render a compact markdown-style list of control statements for
    injection into an LLM prompt. Unknown IDs are listed with a note."""
    lines: list[str] = []
    for cid in control_ids:
        entry = get_control(cid)
        if entry is None:
            lines.append(f"- {cid}: (not found in catalog)")
            continue
        text = entry["control_text"].strip()
        lines.append(f"- {entry['id']} — {entry['name']}:\n    "
                     + text.replace("\n", "\n    "))
    return "\n".join(lines)
