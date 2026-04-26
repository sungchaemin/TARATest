"""
RAG retriever for Step 2 enrichment.

Searches 4 sources and returns relevant context for each attack step:
  1. K-CSMS.md       — test case procedures (Precondition/Procedure/Keywords)
  2. atm_rag_chunks   — ATM technique descriptions
  3. RAG_AUTO_ISAC    — AUTO-ISAC threat techniques
  4. AAD database     — real-world automotive attack records

Returns plain text snippets suitable for inclusion in LLM prompts.
No embeddings — uses keyword matching for MVP simplicity.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from pipeline_types import NormalizedScenario, StepPlan


# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------

_RAG_DIR = Path(__file__).resolve().parent / "RAG" / "STEP2"


# ---------------------------------------------------------------------------
# K-CSMS parser
# ---------------------------------------------------------------------------

def _parse_kcsms(path: Path) -> list[dict[str, str]]:
    """Parse K-CSMS.md into a list of test case dicts."""
    text = path.read_text(encoding="utf-8")
    cases: list[dict[str, str]] = []
    # Split on test case headers.
    blocks = re.split(r"^## Test Case:\s*", text, flags=re.MULTILINE)
    for block in blocks[1:]:  # skip preamble
        case: dict[str, str] = {}
        # Extract case ID from first line.
        first_line = block.split("\n")[0].strip()
        case["id"] = first_line

        for section in ["Title", "Overview", "Precondition", "Procedure", "Keywords"]:
            match = re.search(
                rf"^### {section}\s*\n(.*?)(?=^### |\Z)",
                block,
                re.MULTILINE | re.DOTALL,
            )
            if match:
                case[section.lower()] = match.group(1).strip()

        cases.append(case)
    return cases


def _search_kcsms(
    cases: list[dict[str, str]],
    keywords: list[str],
    top_k: int = 2,
) -> list[dict[str, str]]:
    """Score and return top-k K-CSMS cases by keyword overlap."""
    scored: list[tuple[int, dict[str, str]]] = []
    for case in cases:
        searchable = " ".join(case.values()).lower()
        score = sum(1 for kw in keywords if kw.lower() in searchable)
        if score > 0:
            scored.append((score, case))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [c for _, c in scored[:top_k]]


# ---------------------------------------------------------------------------
# ATM chunks
# ---------------------------------------------------------------------------

def _load_atm_chunks(path: Path) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("chunks", [])


def _search_atm(
    chunks: list[dict[str, Any]],
    keywords: list[str],
    top_k: int = 2,
) -> list[dict[str, Any]]:
    scored: list[tuple[int, dict[str, Any]]] = []
    for chunk in chunks:
        searchable = f"{chunk.get('name', '')} {chunk.get('text', '')}".lower()
        score = sum(1 for kw in keywords if kw.lower() in searchable)
        if score > 0:
            scored.append((score, chunk))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [c for _, c in scored[:top_k]]


# ---------------------------------------------------------------------------
# AUTO-ISAC
# ---------------------------------------------------------------------------

def _load_auto_isac(path: Path) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _search_auto_isac(
    entries: list[dict[str, Any]],
    keywords: list[str],
    top_k: int = 2,
) -> list[dict[str, Any]]:
    scored: list[tuple[int, dict[str, Any]]] = []
    for entry in entries:
        searchable = f"{entry.get('name', '')} {entry.get('description', '')} {entry.get('tactic', '')}".lower()
        score = sum(1 for kw in keywords if kw.lower() in searchable)
        if score > 0:
            scored.append((score, entry))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [c for _, c in scored[:top_k]]


# ---------------------------------------------------------------------------
# AAD database
# ---------------------------------------------------------------------------

def _search_aad(
    db_path: Path,
    keywords: list[str],
    top_k: int = 2,
) -> list[dict[str, str]]:
    """Search AAD SQLite database by keywords in Description and Interface."""
    if not db_path.exists():
        return []

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Build WHERE clause matching any keyword in Description.
    conditions = " OR ".join(
        f'Description LIKE ?' for _ in keywords
    )
    params = [f"%{kw}%" for kw in keywords]

    try:
        rows = cursor.execute(
            f'SELECT ID, Description, "Attack Class", Interface, Tool '
            f'FROM "Automotive Security Attacks" '
            f'WHERE {conditions} '
            f'LIMIT ?',
            params + [top_k],
        ).fetchall()
    except Exception:
        conn.close()
        return []

    results = []
    for row in rows:
        results.append({
            "id": row["ID"],
            "description": row["Description"],
            "attack_class": row["Attack Class"],
            "interface": row["Interface"],
            "tool": row["Tool"],
        })
    conn.close()
    return results


# ---------------------------------------------------------------------------
# Keyword extraction
# ---------------------------------------------------------------------------

def _extract_keywords(
    step: StepPlan,
    scenario: NormalizedScenario,
) -> list[str]:
    """Extract search keywords from step and scenario context."""
    keywords: list[str] = []

    # From step description — extract meaningful terms.
    desc_lower = step.description.lower()
    # Protocol/technology terms.
    for term in ["d-bus", "dbus", "can", "doip", "some/ip", "someip",
                 "uds", "obd", "ethernet", "tcp", "spi", "ota",
                 "routing activation", "diagnosticsessioncontrol",
                 "securityaccess", "ecureset", "writedatabyidentifier",
                 "readdatabyidentifier", "firmware", "gps", "hvac",
                 "service discovery"]:
        if term in desc_lower:
            keywords.append(term)

    # Transport name.
    if step.transport_name:
        keywords.append(step.transport_name)

    # Connection protocol.
    if step.connection and step.connection.protocol:
        # Add short form.
        proto = step.connection.protocol.lower()
        for term in ["doip", "can", "dbus", "d-bus", "some/ip", "someip", "spi"]:
            if term in proto:
                keywords.append(term)

    # Action verbs from description.
    for verb in ["inject", "spoof", "sniff", "enumerate", "scan",
                 "exploit", "flash", "invoke", "authenticate",
                 "brute force", "replay", "manipulate"]:
        if verb in desc_lower:
            keywords.append(verb)

    # Fallback: extract general meaningful words from description.
    # This ensures unseen protocols/terms still produce search hits.
    _STOPWORDS = {
        "the", "a", "an", "to", "from", "for", "in", "on", "of", "and",
        "or", "is", "are", "was", "were", "be", "by", "at", "with",
        "without", "that", "this", "which", "its", "via", "using",
        "whether", "not", "no", "any", "all", "has", "have", "had",
    }
    words = re.findall(r"[a-zA-Z0-9]+", desc_lower)
    general = [w for w in words if len(w) >= 3 and w not in _STOPWORDS]
    keywords.extend(general[:5])

    # Deduplicate while preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for kw in keywords:
        if kw not in seen:
            seen.add(kw)
            unique.append(kw)

    return unique if unique else ["automotive", "security", "attack"]


# ---------------------------------------------------------------------------
# Format results into prompt context
# ---------------------------------------------------------------------------

def _format_kcsms(cases: list[dict[str, str]]) -> str:
    if not cases:
        return ""
    parts: list[str] = ["[K-CSMS Reference Procedures]"]
    for case in cases:
        parts.append(f"Test Case: {case.get('id', '?')}")
        if case.get("title"):
            parts.append(f"  Title: {case['title']}")
        if case.get("precondition"):
            parts.append(f"  Precondition: {case['precondition']}")
        if case.get("procedure"):
            parts.append(f"  Procedure: {case['procedure']}")
        if case.get("keywords"):
            parts.append(f"  Keywords: {case['keywords']}")
        parts.append("")
    return "\n".join(parts)


def _format_atm(chunks: list[dict[str, Any]]) -> str:
    if not chunks:
        return ""
    parts: list[str] = ["[ATM Attack Techniques]"]
    for chunk in chunks:
        text = chunk.get("text", "")
        # Truncate to first 300 chars.
        if len(text) > 300:
            text = text[:300] + "..."
        parts.append(f"{chunk.get('id', '?')}: {chunk.get('name', '?')}")
        parts.append(f"  {text}")
        parts.append("")
    return "\n".join(parts)


def _format_auto_isac(entries: list[dict[str, Any]]) -> str:
    if not entries:
        return ""
    parts: list[str] = ["[AUTO-ISAC Threat Techniques]"]
    for entry in entries:
        desc = entry.get("description", "")
        if len(desc) > 300:
            desc = desc[:300] + "..."
        parts.append(f"{entry.get('id', '?')}: {entry.get('name', '?')} (tactic: {entry.get('tactic', '?')})")
        parts.append(f"  {desc}")
        parts.append("")
    return "\n".join(parts)


def _format_aad(records: list[dict[str, str]]) -> str:
    if not records:
        return ""
    parts: list[str] = ["[AAD Real-World Attack Records]"]
    for rec in records:
        desc = rec.get("description", "")
        if len(desc) > 200:
            desc = desc[:200] + "..."
        parts.append(f"{rec.get('id', '?')}: {desc}")
        parts.append(f"  Attack Class: {(rec.get('attack_class', ''))[:100]}")
        parts.append(f"  Interface: {(rec.get('interface', ''))[:80]}")
        parts.append("")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class RAGContext:
    """Loaded RAG sources — reusable across multiple steps."""

    def __init__(self, rag_dir: Path | str | None = None):
        d = Path(rag_dir) if rag_dir else _RAG_DIR

        self._kcsms_cases = _parse_kcsms(d / "K-CSMS.md") if (d / "K-CSMS.md").exists() else []
        self._atm_chunks = _load_atm_chunks(d / "atm_rag_chunks.json") if (d / "atm_rag_chunks.json").exists() else []
        self._auto_isac = _load_auto_isac(d / "RAG_AUTO_ISAC_final.json") if (d / "RAG_AUTO_ISAC_final.json").exists() else []
        self._aad_path = d / "Automotive_Attack_Database_(AAD)_V3.0.db"

    def retrieve(
        self,
        step: StepPlan,
        scenario: NormalizedScenario,
        max_snippets: int = 6,
    ) -> str:
        """Retrieve relevant RAG context for a step as formatted text.

        Args:
            max_snippets: hard cap on total snippets across all 4 sources.
                          Budget: K-CSMS 2, ATM 1, AUTO-ISAC 1, AAD 2.
                          Unused slots from empty sources are not redistributed.

        Returns a single string suitable for inclusion in an LLM prompt.
        """
        # Budget per source — sum <= max_snippets.
        budget_kcsms = min(2, max_snippets)
        budget_atm = min(1, max_snippets)
        budget_isac = min(1, max_snippets)
        budget_aad = min(2, max_snippets)

        keywords = _extract_keywords(step, scenario)

        kcsms = _search_kcsms(self._kcsms_cases, keywords, budget_kcsms)
        atm = _search_atm(self._atm_chunks, keywords, budget_atm)
        auto_isac = _search_auto_isac(self._auto_isac, keywords, budget_isac)
        aad = _search_aad(self._aad_path, keywords, budget_aad)

        # Enforce hard cap.
        all_counts = len(kcsms) + len(atm) + len(auto_isac) + len(aad)
        if all_counts > max_snippets:
            # Trim from lowest-priority source first (AAD > AUTO-ISAC > ATM).
            over = all_counts - max_snippets
            while over > 0 and len(aad) > 1:
                aad.pop()
                over -= 1
            while over > 0 and len(auto_isac) > 0:
                auto_isac.pop()
                over -= 1
            while over > 0 and len(atm) > 0:
                atm.pop()
                over -= 1

        sections = [
            _format_kcsms(kcsms),
            _format_atm(atm),
            _format_auto_isac(auto_isac),
            _format_aad(aad),
        ]

        result = "\n".join(s for s in sections if s)
        return result if result else "[No relevant RAG context found]"
