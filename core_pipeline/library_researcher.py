"""Library research stage — runs ONCE per (protocol, scheme) at step3a time.

Goal: replace LLM imagination of which Python library to use with an LLM
research pass that fetches official docs (via Anthropic's web_search tool)
and returns a ranked candidate list. The chosen candidates are stamped onto
every TargetBinding sharing the same (protocol, scheme), guaranteeing
path-level library consistency and eliminating "wrong library" timeouts at
testbed time.

Public API:
    research_libraries(protocol, scheme, endpoint_summary, *, api_key=None,
                       model="claude-sonnet-4-6") -> list[dict]

Returned candidates are dicts with: name, import_module, rationale,
evidence_url, evidence_quote.

Caching: in-process dict keyed by (protocol, scheme) so a scenario with N
paths over the same protocol pays the LLM cost once. Pass `cache_clear()` if
running in long-lived processes that need invalidation.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any


_CACHE: dict[tuple[str, str], list[dict[str, Any]]] = {}


_SYSTEM_PROMPT = """You are a Python library researcher. Given a network
binding (protocol over a transport scheme) you must identify Python
libraries that documentably support BOTH the protocol AND the transport,
then return a ranked JSON list of candidates.

Use the web_search tool to find candidate libraries on PyPI / GitHub /
readthedocs. For each candidate, fetch the official docs (README,
API reference) and confirm transport support BY QUOTE — do not
infer. If a library's docs only mention a different transport (e.g. a
D-Bus library that only documents unix sockets), exclude it.

Reject candidates that:
  - have no documentation evidence of the transport
  - are unmaintained for 3+ years with no recent release
  - require non-Python system dependencies that the testbed cannot satisfy
    (e.g. a compiled C extension tied to a specific OS service)

Output STRICT JSON (no prose, no code fences) with this schema:
{
  "candidates": [
    {
      "name": "<human-readable lib name>",
      "import_module": "<top-level module name as used in `import X`>",
      "import_examples": [
        "<exact `from X.Y import Z` line that the docs use to bring in the bus/client class>",
        "<additional supporting `from ... import ...` lines (Message, Variant, errors, etc.)>"
      ],
      "rationale": "<one sentence on why this fits protocol+transport>",
      "evidence_url": "<URL of the docs page that proves transport support>",
      "evidence_quote": "<short verbatim quote from that page>"
    }
  ],
  "notes": "<one-line summary of how you searched, e.g. 'searched PyPI for d-bus tcp; reviewed dbus-next, jeepney, dbus-python docs'>"
}

`import_examples` is REQUIRED. Each line must be verifiable against the
library's public module tree — the submodule path and the imported
symbol must actually exist in the installed package. Do NOT invent
submodule paths or shorten real ones. For example, if a class lives at
`<pkg>.<submodule>` rather than at the top level, write the full path;
a hallucinated path here will cause downstream code generation to fail
at import time. Include all import lines the caller is likely to need
(connection/bus class, message/request types, error/exception types,
and any auth or handshake symbols relevant to the transport) — do not
restrict the list to a minimal happy-path example.

Order candidates from best fit to worst. Empty list if NO library
documentably supports the combination — set notes to explain.
"""


def _build_user_prompt(protocol: str, scheme: str, endpoint_summary: str) -> str:
    return (
        "Find Python libraries that support this binding:\n"
        f"  protocol: {protocol}\n"
        f"  transport scheme: {scheme}\n"
        f"  endpoint summary: {endpoint_summary}\n\n"
        "Return JSON per the schema in the system prompt. Use web_search to "
        "find candidates and fetch their docs. Cite a documentation URL + "
        "quote for each candidate's transport support."
    )


def _call_anthropic_with_search(
    system: str,
    user: str,
    api_key: str | None,
    model: str,
    max_uses: int = 8,
) -> str:
    """Anthropic call with server-side web_search tool enabled."""
    import anthropic

    client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
    resp = client.messages.create(
        model=model,
        max_tokens=4096,
        system=system,
        tools=[
            {
                "type": "web_search_20250305",
                "name": "web_search",
                "max_uses": max_uses,
            }
        ],
        messages=[{"role": "user", "content": user}],
    )
    return "".join(
        block.text for block in resp.content if getattr(block, "type", "") == "text"
    )


def _extract_json(text: str) -> dict[str, Any]:
    """Tolerant JSON extractor — peels code fences, picks the largest {...}."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```\s*$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    matches = re.findall(r"\{.*\}", text, re.DOTALL)
    if not matches:
        return {}
    matches.sort(key=len, reverse=True)
    for m in matches:
        try:
            return json.loads(m)
        except json.JSONDecodeError:
            continue
    return {}


def _normalize_candidates(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw = payload.get("candidates") or []
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for c in raw:
        if not isinstance(c, dict):
            continue
        name = str(c.get("name", "")).strip()
        mod = str(c.get("import_module", "")).strip()
        if not mod:
            continue
        raw_examples = c.get("import_examples") or []
        if isinstance(raw_examples, str):
            raw_examples = [raw_examples]
        examples: list[str] = []
        if isinstance(raw_examples, list):
            for ex in raw_examples:
                ex_s = str(ex).strip()
                if ex_s:
                    examples.append(ex_s)
        out.append(
            {
                "name": name or mod,
                "import_module": mod,
                "import_examples": examples,
                "rationale": str(c.get("rationale", "")).strip(),
                "evidence_url": str(c.get("evidence_url", "")).strip(),
                "evidence_quote": str(c.get("evidence_quote", "")).strip(),
            }
        )
    return out


def research_libraries(
    protocol: str,
    scheme: str,
    endpoint_summary: str = "",
    *,
    api_key: str | None = None,
    model: str = "claude-sonnet-4-6",
    use_cache: bool = True,
) -> list[dict[str, Any]]:
    """Research Python library candidates for a (protocol, scheme) pair.

    Returns a list of candidate dicts (possibly empty). Empty list signals
    "no library documentably supports this combination" — caller decides
    whether to fall back (raw socket) or block.
    """
    protocol = (protocol or "").strip()
    scheme = (scheme or "").strip()
    if not protocol and not scheme:
        return []
    key = (protocol.lower(), scheme.lower())
    if use_cache and key in _CACHE:
        return _CACHE[key]

    user = _build_user_prompt(protocol, scheme, endpoint_summary)
    try:
        raw = _call_anthropic_with_search(_SYSTEM_PROMPT, user, api_key, model)
    except Exception as e:  # noqa: BLE001
        # Network / API failure — return empty so caller can decide
        if os.environ.get("LIBRARY_RESEARCHER_DEBUG"):
            print(f"[library_researcher] API call failed: {type(e).__name__}: {e}")
        _CACHE[key] = []
        return []

    payload = _extract_json(raw)
    candidates = _normalize_candidates(payload)
    if use_cache:
        _CACHE[key] = candidates
    return candidates


def cache_clear() -> None:
    _CACHE.clear()
