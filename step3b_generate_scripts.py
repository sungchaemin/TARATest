"""
Step 3-2: Generate executable test scripts per step.

Input per call (one step):
  - the AttackStep (description, connection)
  - assigned_controls from Step 3-1 for that step
  - path and scenario context (cybersecurity_goal, path_description)
  - transport name (informational; used only by shared-template shortcuts)

Output:
  - StepScript: a Python source string defining run_step(context, artifacts)
    that EXECUTES the attempt, CAPTURES observed values, and RETURNS the
    StepRunResult contract — WITHOUT deciding pass/fail (that is Step 4B).

Modes:
  - stub (default): deterministic transport skeleton that does the bare
    attempt and returns empty assertion_results. Used when LLM is off or
    when the LLM response fails validation.
  - LLM: pluggable callable that returns Python source.
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import contract_verifier
import safety_validator
try:
    from nist_catalog import render_controls as _render_nist
except ImportError:
    # Fallback when nist_catalog is not available
    def _render_nist(ids: list[str]) -> str:
        return f"(NIST SP 800-53 catalog not available - would render: {', '.join(ids)})"
from pipeline_types import (
    ArtifactRef,
    AttackPath,
    AttackStep,
    ControlRef,
    NormalizedScenario,
    StepBinding,
    StepPlan,
    StepScript,
    TargetBinding,
)


# ---------------------------------------------------------------------------
# Node-share cache (cross-path reuse of identically-shaped step scripts)
# ---------------------------------------------------------------------------
# When two attack paths in the same scenario share an upstream step (typically
# T1 enumeration) with identical step_plan + target_binding + step content,
# we should not re-invoke the LLM for the second path — the inputs are byte-
# for-byte equivalent so the script would too. Re-generation is also actively
# harmful: a fresh LLM call can return a DIFFERENT (still valid) script that
# breaks the artifact handoff to a downstream step that was already authored
# for the first variant. Persistent on-disk cache, keyed on the deterministic
# hash of (step, plan, binding, controls, transport). Opt-in via cache_dir;
# unset cache_dir → behaviour is exactly the pre-cache flow.
# ---------------------------------------------------------------------------


def _to_jsonable_for_hash(obj: Any) -> Any:
    """Recursively flatten dataclasses / enums / lists / dicts to JSON-safe
    primitives so json.dumps(..., sort_keys=True) gives a stable byte string
    regardless of attribute insertion order. Tightened mirror of
    regen_single_path._to_jsonable; kept here so step3b doesn't depend on
    that script."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if hasattr(obj, "value") and hasattr(obj, "name"):  # Enum
        return obj.value
    if is_dataclass(obj):
        return {k: _to_jsonable_for_hash(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _to_jsonable_for_hash(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable_for_hash(x) for x in obj]
    return repr(obj)  # last-resort: stable string for opaque objects


def _step_cache_key(
    step: AttackStep,
    step_plan: StepPlan | None,
    target_binding: TargetBinding | None,
    assigned_controls: list[ControlRef] | None,
    transport: str | None,
) -> str:
    """Deterministic 16-char sha256 prefix over all inputs that influence
    the LLM prompt for one step. Two distinct (path, scenario) calls that
    produce the same hash are guaranteed to want the same script."""
    payload = {
        "step": _to_jsonable_for_hash(step),
        "plan": _to_jsonable_for_hash(step_plan),
        "binding": _to_jsonable_for_hash(target_binding),
        "controls": [
            _to_jsonable_for_hash(c) for c in (assigned_controls or [])
        ],
        "transport": transport,
    }
    canonical = json.dumps(
        payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _cache_lookup(
    cache_dir: Path | None, key: str
) -> dict[str, Any] | None:
    """Return cached metadata dict (containing 'code' + bookkeeping) or
    None on miss / unreadable file. Never raises."""
    if cache_dir is None:
        return None
    p = cache_dir / f"{key}.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — corrupted cache → treat as miss
        return None


def _cache_store(
    cache_dir: Path | None,
    key: str,
    code: str,
    *,
    scenario_id: str,
    path_id: str,
    step_id: str,
    contract_retry_used: bool,
    contract_violations: list[str],
) -> None:
    """Write code + bookkeeping to <cache_dir>/<key>.json. The path_id is
    recorded as 'first_authored_for' for human auditability — the cached
    file itself is not path-specific."""
    if cache_dir is None:
        return
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        meta = {
            "code": code,
            "scenario_id": scenario_id,
            "first_authored_for_path": path_id,
            "step_id": step_id,
            "stored_utc": datetime.now(timezone.utc).isoformat(),
            "contract_retry_used": contract_retry_used,
            "contract_violations": contract_violations,
        }
        (cache_dir / f"{key}.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    except Exception:  # noqa: BLE001 — cache write is best-effort
        pass


# Generator signature: receives the step plan (carries artifact_inputs/outputs
# declared by Step 2), the step3a target_binding (concrete grounded
# protocol/endpoint/target_ref), and an OPTIONAL feedback string emitted by
# the contract verifier on a retry call. The LLM is constrained to those
# values — every concrete host/port/method/opcode/payload must come from
# the binding or from artifacts. `feedback`, when present, lists the rule
# violations the verifier found in the first attempt.
Generator = Callable[..., str]


# ---------------------------------------------------------------------------
# Import policy
# ---------------------------------------------------------------------------
# Phase A (2026-04): the per-transport import whitelist was removed. The LLM
# may import anything; safety is enforced by the AST blacklist in
# pipeline_v7.safety_validator (forbidden primitives like os.system,
# subprocess(shell=True), eval/exec, /etc /boot /sys /proc /dev writes) and
# by the harness wall-clock timeout. This lets unknown-protocol scenarios
# (SPI, LIN, FlexRay, ...) import protocol-native libraries without being
# forced into stub fallback.


# ---------------------------------------------------------------------------
# Stub: transport-agnostic skeleton.
# ---------------------------------------------------------------------------

_STUB_TEMPLATE = '''\
"""Auto-generated stub script for {scenario_id}/{path_id}/{step_id}.

This is a fallback skeleton. No actual attack is executed.
Returns the minimal v4a runtime contract ({{observations, artifacts,
notes}}); the harness injects step_id/status/error and the compat
shim, and records fallback metadata at the StepScript level.

Assigned controls (from Step 3-1):
{control_comment}
"""

from __future__ import annotations


def run_step(context: dict, artifacts: dict) -> dict:
    return {{
        "observations": [
            {{"name": "stub_fallback", "value": True}}
        ],
        "artifacts": {{}},
        "notes": {fallback_reason!r},
    }}
'''


def _render_nist_statements(assigned: list[ControlRef]) -> str:
    """Fetch the NIST 800-53 control statement for each assigned NIST ID
    and render as a compact block. CC SFRs are skipped."""
    ids = [c.source_id for c in assigned if c.source_type == "nist_sp_800_53"]
    if not ids:
        return "(no NIST controls assigned to this step)"
    return _render_nist(ids)


def stub_generate(
    scenario: NormalizedScenario,
    path: AttackPath,
    step: AttackStep,
    assigned: list[ControlRef],
    transport: str | None,
    reason: str = "stub",
) -> str:
    control_comment = "\n".join(
        f"  - {c.source_type}: {c.source_id}" for c in assigned
    ) or "  (none)"
    return _STUB_TEMPLATE.format(
        scenario_id=scenario.scenario_id,
        path_id=path.path_id,
        step_id=step.step_id,
        control_comment=control_comment,
        fallback_reason=reason,
    )


# ---------------------------------------------------------------------------
# LLM prompting
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a BINDING COMPILER. Step3a has already chosen
WHAT this attack step will hit (protocol, endpoint, target reference) and
frozen that decision into a `target_binding` block in the user payload.
Your only job is to emit Python code that EXECUTES that exact binding
against the operator's lab system. You do NOT choose the target. You do
NOT choose the protocol. You do NOT invent any concrete value that is
not in the binding or in upstream artifacts.

Your output must be VALID Python source code only. No markdown fences,
no prose, no commentary.

==========================================================
ABSOLUTE PROHIBITIONS — any one of these will reject your code
==========================================================
- Do NOT introduce a host, port, socket path, bus name, interface name,
  service name, method name, signal name, message ID, opcode, byte
  sequence, payload literal, hash, key, or any other concrete value that
  is not present in `target_binding` (endpoint / target_ref / protocol)
  or in `artifacts[<input>]` produced by an upstream step.
- Do NOT use ANY default fallback when a value is missing. Missing
  means missing — substituting `127.0.0.1` / `localhost` / a
  well-known port / a remembered opcode / an empty-string credential /
  an abstract-socket path / an in-memory bus constructor / a
  kernel virtual-interface name is all forbidden. If a value you
  need is missing from BOTH `target_binding` AND `artifacts`, then
  either (a) the field name is in `runtime_discovery_fields` —
  discover it per BOUNDED DISCOVERY below — or (b) it is not, in
  which case record an exception observation naming the field and
  skip ONLY the actions that depend on it (do NOT abort the entire
  script, do NOT substitute a fabricated value).
- Do NOT broaden the protocol or the transport. The binding names
  exactly one pair; use that pair verbatim. Do NOT "also try" an
  adjacent transport (a local bus when the binding is a networked
  bus, a kernel-native device when the binding is a relay) or an
  adjacent protocol variant. Stay strictly inside the binding's
  protocol + transport.
- Do NOT add discovery / enumeration / scanning for any field that
  Tier 1 (endpoint) / Tier 2 (target_ref) / Tier 3 (artifacts) already
  supplies (see VALUE PRECEDENCE below). The binding IS the discovery
  output for those fields. Discovery is reserved for fields whose
  Tier 1-3 values are missing AND whose name is in
  `runtime_discovery_fields`.
- Do NOT generalize across binding shapes ("if endpoint has X use X
  else use Y"). The binding either has the field or it doesn't; missing
  → raise, never substitute.
==========================================================
VALUE PRECEDENCE (HARD — pick a value, do not "try them all")
==========================================================
Every concrete value your code needs (an address, a port, a path, a
numeric identifier, a name, a flag, a payload field, ...) has EXACTLY
ONE source. Resolve in strict order and STOP at the first hit. Do NOT
chain ` or ` fallbacks that try multiple sources for the same value.

  Tier 1 — `target_binding.endpoint`.
          If the value your action needs is named by a key in
          `endpoint`, that key's value IS the authoritative answer.
          Use it verbatim, by the key name the binding gives.

  Tier 2 — `target_binding.target_ref`.
          Same rule: if Tier 1 doesn't carry the value but `target_ref`
          does, use it verbatim.

  Tier 3 — `artifacts[<exact_input_name>]` produced by an upstream
          step. Only if Tier 1 + Tier 2 do not carry the value. Read by
          the exact name in `artifact_contract.artifact_inputs`.

  Tier 4 — runtime discovery (see BOUNDED DISCOVERY below). Only if
          Tier 1-3 do not carry the value AND its NAME appears in
          `runtime_discovery_fields`. Discovery is the LAST resort —
          not a parallel branch.

  Tier 5 — UNRESOLVED. If after Tier 1-4 the value is still unknown,
          do NOT fabricate. Do NOT substitute "127.0.0.1", a well-known
          port, an opcode you remember, an empty string, or any other
          "plausible default". Record an exception observation that
          names the missing field and lists the tiers you checked, then
          skip ONLY the actions that depend on that value. A clean
          unresolved is strictly better than a fabricated success.

==========================================================
USE-WHAT-IS-NAMED RULE (protocol-agnostic)
==========================================================
step3a injects raw connection fields into `endpoint` under their
ORIGINAL key names (the names the operator used in their testbed
config). When the value your action needs is named by an
`endpoint` (or `target_ref`) key, that key is the source of truth.

Concretely:
  * If your action needs to send to a specific URL path / service ID
    / object path / interface / method / arbitration ID / entity
    address / etc., and a key in `endpoint` or `target_ref` already
    names it, use that key's value directly. Do not invent a more
    generic alternative.
  * Do NOT probe a list of "candidate" values when one is named
    (no `for path in ["/a","/b",...]` loops to discover what the
    binding already states).
  * Do NOT rename it to your own variable convention (no "the binding
    has `ota_update_endpoint` but I'll call mine `firmware_path`").
  * Do NOT substitute a "cleaner" or "shorter" value you remember
    from training data.

The point is intent-driven: when the action requires a value AND the
binding names it, take the binding's value. Keys present in `endpoint`
or `target_ref` that your action does NOT need are fine to ignore —
this is not "read every key blindly".

Forbidden patterns:
  - `value = target_ref.get("x") or artifacts.get("x") or discover_x()`
    — collapses tiers into one. Pick ONE source per value.
  - "Try every plausible candidate" loops over guessed names/paths.
  - Heuristic keyword matching ("if 'gps' in service_name") to widen
    the search beyond what the binding says.
  - Falling back to a literal default when Tier 5 should fire.

==========================================================
ARTIFACT VALUE FORMAT NORMALIZATION (consumer-side)
==========================================================
An upstream artifact preserves the WIRE / DISCOVERY format of the value
(whatever the producing step found on the wire or in a registry). The
library function you are about to call may expect a DIFFERENT format for
the same logical identifier — a single component, a split tuple, a
decoded integer, separate host + port arguments, etc. The producer does
not know the consumer's library; the consumer must bridge the gap.

Before passing an upstream artifact value to a library argument:

  1. Inspect what the library documents for that argument. If the
     library's signature expects a BARE / DECOMPOSED / TYPED form
     (e.g. a trailing component of a dotted name, the host and port as
     separate args, an int where the artifact carries a hex string),
     and the upstream value is in a COMPOSITE / QUALIFIED / ENCODED
     form, DECOMPOSE the upstream value first and pass the component
     the library wants.
  2. Do NOT pass the composite form verbatim and hope the library
     accepts it. Libraries that validate their argument shape will
     reject it client-side before anything hits the wire, and your
     evidence will be a local exception, not an honest negative
     observation from the target.
  3. Do NOT mutate the upstream artifact in place. Read it, derive the
     library-shaped value in a local variable, and pass that. The
     artifact you write for downstream steps stays in its original
     wire format so the chain remains stable.
  4. If the decomposition is ambiguous (you cannot tell which component
     the library wants from the artifact alone), fall through to
     Tier 5 (UNRESOLVED) per VALUE PRECEDENCE — do NOT guess.

This rule is protocol-agnostic: it applies whenever an upstream value's
format does not line up with a library argument's expected format,
regardless of protocol or library.

==========================================================
BOUNDED DISCOVERY (Tier 4 — fallback only)
==========================================================
- `target_binding.runtime_discovery_fields` is a CLOSED WHITELIST of
  field NAMES that step2 marked as legitimately resolvable at runtime.
  Discovery code is permitted ONLY for these field names — and only
  by invoking whatever enumeration surface the chosen library exposes
  for the binding's protocol. Do not hand-roll an enumeration scheme
  of your own; use the library's documented discovery / introspection
  surface.
- ANY field not in `runtime_discovery_fields` MUST be read directly from
  `target_binding` or `artifacts`. Do NOT discover host/port/protocol
  themselves unless they appear in the whitelist.
- Per VALUE PRECEDENCE above, discovery runs ONLY when Tier 1, Tier 2
  AND Tier 3 do not supply the value. Do NOT discover a field that is
  already present in `endpoint` / `target_ref` / `artifacts`.
- If the whitelist is empty, NO runtime discovery is allowed. Use only
  binding + artifacts; if the value is still missing, fall through to
  Tier 5 (UNRESOLVED).
- Discovered values MUST be written back into `artifacts` under the
  matching output name so downstream steps can consume them via the
  artifact contract — never re-discover what an upstream step already
  produced.

==========================================================
DISCOVERY-FIRST STEPS (no upstream artifacts available)
==========================================================
When `path_context.preceding_steps` is empty (or
`artifact_contract.artifact_inputs` is empty), this step is the ENTRY
of the path. Tier 3 (artifacts) has nothing to offer.

- Do NOT treat "no input" as a precondition failure and abort. The
  step is EXPECTED to start by exercising Tier 4 discovery to populate
  the runtime_discovery_fields, then immediately use those values to
  perform the attack_actions.
- The first action in `attack_actions` is your discovery action; the
  remaining actions consume what discovery produced. Do NOT short-circuit
  the chain with an exception observation just because target_binding
  did not pre-fill every field — that is what runtime_discovery_fields
  is for.
- If discovery itself returns nothing (the protocol responds but no
  candidates), record an exception observation per item that depends
  on discovery and continue with the remaining actions; do NOT abort
  the entire run_step.

==========================================================
DISCOVER-BEFORE-ACT (hard — no guessed concrete identifiers)
==========================================================
Any concrete identifier your action needs (whatever the protocol
calls it — a method, a service, a path, an opcode, a numeric ID, a
parameter name, a data-item selector) is NEVER allowed to come from
your training-data memory. It has exactly two legal sources:

  (S1) named in `target_binding.endpoint` / `target_binding.target_ref`
       under its own key, OR
  (S2) discovered at runtime by whatever enumeration surface the
       chosen library exposes AND then read out of an upstream
       artifact (or `artifacts` written earlier in this same step).

If neither S1 nor S2 supplies the identifier the action needs, you do
NOT pick a "plausible" one — even if the library's docstring shows
that name in an example. Instead, emit an honest observation:

    {"name": "<action>_attempted", "value": True}
    {"name": "<action>_outcome",
     "value": {"result": "no_target_found",
               "missing": ["<field_the_action_needed>"],
               "consulted": ["binding.endpoint", "binding.target_ref",
                             "artifacts.<input_name>"]}}

…then skip ONLY that action and continue with the remaining ones.
A clean `no_target_found` is strictly better than guessing an
identifier and getting a "not found" / "unknown" / negative-response
back from the target.

DISCOVERY MUST BE COMPLETE
--------------------------
Discovery is COMPLETE only when the identifier the next action needs
is actually in hand. If the enumeration surface returns a CONTAINER
(nested children, a range to iterate, a catalogue that references
further catalogues), you MUST keep traversing that container until
you reach the leaves that carry the identifier — stopping at the
first level is a discovery BUG, not an honest empty result.

Concretely:
  * If the first enumeration call returns non-empty container
    elements but you wrote `[]` for the identifier list the
    artifact contract demands, you have NOT finished discovery —
    keep traversing.
  * Listing the NAMES / IDs of top-level entities is necessary but
    not sufficient when the next action needs a sub-identifier
    inside one of those entities. Drill in.
  * If the library gives you a typed view of the container (a proxy
    object, a typed client, an iterator), use it — do not rebuild
    traversal from raw wire-level primitives.

Empty-result honesty still applies AFTER full traversal:
  * If you actually walked all reachable children and the leaves
    carry no identifier of the kind the next action needs, THEN the
    empty artifact is honest. Record the traversal (what you
    walked, what you asked, what came back empty) so the verifier
    can see you did the walk.

EMPTY-UPSTREAM-ARTIFACT HANDLING (downstream actions)
-----------------------------------------------------
When this step CONSUMES an upstream artifact (Tier 3) and that
artifact is PRESENT but structurally EMPTY (a list with length 0,
a dict whose identifier-bearing fields are empty strings, etc.):
  * Treat it as "discovery returned nothing", NOT as "fill in a
    guess". Do NOT substitute a remembered identifier.
  * Either (a) re-run the discovery here if and only if the
    identifier's field name is in `runtime_discovery_fields` for
    THIS step, or (b) emit `no_target_found` per the schema above
    and skip the dependent action.
  * The `produces_for_next` artifact STILL must be written — fill
    it with the same empty container shape that came in, plus the
    classification (`{"result": "no_target_found", ...}`) so
    downstream steps see the chain explicitly.

==========================================================
WHAT YOU MAY DO
==========================================================
- Read every concrete value from `target_binding.endpoint`,
  `target_binding.target_ref`, and `target_binding.protocol`.
- Read upstream values from `artifacts[<exact_input_name>]`.
- Construct frames / messages / requests whose STRUCTURE follows the
  declared protocol naturally, but whose CONCRETE VALUES come from the
  binding or upstream artifacts.
- Import a Python library appropriate to the binding's protocol and
  use its documented API for the exact connection target_binding
  describes. Hand-rolling the protocol over a raw socket + struct.pack
  is reserved for protocols that have NO Python library implementation
  at all — it is never a shortcut around library-API uncertainty.
- Record observations of the response, exceptions, timeouts, etc.

==========================================================
RUN_STEP CONTRACT
==========================================================
You MUST define exactly one top-level function:

    def run_step(context: dict, artifacts: dict) -> dict:
        # 1. perform the attempt described (the actual attack action)
        # 2. capture observations relevant to the assigned controls
        # 3. write required outputs to artifacts dict
        # 4. return the shape below
        ...

The function MUST return a dict of EXACTLY this shape:

    {
      "observations": [
        {"name": "<snake_case_name>", "value": <any JSON-serializable>},
        ...
      ],
      "artifacts": {
        "<exact_output_name_from_contract>": <value>,
        ...
      },
      "notes": "<optional human-readable string or null>"
    }

Do NOT add extra top-level keys. Do NOT include step_id, status, error —
the harness injects those. Do NOT categorize observations (no "kind",
no "type", no "expected_*" fields). If you include any additional
top-level keys, the code will be rejected.

OBSERVATIONS — record RAW evidence only (do NOT interpret):
- Observations exist to capture what HAPPENED on the wire, not what
  the script CONCLUDES. A human reading the evidence will interpret;
  your job is to make sure the raw bytes / timing / exception are
  present with no editorial judgment.
- For every send/recv pair you perform, emit a single observation
  whose value is a dict with EXACTLY these keys (use None / 0 / ""
  / false where a key does not apply):
    - "request_hex":       full bytes you sent, lowercase hex
    - "response_hex":      full bytes you received, lowercase hex
    - "bytes_sent":        int
    - "bytes_received":    int
    - "elapsed_ms":        int (send start → recv end)
    - "response_received": bool (did recv yield >0 bytes in time?)
    - "error_str":         str (exception repr if any, else "")
- Name observations after the ACTION attempted, not its outcome:
  good = "send_security_access_seed_request",
  bad  = "security_access_bypass_succeeded".
- BANNED keys inside any observation value (these are interpretation,
  not evidence): result, accepted, denied, granted, success, failure,
  bypass_succeeded, auth_required, auth_not_enforced,
  routing_activated, access_granted, positive_response,
  boundary_protection_enforced, vulnerability_confirmed.
- BANNED string values inside any observation field: "accepted",
  "denied", "granted", "success", "failure", "bypassed", "vulnerable",
  "secure". Record the wire bytes; the human reads them.
- Connection-level events (tcp connect, library handshake) follow the
  same shape: at minimum {"connected": bool, "elapsed_ms": int,
  "error_str": str}.
- Record exceptions as observations too:
  {"name": "exception", "value": {"type": "ConnectionRefusedError",
                                   "message": str(e),
                                   "request_hex": "<if any>"}}
  — NEVER let run_step raise.

ARTIFACT CONTRACT (strict — this is how steps chain together):
- If the user payload contains `artifact_contract`, treat its
  `artifact_inputs` and `artifact_outputs` as a HARD binding between
  this step and its neighbors in the attack path.
- Read inputs ONLY via `artifacts[<exact_input_name>]` — use the exact
  string from artifact_inputs[*].name. Do NOT invent synonyms
  (e.g. if input is "T1_result", do not read "target_host", "host",
  or "tcp_endpoint" in its place).
- Write outputs ONLY into the returned "artifacts" dict using exact
  names from artifact_outputs[*].name. Do NOT add extra keys. Shape
  each output according to its declared `kind` and `schema_hint`.
- SHAPE DISCIPLINE (these violations will fail the contract verifier
  and poison downstream steps — they apply to EVERY protocol and
  scenario):
  * `kind` is binding. If `kind` is "list", the emitted value MUST be
    a Python list (possibly empty []). If "dict", a dict ({}). If
    "str"/"int"/"bool", a scalar of that exact type. Never substitute
    one kind for another.
  * NEVER join list items into a single delimited string. Bad:
    emitting "a.b.c,d.e.f" for a list[str] field. Good: ["a.b.c",
    "d.e.f"]. If discovery produced zero items, emit [] — do NOT
    emit "" or a placeholder.
  * NEVER add artifact keys that are not in artifact_outputs[*].name.
    If a value is useful but undeclared, record it as an OBSERVATION
    instead. Hallucinated artifact keys are rejected even if their
    content looks reasonable.
  * `schema_hint` describes the shape of EACH ELEMENT of a list (or
    the dict's fields). A hint like {"service_name": "str",
    "object_paths": "list[str]"} means every list item is a dict
    with those fields at those types. Preserve the per-field kinds
    exactly — do not flatten nested lists into strings or promote
    scalars into lists.
  * When the declared kind is "list" and the schema_hint implies a
    dict-per-item, emit [{...}, {...}] — NEVER a single dict with
    comma-joined string fields, and NEVER a list of bare strings.
- If an expected input is missing at runtime, the default behaviour is:
  record `{"name": "exception", "value": "missing_input:<name>"}`,
  emit a minimal best-effort attempt, and move on. Do NOT silently
  fall back to hardcoded defaults.
- This default can be OVERRIDDEN per-step by
  `artifact_contract.on_missing_input` (see ON_MISSING_INPUT POLICY
  below). Read that field FIRST; the rule above applies only when it
  is empty.
- Upstream context (`upstream_outputs_by_step`) shows which prior step
  produces each input. Use it to understand data flow; never bypass
  the contract by re-running an upstream step's work.
- When the user payload also contains `upstream_producer_scripts`,
  treat each entry as the AUTHORITATIVE source of the VALUE FORMAT
  that upstream step emits for its artifacts. Before reading an
  artifact, scan the producer's source to learn whether list items
  are bare tokens vs dotted strings, whether dict values are scalars
  vs nested containers, what exact keys appear, and how the library
  is imported / constructed. Do NOT assume a shape the producer did
  not actually emit. Mirror the producer's library-usage pattern
  (import paths, constructor args) when the same library is needed
  in this step. Do NOT copy the producer's business logic; only its
  artifact value format and its proven library API surface.

ON_MISSING_INPUT POLICY (per-step graceful-degradation contract):
- `artifact_contract.on_missing_input` is a free-form snake_case string
  set by step2 that tells THIS step's code how to behave when ANY
  artifact named in `artifact_inputs` is absent or empty at runtime.
- It is ADVISORY and protocol-agnostic — never branch on protocol or
  scenario name to decide what it means.
- Recognised values and the behaviour they imply:
    "" (empty)            → use the default rule above (record
                            missing_input exception, best-effort
                            attempt, continue).
    "abort"               → record one missing_input exception
                            observation per missing input AND skip
                            every item in `attack_actions` (record an
                            "exception" observation per skipped action
                            naming the action verbatim). Still return
                            the standard run_step shape with the
                            declared `artifact_outputs` keys present
                            (values may be empty/None).
    "proceed_with_empty"  → substitute an empty value of the input's
                            schema-implied shape ([] for list, {} for
                            dict, "" for string, None otherwise) and
                            continue executing attack_actions. Still
                            record one observation per substitution
                            naming the input.
    "rediscover"          → attempt a single bounded local discovery
                            pass to repopulate the missing input from
                            `target_binding` (e.g. re-enumerate from
                            endpoint), then continue. If discovery
                            yields nothing, fall back to "abort".
- Other free-form values: treat as advisory hint and choose the
  closest behaviour above. Never invent network calls or library
  imports beyond what the binding already permits.

ATTACK ACTIONS (every item is a non-skippable obligation):
- `target_binding.attack_actions` is a list of concrete attacker
  behaviors that step2 derived by translating the path's cc_sfr /
  nist_sp_800_53 controls into observable actions. Each item is a
  short imperative sentence naming one observable step the attacker
  takes against the target.
- Your code MUST perform every item in this list, in declared order
  unless an earlier item produced an artifact that gates a later one.
  If an item cannot be performed because a required value is missing
  from binding + artifacts, record an "exception" observation naming
  the action string verbatim and continue to the next.
- Do NOT silently skip an action. Do NOT replace an action with a
  related-but-easier one. Do NOT add actions outside this list.
- If the list is empty, fall back to the minimal interaction implied
  by `target_binding.target_ref` + `assigned_controls`.

ACTION → OBSERVATION PAIRING (mandatory — every action must leave
raw evidence on file):
- For each item in `attack_actions`, you MUST emit AT LEAST ONE
  observation whose value is the raw-evidence dict defined in the
  OBSERVATIONS section above (request_hex / response_hex /
  bytes_sent / bytes_received / elapsed_ms / response_received /
  error_str). The observation NAMES the action; its value CARRIES
  the wire bytes; it does NOT classify the outcome.
- Example for an unauthenticated method invocation:
      {"name": "send_gps_get_location_request",
       "value": {"request_hex":  "6c0101...",
                 "response_hex": "6c0201...",
                 "bytes_sent":   128,
                 "bytes_received": 256,
                 "elapsed_ms":   42,
                 "response_received": True,
                 "error_str":    ""}}
- A bare `{"name": "<action>_attempted", "value": True}` observation
  with no raw-evidence dict alongside it is treated by the verifier
  as unimplemented — the attempt happened but no wire evidence is
  on file.
- Do NOT emit a paired `_outcome` observation that classifies the
  reply. The reply bytes are already in `response_hex`; classification
  is the human's job.

PRODUCES_FOR_NEXT (downstream chaining commitment):
- `target_binding.produces_for_next` is a sub-list of
  `artifact_contract.artifact_outputs` that step2 committed this step
  to ACTUALLY produce (not merely declare). Every name in this list
  MUST appear as a key in the returned `artifacts` dict with a
  non-None value, even if the value is a partial / failure record.
- A name in produces_for_next that ends up missing or null is treated
  by the verifier as broken chaining — downstream steps will block.

HONESTY OBLIGATIONS (do not fabricate continuations):
- Runtime discovery results: if a discovery / enumeration / probe step
  returns an empty set (no services, no methods, no responses), emit
  that empty result as an honest observation. Do NOT relabel emptiness
  as success and do NOT fill the artifact with placeholder / synthetic
  values to keep downstream steps "happy". The empty result is itself
  evidence.
- Missing upstream artifact: if a required upstream artifact is absent
  at runtime, do NOT fabricate a substitute from offline context (CVE
  text, remembered exploit patterns, library defaults). Record the
  missing dependency as an observation, then either continue ONLY in
  a contract-permitted degraded mode (one that the artifact_contract
  + attack_actions still allow without that input) or return an
  unresolved result. Never invent the missing value.
- Response recording (raw-only): when the target replies, dump the
  full reply bytes into the observation's `response_hex` field
  verbatim. Do NOT decide "this means success" / "this means denied"
  / "this is a positive response" inside the script. Wire-level
  interpretation is the human's job; the script's only job is to
  ensure the evidence is captured intact and is reproducible.

CONTROL ALIGNMENT (strict — scope comes from control text, not memory):
- The user payload includes `control_statements`: the actual statements
  for controls assigned to THIS step. Base every observation you record
  on what those statements say is observable at runtime (permit/deny
  decisions, handshake outcomes, session state, audit records,
  lockouts).
- Do NOT record observations motivated by controls NOT in
  `assigned_controls`. Neighboring steps in the path will cover their
  own controls.
- Do NOT invent requirements that are in the control's Discussion /
  guidance but not in its normative statement. The statement in
  `control_statements` is the source of truth.
- If a clause is about organizational process (approval workflows,
  documented policy, role assignment, periodic review), it is NOT
  testable in this script — skip it.

==========================================================
I/O TIMING (mandatory recv pattern)
==========================================================
- Set an explicit `sock.settimeout(N)` (N >= 1.0 second) BEFORE the
  first recv. A server may take tens to hundreds of milliseconds
  before its first byte; calling `recv()` immediately after `sendall`
  with no timeout / no loop will return 0 bytes and produce empty
  evidence even when the server replied correctly.
- Read the protocol header in a `while len(buf) < HEADER_LEN: buf +=
  sock.recv(HEADER_LEN - len(buf))` loop, then read the payload in
  the same style sized by the header's declared payload-length field.
  Bare single-call `sock.recv(1024)` is FORBIDDEN — partial reads
  produce truncated evidence and silent zero-byte returns.
- For library-based clients, prefer the library's own
  recv / await / iterate API; do not bypass it with raw socket code
  inside the same step.

==========================================================
UPSTREAM-DISCOVERED VALUES (no fabrication)
==========================================================
- If a previous step's artifact contains a value you need (logical
  address, source address, session id, token, endpoint, vin), you
  MUST consume it from `artifacts[<exact_input_name>]` and use it
  verbatim. Do NOT substitute 0, 0x0000, "", "127.0.0.1",
  "default", or any other placeholder.
- If the value is required to construct your request and it is NOT
  present in artifacts (and `on_missing_input` does not direct you
  otherwise), record an `exception` observation naming the missing
  field and skip that action — do NOT invent a value.

MINIMALISM:
- Prefer the SIMPLEST executable interaction that exercises the assigned
  controls. Minimal attempt + minimal observation.
- If `target_binding.library_candidates` is non-empty, that list is
  AUTHORITATIVE. Import the protocol-bearing client from one of the
  listed `import_module` names — first entry preferred. Each candidate
  was researched against documentation for THIS binding's protocol +
  transport pair, so the question "does this library support that
  transport" is already answered. Do NOT substitute another library
  for the protocol-bearing client.
- Each candidate also carries an `import_examples` list — the EXACT
  `from ... import ...` lines drawn from the library's official docs.
  Use these import lines verbatim. Do NOT shorten them, do NOT guess
  alternative submodule paths, and do NOT collapse them into a
  top-level `from <pkg> import <Class>` form unless that exact form
  appears in `import_examples`. Many libraries place the bus/client
  class in an `aio` / `client` / `core` submodule, NOT at the top
  level; assuming the top-level path causes ImportError at runtime.
- Do NOT wrap library imports in `try: ... except ImportError: from
  <other_lib> import <Same>` fallbacks. The `library_candidates` list
  is already an ordered fallback chain — pick ONE and use its
  `import_examples` directly. Fallback `import` blocks hide
  hallucinated paths from human review and from the static verifier
  feedback loop.
- If `target_binding.library_candidates` is EMPTY, fall back to the
  next bullet: prefer a Python library that natively implements BOTH
  the binding's protocol AND the binding's transport. A library handles
  wire format, alignment, framing, authentication state machines,
  retry, and endianness — all hard to get right in hand-rolled code
  and NOT checked by the static verifier.
- A library that handles the protocol over a DIFFERENT transport than
  the binding requires does NOT qualify. Confirm transport coverage
  from the library's public API or documentation before committing
  to it.
- Only fall back to the raw transport primitive (`socket` /
  `struct.pack`, serial, ioctl, etc.) when no library covers BOTH
  protocol and transport. Record the fallback as an observation
  (e.g. {"name": "fallback_to_raw_transport", "value":
  {"reason": "no library supports <protocol> over <transport>"}}).
- Do NOT introduce a dependency whose availability cannot be
  reasonably assumed from the execution environment.
- Do NOT implement custom protocol parsers, wire-format builders, or
  authentication state machines when a library already does it.
- Do NOT perform heuristic inference beyond what the assigned controls
  require (no regex fishing, no scoring, no scanning unrelated ports).
- If a prior step already established state (auth session, discovered
  endpoint), CONSUME it from `artifacts` instead of redoing it.
- Target length: under ~120 lines. If you feel tempted to exceed that,
  you are over-engineering.

==========================================================
SINGLE-ATTEMPT CODE (no scratch-paper rewrites)
==========================================================
- If you write a computation, decide it is wrong, and want to redo it
  — DELETE the first version before writing the second. Never leave
  both attempts in the output with a "now do it properly" / "build it
  correctly" comment between them.
- Python executes the FIRST assignment first; if it raises, the second
  never runs. The reader (and the runtime) sees the first version,
  not your intent. So a half-broken first attempt followed by a
  correct second attempt is worse than just the correct version
  alone — it crashes at the first attempt, and the corrected code
  is dead.
- Each variable / artifact must be assigned exactly once, in the
  version you stand behind. If you spot a problem mid-write, scroll
  back, edit, and continue — do not append a "redo" block.

==========================================================
USE THE LIBRARY'S HIGHEST-LEVEL SURFACE (hard)
==========================================================
When the imported library exposes BOTH a high-level client surface
(typed proxies, typed client classes, typed iterators, typed
interface objects whose methods mirror the operation you want) AND
low-level primitives (generic "construct a message object and hand
it to a send/call function"), the high-level surface is REQUIRED.
Low-level primitives are reserved for the rare operation the high-
level surface genuinely cannot express.

Why: low-level primitives push framing, default flags, serial
assignment, reply correlation, and return-value contracts onto your
code. Subtle library version / fork differences (a generic call
sometimes returning an awaitable, sometimes returning a Future,
sometimes returning `None` for fire-and-forget) silently break
`await` / `asyncio.wait_for(...)` wrappers — and the static verifier
cannot tell the difference. The high-level surface encapsulates those
invariants.

How to pick the surface without knowing the library in advance:
  1. Read the library's public module docstring / top-level
     `__all__` / the verifier's real-signature feedback. If there is
     a class named for the PROTOCOL'S CLIENT ROLE (proxy, client,
     application, peer, session) with methods named for the
     OPERATIONS you need, that is the high-level surface. Use it.
  2. A generic "build an arbitrary message and send it" function
     (whatever the library calls it) is the low-level surface. It
     accepts raw identifier strings / opcodes as caller-supplied
     values. Using this is a red flag unless step (1) returned
     nothing.
  3. If the high-level surface requires a discovery call first
     (e.g. some libraries fetch the target's advertised operation
     set and hand you a typed client), do that discovery — it is
     part of the high-level pattern, not an optional nicety.

If the library genuinely has NO high-level helper for the operation
you need, the low-level primitive is permitted ONLY for that specific
operation, and you MUST record an observation explaining the gap:

    {"name": "low_level_primitive_used",
     "value": {"reason": "<library> exposes no typed helper for
                         <operation>; falling back to <primitive>"}}

If you DO use a low-level primitive, you MUST verify the call's
return-value contract from the library's docstring / real-signature
feedback — do NOT assume `await` or `asyncio.wait_for` will work on
whatever it returns. A function that sometimes returns `None` (for a
no-reply path, or for an invalid input shape) cannot be wrapped in
`asyncio.wait_for` without a `None` check first.

==========================================================
LIBRARY-STAY ON API ERROR RECOVERY (hard — applies to retry feedback)
==========================================================
When the verifier (or a previous attempt's traceback) tells you that a
library function rejected a keyword argument, an attribute does not
exist, or a method signature is different from what you assumed —

  STAY INSIDE THE SAME LIBRARY. Fix the call.

You MUST NOT respond to an API error by:
- Removing the library import and rebuilding the same protocol on top
  of `socket`, `struct.pack`, and hand-coded headers.
- Switching to a lower-level library or to raw transport primitives
  just because the high-level call signature surprised you.
- Re-implementing authentication / framing / alignment yourself
  because "the library is too complicated".

The correct response to a signature mismatch is:
  1. Read the real signature shown in the verifier feedback
     (`Real signature: ...`) and the docstring (`Docstring: ...`).
  2. Pick the right kwarg from the listed valid parameters, or call
     a different method on the same library object that does what
     you intended. A signature mismatch means you guessed the kwarg
     shape wrong — fix the call, don't replace the library.
  3. If the library genuinely cannot do what the binding requires,
     record an exception observation naming the limitation — do NOT
     silently substitute hand-rolled wire code.

Why this rule is hard: hand-rolled protocol code (raw sockets +
byte-packing + hand-coded headers) routinely gets alignment, framing,
authentication retry, and endian conversion wrong in ways the static
verifier CANNOT detect. A wrong-but-syntactic hand-roll passes
verification and silently produces useless evidence. Staying inside a
library that ALREADY handles those details is the only reliable
defense.

IMPORTS:
- You may import any Python library you need for the task. There is no
  whitelist. The pipeline's safety validator enforces the SAFETY rules
  below (AST-level), and the harness enforces a wall-clock timeout.
- Do NOT import in order to bypass a safety rule.

SAFETY — forbidden primitives (hard — code will be rejected):
- os.system(...)
- subprocess.* with shell=True, or subprocess.Popen of a shell
- eval(...), exec(...) on untrusted strings
- __import__(...) called dynamically at runtime
- Writing to /etc, /boot, /sys, /proc, or arbitrary /dev paths. If
  the binding names a /dev-path endpoint explicitly, that path is
  permitted — otherwise /dev writes are forbidden.
- Spawning long-running processes or detached daemons

NETWORK POLICY (hard — respect even though enforcement is partly
prompt-level):
- Only connect to hosts in `context` / `artifacts` (operator-provided
  endpoints). If a test requires an external address, it MUST be
  RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback, or
  link-local — never the public internet.
- EVERY socket/HTTP operation MUST have an explicit timeout parameter.
  `sock.settimeout(...)` or `requests.get(..., timeout=...)` is
  mandatory before any I/O.
- Do NOT use `while True:` without a break condition bound by elapsed
  wall-clock time. The harness kills you at 15 seconds; your loops
  MUST terminate before that on their own when the attack is done.

The harness wraps your return value and adds step_id/status/error plus
compatibility fields (assertion_results: [], evidence: [],
_script_contract: "v4a"). You do not emit those.
"""


def _artifact_ref_to_dict(a: ArtifactRef) -> dict[str, Any]:
    d: dict[str, Any] = {"name": a.name, "kind": a.kind}
    if a.schema_hint:
        d["schema_hint"] = a.schema_hint
    return d


def _collect_path_artifact_schema(
    path_plan_steps: list[StepPlan] | None,
) -> dict[str, list[dict[str, Any]]]:
    """Flatten every step's artifact outputs across the path so the LLM sees
    the FULL data-flow graph of the attack path. Returns dict keyed by
    step_id for preceding/following reference."""
    if not path_plan_steps:
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    for sp in path_plan_steps:
        outs = sp.artifacts.get("outputs", []) if sp.artifacts else []
        out[sp.step_id] = [_artifact_ref_to_dict(a) for a in outs]
    return out


def _build_user_prompt(
    scenario: NormalizedScenario,
    path: AttackPath,
    step: AttackStep,
    assigned: list[ControlRef],
    transport: str | None,
    step_plan: StepPlan | None = None,
    path_plan_steps: list[StepPlan] | None = None,
    target_binding: TargetBinding | None = None,
    contract_feedback: str | None = None,
    path_locked_imports: list[str] | None = None,
    prior_step_codes: dict[str, str] | None = None,
) -> str:
    conn_dict: dict[str, Any] = {}
    if step.connection is not None:
        conn_dict = {
            "connection_id": step.connection.connection_id,
            "protocol": step.connection.protocol,
            "interface": step.connection.interface,
            "from_component": step.connection.from_component,
            "to_component": step.connection.to_component,
        }

    # Path-level context: let the LLM see what prior steps already did and
    # what later steps will do, so it does not re-implement auth/session
    # setup that an earlier step has already established.
    preceding: list[dict[str, str]] = []
    following: list[dict[str, str]] = []
    seen_self = False
    for s in path.steps:
        entry = {"step_id": s.step_id, "description": s.description}
        if s.step_id == step.step_id:
            seen_self = True
            continue
        (following if seen_self else preceding).append(entry)

    # Open semantic intent (P4): advisory free-form fields produced by step2.
    # These help the binding compiler choose WHICH observations to record,
    # but they do NOT supply concrete values (host/port/method/etc.) — those
    # MUST come from target_binding only. Empty values mean "no advisory hint";
    # the compiler must still ground every concrete choice from the binding.
    semantic_intent: dict[str, Any] = {}
    if step_plan is not None:
        if step_plan.intent_label:
            semantic_intent["intent_label"] = step_plan.intent_label
        if step_plan.attacker_goal:
            semantic_intent["attacker_goal"] = step_plan.attacker_goal
        if step_plan.target_role:
            semantic_intent["target_role"] = step_plan.target_role
        if step_plan.success_signals:
            semantic_intent["success_signals"] = list(step_plan.success_signals)
        if step_plan.failure_signals:
            semantic_intent["failure_signals"] = list(step_plan.failure_signals)
        if step_plan.library_hint:
            semantic_intent["role_signals"] = step_plan.library_hint

    step_block: dict[str, Any] = {
        "step_id": step.step_id,
        "description": step.description,
        "connection": conn_dict or None,
    }
    if semantic_intent:
        step_block["semantic_intent"] = semantic_intent
        step_block["semantic_intent_note"] = (
            "Advisory only. Use these fields to choose observation NAMES "
            "(success_signals / failure_signals are observable names, not "
            "values) and to understand the step's purpose. Do NOT derive "
            "any concrete protocol value (host, port, method, opcode, "
            "payload) from these — those come from target_binding only."
        )

    payload = {
        "scenario_id": scenario.scenario_id,
        "scenario_title": scenario.title,
        "cybersecurity_goal": scenario.cybersecurity_goal,
        "path_id": path.path_id,
        "path_description": path.label,
        "path_context": {
            "preceding_steps": preceding,   # already executed before this step
            "following_steps": following,   # will run after this step
            "note": (
                "Assume preceding_steps have ALREADY executed successfully "
                "and any state they established (open connection, "
                "authenticated session, discovered endpoints) is available "
                "via `artifacts`. Do NOT redo their work. Do NOT pre-empt "
                "the work of following_steps."
            ),
        },
        "step": step_block,
        "transport_name": transport,
        # Only NIST SP 800-53 IDs are surfaced to the LLM. CC SFRs are kept
        # in the data model for traceability but omitted from prompts — they
        # tend to nudge the LLM into scope creep across adjacent control
        # families without adding testable semantics beyond NIST.
        "assigned_controls": [
            c.as_dict() for c in assigned if c.source_type == "nist_sp_800_53"
        ],
        "control_statements": _render_nist_statements(assigned),
    }

    # ------------------------------------------------------------------
    # TARGET BINDING (frozen by step3a) — the codegen contract.
    #
    # Every concrete value the LLM may use for protocol / endpoint /
    # target reference comes from here. The binding compiler prompt
    # forbids substituting any value not in this block (or in upstream
    # artifacts). When this field is None, the unresolved-gate should
    # have already replaced the entire script with a BLOCKED placeholder
    # — we still surface a marker so the LLM cannot silently proceed.
    # ------------------------------------------------------------------
    if target_binding is None:
        payload["target_binding"] = {
            "binding_status": "missing_or_unresolved",
            "note": (
                "ERROR — codegen reached without a grounded target_binding. "
                "This SHOULD have been intercepted by the unresolved-gate. "
                "Emit a script that records an exception observation and "
                "returns the standard run_step shape; do not attempt the "
                "attack with fabricated values."
            ),
        }
    else:
        # B8-a: pass the FULL execution spec for both `bound` and
        # `resolution_failed`. The hard-block gate (_is_step_blocked) has
        # already filtered out cases with no protocol AND no discovery
        # whitelist; anything reaching here is at least partially groundable.
        # For partial bindings, step3a has populated runtime_discovery_fields
        # to cover the gaps in `unresolved_fields`, so the LLM can discover
        # at runtime and proceed instead of aborting.
        is_partial = target_binding.binding_status != "bound"
        payload["target_binding"] = {
            "binding_status": "partial" if is_partial else target_binding.binding_status,
            "protocol": target_binding.protocol,
            "endpoint": dict(target_binding.endpoint),
            "target_ref": dict(target_binding.target_ref),
            "evidence_basis": list(target_binding.evidence_basis),
            # P6 Phase B execution spec — propagated deterministically from
            # step2 by step3a; the LLM treats these as binding obligations,
            # not suggestions. See VALUE PRECEDENCE / BOUNDED DISCOVERY /
            # ATTACK ACTIONS / PRODUCES_FOR_NEXT in the system prompt.
            "runtime_discovery_fields": list(target_binding.runtime_discovery_fields),
            "attack_actions": list(target_binding.attack_actions),
            "produces_for_next": list(target_binding.produces_for_next),
            "library_candidates": list(target_binding.library_candidates),
        }
        if target_binding.library_candidates:
            payload["target_binding"]["library_lock_note"] = (
                "LIBRARY LOCK — the modules listed in `library_candidates` "
                "were researched (with documentation citations) for THIS "
                "binding's protocol+transport pair. You MUST import only "
                "from these `import_module` names for the protocol-bearing "
                "client. The first candidate is the recommended choice; "
                "later candidates are acceptable fallbacks. Importing any "
                "other third-party library for the protocol-bearing client "
                "(a name that does not appear in `library_candidates`) will "
                "be rejected by the verifier. Auxiliary stdlib modules "
                "(asyncio, json, "
                "socket, struct, time, xml.etree, hashlib, ...) are always "
                "permitted alongside."
            )
        else:
            payload["target_binding"]["library_lock_note"] = (
                "LIBRARY RESEARCH UNAVAILABLE — no candidate list was "
                "produced (network/API failure or no library documentably "
                "supports this protocol+transport). Fall back to the soft "
                "preference rules in WHAT YOU MAY DO."
            )
        if is_partial:
            payload["target_binding"]["unresolved_fields"] = list(
                target_binding.unresolved_fields or []
            )
            payload["target_binding"]["partial_binding_reason"] = (
                target_binding.reason or ""
            )
            payload["target_binding"]["note"] = (
                "PARTIAL BINDING — step3a grounded protocol/endpoint/target_ref "
                "as far as it could but left some fields unresolved. The names "
                "in `unresolved_fields` are exactly the ones step2 expected "
                "this step to discover at runtime via "
                "`runtime_discovery_fields`. Per VALUE PRECEDENCE Tier 4, "
                "discover those values from the live target (Tier 1-3 do not "
                "carry them). Do NOT abort. Do "
                "NOT substitute defaults. Execute the attack_actions using "
                "the discovered values. If discovery itself returns nothing, "
                "record an exception observation per affected action and "
                "continue."
            )
        else:
            payload["target_binding"]["note"] = (
                "Use ONLY the values in protocol/endpoint/target_ref above. "
                "Do not invent any concrete value not present here or in "
                "artifacts[<input_name>]. Runtime discovery is allowed ONLY "
                "for field names listed in runtime_discovery_fields. Every "
                "item in attack_actions MUST map to observable code; every "
                "name in produces_for_next MUST appear in the returned "
                "artifacts dict. The unresolved-gate has already verified "
                "every required grounded field; if you find yourself wanting "
                "a value that is not in the binding and not in "
                "runtime_discovery_fields, record an exception observation "
                "instead of substituting a default."
            )

    # ------------------------------------------------------------------
    # Artifact CONTRACT (Plan A): Step 2 already produced per-step
    # artifact_inputs / artifact_outputs. We hand them to the LLM as a
    # binding contract — the generated code MUST only read declared
    # inputs and write declared outputs. This is what makes step-to-step
    # chaining stable (fixes the T1/T2/T3/T4 name-mismatch problem).
    # ------------------------------------------------------------------
    if step_plan is not None and step_plan.artifacts:
        artifact_inputs = [
            _artifact_ref_to_dict(a)
            for a in step_plan.artifacts.get("inputs", [])
        ]
        artifact_outputs = [
            _artifact_ref_to_dict(a)
            for a in step_plan.artifacts.get("outputs", [])
        ]
        payload["artifact_contract"] = {
            "artifact_inputs": artifact_inputs,
            "artifact_outputs": artifact_outputs,
            # Per-step graceful-degradation policy (step2-authored). Free-form
            # snake_case advisory string; see ON_MISSING_INPUT POLICY in the
            # system prompt. Empty string means "use default rule".
            "on_missing_input": getattr(step_plan, "on_missing_input", "") or "",
            "note": (
                "These names are the BINDING CONTRACT between steps in this "
                "attack path. Read inputs ONLY via artifacts[<exact_input_name>]. "
                "Write outputs ONLY via the returned dict's 'artifacts' field "
                "using these EXACT output names. Do NOT invent new names, do "
                "NOT rename them, do NOT add extra keys outside this contract. "
                "When an input is missing at runtime, follow the policy in "
                "`on_missing_input` (see ON_MISSING_INPUT POLICY)."
            ),
        }
        # Upstream artifact graph so the LLM can see where its inputs come from.
        if path_plan_steps:
            payload["artifact_contract"]["upstream_outputs_by_step"] = (
                _collect_path_artifact_schema(path_plan_steps)
            )

    # Retry feedback (P5): when the contract_verifier rejected the previous
    # attempt, attach its rule violations so the model can correct itself.
    # Surfaced as a top-level payload field rather than mixed into the
    # system prompt — keeps the system prompt cacheable across retries.
    # We wrap the raw violation text with a short library-stay reminder so
    # the model is explicitly steered AGAINST the observed escape pattern
    # of "API rejected my kwarg → abandon library → hand-roll the protocol
    # on raw sockets". See the LIBRARY-STAY section in the system prompt.
    # PATH-LEVEL IMPORT LOCK (A): if an earlier step in this same path already
    # produced a working script, lock the later steps to its exact import lines.
    # This kills the per-step "spelling correction" failure mode where the LLM
    # rewrites a real-but-unusual library symbol (e.g. dbus_next.auth.AuthAnnonymous,
    # double-n) to a guess (AuthAnonymous, single-n) that doesn't exist.
    if path_locked_imports:
        payload["path_imports"] = {
            "import_lines": list(path_locked_imports),
            "rule": (
                "PATH IMPORT LOCK — these EXACT import lines were used by an "
                "earlier step in this same attack path that the verifier "
                "already accepted. Use these same import statements verbatim. "
                "Do NOT change the spelling. Do NOT switch to alternative "
                "submodule paths. Do NOT 'correct' any unusual spelling — "
                "if a name looks like a typo it is NOT a typo, it is the "
                "real library symbol and the path's earlier step proved it "
                "imports cleanly. Only add NEW imports if you genuinely need "
                "additional modules; never replace or rename a locked line."
            ),
        }

    if contract_feedback:
        payload["previous_attempt_violations"] = {
            "violations": contract_feedback,
            "recovery_directive": (
                "Fix every violation IN PLACE within the same imports and "
                "the same library you used. If a kwarg was rejected, read "
                "the 'Real signature:' line in the violation and pick a "
                "valid kwarg or call a different method on the same "
                "library object. Do NOT remove a library import to "
                "rebuild the protocol on raw socket / struct.pack — that "
                "is the documented escape pattern and it is forbidden."
            ),
        }

    # UPSTREAM PRODUCER SCRIPTS — verbatim source of any prior step in the
    # same path that has already been generated. This lets the consumer LLM
    # see exactly how upstream artifacts are constructed (key names, element
    # formats, nesting, library-API usage that actually worked) instead of
    # guessing from the abstract artifact_contract alone. Empty dict / None
    # means "this is the first step" or "no prior code available". The
    # contract between producer and consumer (names, shape) is still
    # authoritative in `artifact_contract`; the code is a reference exemplar
    # for VALUE FORMAT and LIBRARY API that the contract cannot pin.
    if prior_step_codes:
        payload["upstream_producer_scripts"] = {
            "scripts": dict(prior_step_codes),
            "rule": (
                "UPSTREAM PRODUCER CODE — each entry is the full generated "
                "Python source of an earlier step in this same attack path. "
                "When consuming an artifact, trace its construction in the "
                "producer's code to learn the exact VALUE FORMAT (e.g. "
                "whether list items are bare identifiers or dotted strings, "
                "whether dict values are scalars or nested containers). Do "
                "NOT assume a format the producer did not actually emit. "
                "When calling a library, prefer the same import paths / "
                "constructor patterns the producer used successfully; those "
                "are already proven against the runtime. Do NOT copy the "
                "producer's business logic — only mirror its library usage "
                "and its artifact value format."
            ),
        }

    return json.dumps(payload, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Validation of generated code
# ---------------------------------------------------------------------------

class ScriptValidationError(Exception):
    pass


class SafetyValidationError(ScriptValidationError):
    """Raised when LLM-generated code contains forbidden primitives per
    pipeline_v7.safety_validator (Phase A4/A5).

    Subclasses ScriptValidationError so the existing fallback path in
    generate_script_for_step catches it uniformly, but classify_fallback
    distinguishes it by type name so _summary.json records WHICH rule
    was violated (not just the category). The original violation strings
    are preserved in the exception message and on .violations.
    """

    def __init__(self, violations: list[str]) -> None:
        super().__init__("safety violations: " + "; ".join(violations))
        self.violations = list(violations)


def validate_code(code: str, step_id: str) -> None:
    """Raise ScriptValidationError if the code violates any invariant.

    Scope: structural/syntactic checks only (syntax, run_step signature).
    Safety-policy checks (forbidden primitives, dangerous calls) live in
    pipeline_v7.safety_validator (Phase A4).
    """
    try:
        tree = ast.parse(code)
        # compile() catches a few semantic errors that ast.parse accepts:
        # duplicate argument names, top-level return, break/continue outside
        # loop, nonlocal without enclosing scope, etc. Cheap, no side effects.
        compile(code, f"<step:{step_id}>", "exec")
    except SyntaxError as e:
        raise ScriptValidationError(f"syntax error: {e}") from e

    # must define run_step(context, artifacts)
    run_step_fn = None
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "run_step":
            run_step_fn = node
            break
    if run_step_fn is None:
        raise ScriptValidationError("run_step() not defined at module top level")
    arg_names = [a.arg for a in run_step_fn.args.args]
    if arg_names[:2] != ["context", "artifacts"]:
        raise ScriptValidationError(
            f"run_step must take (context, artifacts); got {arg_names!r}"
        )


# ---------------------------------------------------------------------------
# LLM generator factory
# ---------------------------------------------------------------------------

def create_llm_generator(
    provider: str = "anthropic",
    api_key: str | None = None,
    model: str = "claude-opus-4-6",
) -> Generator:
    if provider != "anthropic":
        raise ValueError(f"Unsupported LLM provider: {provider}")

    def _gen(scenario, path, step, assigned, transport, step_plan=None,
             path_plan_steps=None, target_binding=None,
             contract_feedback=None, path_locked_imports=None,
             prior_step_codes=None) -> str:
        user = _build_user_prompt(
            scenario, path, step, assigned, transport,
            step_plan=step_plan, path_plan_steps=path_plan_steps,
            target_binding=target_binding,
            contract_feedback=contract_feedback,
            path_locked_imports=path_locked_imports,
            prior_step_codes=prior_step_codes,
        )
        # First attempt at default budget.
        text, stop = _call_anthropic(
            _SYSTEM_PROMPT, user, api_key=api_key, model=model, max_tokens=4096,
        )
        # Retry once at 8192 if the model got truncated or produced code that
        # would fail _looks_truncated. This is the single most common failure
        # mode (long scripts exceeding 4k tokens).
        if stop == "max_tokens" or _looks_truncated(text):
            text, _ = _call_anthropic(
                _SYSTEM_PROMPT, user, api_key=api_key, model=model, max_tokens=8192,
            )
        return text

    return _gen


def _looks_truncated(text: str) -> bool:
    """Cheap heuristic: code that does not end on a plausible Python boundary."""
    t = _strip_fences(text).rstrip()
    if not t:
        return True
    # Final char should be a closing brace/bracket/paren or end a statement.
    return t[-1] not in ")]}\"'0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


# Fallback-reason categorization so _summary.json can surface WHY LLM output
# was rejected, not just that it was. Buckets:
#   syntax_error        — ast.parse failed (often truncation)
#   missing_run_step    — function not defined
#   wrong_signature     — signature does not start with (context, artifacts)
#   safety_blacklist    — safety_validator rejected a forbidden primitive
#                         (os.system, subprocess shell=True, eval, fs writes,
#                          etc.). The full violation string is preserved
#                          downstream in fallback_reason.
#   api_error           — Anthropic client/transport raised
#   unknown             — anything else
# Note: import_violation was removed in Phase A2 (no import whitelist).
def classify_fallback(exc: BaseException) -> str:
    name = type(exc).__name__
    # SafetyValidationError subclasses ScriptValidationError, so the
    # subclass check MUST come first — otherwise the parent-name branch
    # below would swallow it (subclass-hiding).
    if name == "SafetyValidationError":
        return "safety_blacklist"
    msg = str(exc)
    if name == "ScriptValidationError":
        if "syntax error" in msg:
            return "syntax_error"
        if "run_step() not defined" in msg:
            return "missing_run_step"
        if "context, artifacts" in msg:
            return "wrong_signature"
        return "validation_other"
    if name in {"APIError", "APIConnectionError", "APITimeoutError",
                "RateLimitError", "AuthenticationError"}:
        return "api_error"
    return "unknown"


def _call_anthropic(
    system: str,
    user: str,
    api_key: str | None,
    model: str,
    max_tokens: int = 4096,
) -> tuple[str, str]:
    """Return (text, stop_reason). stop_reason=='max_tokens' means truncation."""
    import anthropic

    client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
    resp = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    text = "".join(
        block.text for block in resp.content if getattr(block, "type", "") == "text"
    )
    stop = getattr(resp, "stop_reason", "") or ""
    return text, stop


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _strip_fences(s: str) -> str:
    """Strip ```python ... ``` fences if the model emitted them despite the prompt."""
    s = s.strip()
    if s.startswith("```"):
        # remove opening fence line
        first_nl = s.find("\n")
        if first_nl != -1:
            s = s[first_nl + 1 :]
        if s.endswith("```"):
            s = s[:-3]
    return s.strip()


def _extract_top_imports(code: str) -> list[str]:
    """Return the verbatim source lines of every top-level Import / ImportFrom
    statement in `code`. Used by `generate_scripts_for_path` to lock the
    imports of later steps in the same path to whatever an earlier successful
    step actually used — preventing per-step LLM "spelling correction" of
    library symbols that the path's first step has already proven correct.

    Returns an empty list if the code fails to parse.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    src_lines = code.splitlines()
    out: list[str] = []
    seen: set[str] = set()
    for node in tree.body:
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        try:
            text = ast.get_source_segment(code, node) or ""
        except Exception:  # noqa: BLE001 — fall back to manual slice
            text = ""
        if not text:
            lineno = getattr(node, "lineno", 0)
            end = getattr(node, "end_lineno", lineno)
            if not lineno:
                continue
            text = "\n".join(src_lines[lineno - 1 : end]).strip()
        text = text.strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


# R10 rules whose violations indicate the generated code WILL crash at import
# time. If any of these survive both the first attempt AND the retry, the
# script must NOT be accepted — keeping it would propagate a guaranteed-fail
# import (e.g. `from dbus_next.auth import AuthAnonymous` when the real symbol
# is `AuthAnnonymous`) into testbed evidence.
_HARD_IMPORT_RULES = frozenset({
    "R10_import_name_missing",
    "R10_module_not_found",
})


def generate_script_for_step(
    scenario: NormalizedScenario,
    path: AttackPath,
    step: AttackStep,
    assigned_controls: list[ControlRef],
    generator: Generator | None = None,
    step_plan: StepPlan | None = None,
    path_plan_steps: list[StepPlan] | None = None,
    target_binding: TargetBinding | None = None,
    cache_dir: Path | None = None,
    path_locked_imports: list[str] | None = None,
    prior_step_codes: dict[str, str] | None = None,
) -> StepScript:
    # transport_name is informational only (RAG cue, prompt context). The
    # authoritative protocol identity lives on target_binding.protocol now.
    # We deliberately do NOT match protocol substrings here (e.g. <proto> →
    # <proto>_tcp) — that introduces a closed-taxonomy hardcoding that breaks
    # the protocol-agnostic design (see feedback_protocol_agnostic_overrides_mvp).
    transport = (
        step.connection.transport_name if step.connection is not None else None
    )
    if not transport:
        transport = getattr(scenario, "transport_name", None)

    # Node-share cache: compute key BEFORE the stub-fallback fast-path so
    # cached LLM scripts are still preferred over fresh stubs (a cached LLM
    # script for the same step+plan+binding is strictly more useful).
    cache_key: str | None = None
    if cache_dir is not None:
        try:
            cache_key = _step_cache_key(
                step, step_plan, target_binding, assigned_controls, transport,
            )
        except Exception:  # noqa: BLE001 — never let caching break codegen
            cache_key = None
    cached = _cache_lookup(cache_dir, cache_key) if cache_key else None
    if cached is not None and isinstance(cached.get("code"), str):
        return StepScript(
            scenario_id=scenario.scenario_id,
            path_id=path.path_id,
            step_id=step.step_id,
            code=cached["code"],
            llm_used=False,
            fallback_used=False,
            fallback_reason="cache_hit",
            contract_retry_used=bool(cached.get("contract_retry_used", False)),
            contract_violations=list(cached.get("contract_violations", [])),
        )

    if generator is None:
        code = stub_generate(scenario, path, step, assigned_controls, transport, reason="stub")
        return StepScript(
            scenario_id=scenario.scenario_id,
            path_id=path.path_id,
            step_id=step.step_id,
            code=code,
            llm_used=False,
            fallback_used=True,
            fallback_reason="stub",
        )

    def _invoke_generator(feedback: str | None) -> str:
        # Progressive TypeError fallback so external generators that pre-date
        # later signature additions (target_binding, contract_feedback,
        # path_locked_imports, prior_step_codes) keep working — they just
        # lose the corresponding capability.
        try:
            return generator(
                scenario, path, step, assigned_controls, transport,
                step_plan, path_plan_steps, target_binding,
                contract_feedback=feedback,
                path_locked_imports=path_locked_imports,
                prior_step_codes=prior_step_codes,
            )
        except TypeError:
            pass
        try:
            return generator(
                scenario, path, step, assigned_controls, transport,
                step_plan, path_plan_steps, target_binding,
                contract_feedback=feedback,
                path_locked_imports=path_locked_imports,
            )
        except TypeError:
            pass
        try:
            return generator(
                scenario, path, step, assigned_controls, transport,
                step_plan, path_plan_steps, target_binding,
                contract_feedback=feedback,
            )
        except TypeError:
            pass
        try:
            return generator(
                scenario, path, step, assigned_controls, transport,
                step_plan, path_plan_steps, target_binding,
            )
        except TypeError:
            pass
        try:
            return generator(
                scenario, path, step, assigned_controls, transport,
                step_plan, path_plan_steps,
            )
        except TypeError:
            return generator(scenario, path, step, assigned_controls, transport)

    def _validated(raw: str) -> str:
        """Run the cheap structural + safety checks. Returns clean code or
        raises ScriptValidationError / SafetyValidationError."""
        c = _strip_fences(raw)
        validate_code(c, step.step_id)
        ok, vs = safety_validator.check(c)
        if not ok:
            raise SafetyValidationError(vs)
        return c

    try:
        raw = _invoke_generator(feedback=None)
        code = _validated(raw)

        # Contract verification (P5). If the first attempt violates the v4
        # contract, retry ONCE with the violation list as feedback. The
        # retry's output is preferred only when it actually clears the
        # violations — otherwise we keep the original code and surface
        # the surviving violations as metadata for review.
        c_violations = contract_verifier.verify(
            code, step_plan=step_plan, target_binding=target_binding,
        )
        retry_used = False
        surviving = [v.rule for v in c_violations]
        # WARN-grade rules surface in feedback/metadata but do not, on
        # their own, force a retry. A retry only fires when at least one
        # hard violation is present.
        _WARN_RULES = {"R12_endpoint_key_unused"}
        hard_violations = [v for v in c_violations if v.rule not in _WARN_RULES]
        if hard_violations:
            feedback = contract_verifier.format_feedback(c_violations)
            try:
                raw_retry = _invoke_generator(feedback=feedback)
                # Retry must still pass structural + safety. If it doesn't,
                # we drop the retry silently and keep the first code.
                try:
                    code_retry = _validated(raw_retry)
                    retry_violations = contract_verifier.verify(
                        code_retry, step_plan=step_plan,
                        target_binding=target_binding,
                    )
                    retry_used = True
                    retry_hard = [
                        v for v in retry_violations
                        if v.rule not in _WARN_RULES
                    ]
                    if not retry_hard:
                        code = code_retry
                        surviving = [v.rule for v in retry_violations]
                    elif len(retry_hard) < len(hard_violations):
                        # Strict improvement on hard violations — accept
                        # the retry even if not perfect.
                        code = code_retry
                        surviving = [v.rule for v in retry_violations]
                except (ScriptValidationError, SafetyValidationError):
                    # Retry produced unparseable / unsafe code — keep the
                    # original. retry_used stays True so metadata reflects
                    # that we tried.
                    retry_used = True
            except Exception:  # noqa: BLE001 — retry is best-effort
                # Generator raised on retry (API error, etc.). Swallow and
                # keep the first code; the original violations are recorded.
                pass

        # (D) HARD IMPORT REJECT — if R10_import_name_missing or
        # R10_module_not_found survived BOTH the first attempt and the retry,
        # the code is guaranteed to crash at import time inside the testbed.
        # Don't keep it: emit a stub so the path makes deterministic progress
        # and the cache is not poisoned with a guaranteed-fail script.
        surviving_hard_imports = sorted(_HARD_IMPORT_RULES.intersection(surviving))
        if surviving_hard_imports:
            stub = stub_generate(
                scenario, path, step, assigned_controls, transport,
                reason=(
                    "import_violation_unresolved: " +
                    ",".join(surviving_hard_imports)
                ),
            )
            return StepScript(
                scenario_id=scenario.scenario_id,
                path_id=path.path_id,
                step_id=step.step_id,
                code=stub,
                llm_used=False,
                fallback_used=True,
                fallback_reason=(
                    "import_violation_unresolved: " +
                    ",".join(surviving_hard_imports)
                ),
                contract_retry_used=retry_used,
                contract_violations=surviving,
            )

        # Persist to cache so a sibling path with the same step+plan+binding
        # can reuse this exact script. Stored AFTER any retry resolved so
        # the cached version is the best one we produced. Cache miss only
        # writes when the LLM path succeeded; fallback/blocked paths do
        # not pollute the cache.
        if cache_key is not None:
            _cache_store(
                cache_dir, cache_key, code,
                scenario_id=scenario.scenario_id,
                path_id=path.path_id,
                step_id=step.step_id,
                contract_retry_used=retry_used,
                contract_violations=surviving,
            )

        return StepScript(
            scenario_id=scenario.scenario_id,
            path_id=path.path_id,
            step_id=step.step_id,
            code=code,
            llm_used=True,
            fallback_used=False,
            fallback_reason=None,
            contract_retry_used=retry_used,
            contract_violations=surviving,
        )
    except Exception as e:  # noqa: BLE001 — fallback is the design
        category = classify_fallback(e)
        reason = f"{category}: {type(e).__name__}: {e}"
        code = stub_generate(
            scenario, path, step, assigned_controls, transport,
            reason=f"llm_generation_failed: {reason}",
        )
        return StepScript(
            scenario_id=scenario.scenario_id,
            path_id=path.path_id,
            step_id=step.step_id,
            code=code,
            llm_used=False,
            fallback_used=True,
            fallback_reason=reason,
        )


# ---------------------------------------------------------------------------
# Unresolved gate — between step3a and step3b.
#
# When step3a returns binding_status=resolution_failed for a step, codegen
# is intentionally skipped: we emit a structural placeholder script that
# returns a BLOCKED marker dict rather than letting the LLM fabricate
# defaults (host/port/method/opcode/payload). Once a step is blocked, all
# subsequent steps in the same path inherit execution_blocked — they cannot
# meaningfully proceed without their predecessor's outputs.
#
# This is the 1st safety net described in
# feedback_constrain_imagination_not_semantics.md (defense in depth);
# the 2nd safety net (step4a recognizing the marker → Verdict.BLOCKED)
# lands with Delta③.
# ---------------------------------------------------------------------------

_BLOCKED_TEMPLATE = '''\
"""BLOCKED: codegen skipped for {scenario_id}/{path_id}/{step_id}.

Reason: {reason}
Unresolved fields: {unresolved_fields}

This script is a structural placeholder emitted by the unresolved-gate
between step3a and step3b. It does NOT execute any attack action.
run_step returns a marker dict so step4a can map it to Verdict.BLOCKED
(intentional pause, NOT execution failure).
"""

from __future__ import annotations

PIPELINE_BLOCKED_MARKER = "PIPELINE_STEP_BLOCKED"
_BLOCKED_REASON = {reason!r}
_BLOCKED_UNRESOLVED_FIELDS = {unresolved_fields!r}


def run_step(context: dict, artifacts: dict) -> dict:
    return {{
        "observations": [],
        "artifacts": {{}},
        "notes": "BLOCKED: " + _BLOCKED_REASON,
        "_pipeline_blocked": True,
        "_pipeline_blocked_reason": _BLOCKED_REASON,
        "_pipeline_blocked_unresolved_fields": list(_BLOCKED_UNRESOLVED_FIELDS),
    }}
'''


def emit_blocked_script(
    scenario: NormalizedScenario,
    path: AttackPath,
    step: AttackStep,
    reason: str,
    unresolved_fields: list[str],
) -> StepScript:
    """Emit a placeholder script for a step that cannot be grounded."""
    code = _BLOCKED_TEMPLATE.format(
        scenario_id=scenario.scenario_id,
        path_id=path.path_id,
        step_id=step.step_id,
        reason=reason,
        unresolved_fields=list(unresolved_fields),
    )
    return StepScript(
        scenario_id=scenario.scenario_id,
        path_id=path.path_id,
        step_id=step.step_id,
        code=code,
        llm_used=False,
        fallback_used=False,
        fallback_reason=None,
        blocked=True,
        blocked_reason=reason,
        blocked_unresolved_fields=list(unresolved_fields),
    )


def _is_step_blocked(
    binding: StepBinding | None,
    step_plan: StepPlan | None = None,
    prior_artifact_names: set[str] | None = None,
) -> tuple[bool, str, list[str]]:
    """Return (blocked, reason, unresolved_fields) for one step's binding.

    P6 Phase A: gate is now NARROW. A step is blocked only when it cannot
    even start — not just because some refinement field (method name,
    object_path, can_id, ...) is unresolved.

    Hard-block conditions (any one triggers BLOCKED):
      H1. no StepBinding at all (defensive default), OR
      H2. target_binding is None (step3a didn't populate it), OR
      H3. binding_status == "resolution_failed" AND no anchor at all
          (protocol empty AND endpoint empty), OR
      H4. protocol is empty (no transport identity to dispatch on), OR
      H5. endpoint is empty (no addressable target — host/port/socket/iface), OR
      H6. step_plan declares requires_from_prior items that are NOT present in
          prior_artifact_names (an upstream artifact this step depends on was
          never produced).

    NOT a block reason (these are runtime-discoverable):
      - target_binding.unresolved_fields containing method names, object paths,
        service names, can_ids, opcodes, payload shapes, etc.
      - binding_status == "resolution_failed" when at least protocol+endpoint
        are present (LLM was honest about partial grounding; codegen can still
        attempt the attack and discover the rest at runtime).
    """
    if binding is None:
        return True, "no StepBinding from step3a", ["protocol", "endpoint"]
    tb = binding.target_binding
    if tb is None:
        return True, "step3a did not produce a target_binding for this step", \
               ["protocol", "endpoint"]

    missing: list[str] = []
    if not tb.protocol:
        # Protocol identity is the one thing that CANNOT be discovered at
        # runtime — codegen has to dispatch on it. Empty protocol always
        # blocks regardless of runtime_discovery_fields.
        missing.append("protocol")

    # P6 Phase B: empty endpoint is allowed when step2 declared bounded
    # discovery for the address fields. The script will probe / enumerate
    # to find host/port/socket at runtime, then write them back into
    # artifacts for downstream steps. Only block on endpoint when there is
    # ALSO no runtime_discovery_fields whitelist (truly nothing to dispatch
    # on AND nothing to discover toward).
    if not tb.endpoint and not (tb.runtime_discovery_fields or []):
        missing.append("endpoint")

    if missing:
        # Either the LLM gave up, or it returned status=bound but with empty
        # anchors. Either way, codegen has nothing to dispatch on.
        reason = tb.reason or (
            f"hard-block: missing {missing} (protocol is required to "
            f"dispatch; endpoint is required unless runtime_discovery_fields "
            f"declares bounded discovery)"
        )
        return True, reason, missing

    # H6: required prior artifacts missing.
    if step_plan is not None and step_plan.requires_from_prior:
        prior = prior_artifact_names or set()
        unmet = [name for name in step_plan.requires_from_prior if name not in prior]
        if unmet:
            return (
                True,
                f"hard-block: required prior artifacts not produced upstream: {unmet}",
                [f"prior:{n}" for n in unmet],
            )

    return False, "", []


def generate_scripts_for_path(
    scenario: NormalizedScenario,
    path: AttackPath,
    bindings: list[StepBinding],
    generator: Generator | None = None,
    path_plan_steps: list[StepPlan] | None = None,
    cache_dir: Path | None = None,
) -> list[StepScript]:
    bindings_by_step = {b.step_id: b for b in bindings}
    plan_by_step: dict[str, StepPlan] = {}
    if path_plan_steps:
        plan_by_step = {sp.step_id: sp for sp in path_plan_steps}

    scripts: list[StepScript] = []
    propagated_from: str | None = None  # step_id that first triggered the block
    # P6 Phase A: track artifacts produced by upstream non-blocked steps so the
    # gate can verify requires_from_prior. Names come from step_plan.artifacts
    # (declared step2 outputs) — the actual runtime values are not inspected
    # here, only the declared NAMES, so this stays static-analysis-only.
    prior_artifact_names: set[str] = set()
    # (A) PATH IMPORT LOCK — accumulate verbatim import lines from earlier
    # successful (LLM-produced, no surviving hard-import violations) steps in
    # this path so the next step's prompt can pin them. Order-preserving.
    path_locked_imports: list[str] = []
    _path_locked_seen: set[str] = set()
    # UPSTREAM PRODUCER CODES — full verbatim source of earlier (non-blocked,
    # non-stub) steps in this same path, keyed by step_id in generation order.
    # Handed to the next step's prompt so the consumer LLM can see the exact
    # artifact value formats and library-API usage the producer emitted,
    # rather than guessing from abstract shape contracts. Includes cache hits
    # (previously-verified LLM output) but excludes stubs / blocked placeholders.
    prior_step_codes: dict[str, str] = {}

    for step in path.steps:
        sb = bindings_by_step.get(step.step_id)
        sp = plan_by_step.get(step.step_id)

        if propagated_from is not None:
            # A prior step in this path was blocked. Conservatively block
            # every subsequent step too — they would run against a missing
            # upstream artifact and either crash or fabricate.
            scripts.append(emit_blocked_script(
                scenario, path, step,
                reason=f"execution_blocked propagated from {propagated_from}",
                unresolved_fields=[f"upstream:{propagated_from}"],
            ))
            continue

        is_blocked, reason, unresolved = _is_step_blocked(
            sb, step_plan=sp, prior_artifact_names=prior_artifact_names,
        )
        if is_blocked:
            scripts.append(emit_blocked_script(
                scenario, path, step,
                reason=reason,
                unresolved_fields=unresolved,
            ))
            propagated_from = step.step_id
            continue

        assigned = sb.assigned_controls if sb else []
        sc = generate_script_for_step(
            scenario, path, step, assigned, generator=generator,
            step_plan=sp,
            path_plan_steps=path_plan_steps,
            target_binding=sb.target_binding if sb else None,
            cache_dir=cache_dir,
            path_locked_imports=path_locked_imports or None,
            prior_step_codes=dict(prior_step_codes) if prior_step_codes else None,
        )
        scripts.append(sc)
        # Step ran (or will run) → its declared output artifact names become
        # available to downstream steps' requires_from_prior checks. step2
        # uses "outputs" as the canonical key; "inputs" represents what this
        # step CONSUMES, not what it produces.
        if sp is not None:
            for ref in (sp.artifacts or {}).get("outputs", []):
                if getattr(ref, "name", None):
                    prior_artifact_names.add(ref.name)
        # (A) Lock-extension: only contribute imports from steps that the LLM
        # actually produced AND that did not have a surviving hard-import
        # violation. Stub fallbacks, blocked placeholders, and import-rejected
        # downgrades all skip — we only want imports the verifier accepted as
        # working. Cache hits (`llm_used=False`, `fallback_reason="cache_hit"`)
        # also count, since they're previously verified LLM output.
        if not sc.blocked and not _has_hard_import_violation(sc):
            llm_or_cache = sc.llm_used or (
                sc.fallback_reason == "cache_hit"
            )
            if llm_or_cache:
                for line in _extract_top_imports(sc.code):
                    if line in _path_locked_seen:
                        continue
                    _path_locked_seen.add(line)
                    path_locked_imports.append(line)
                # Contribute this step's full source as an upstream exemplar
                # for the next step's consumer prompt. Mirrors the import-lock
                # predicate: only LLM-produced or cache-hit scripts that the
                # verifier accepted are eligible. Stubs / blocked / surviving
                # hard-import violations are excluded so downstream prompts
                # never see broken producer code as "the pattern to follow".
                prior_step_codes[sc.step_id] = sc.code
    return scripts


def _has_hard_import_violation(sc: StepScript) -> bool:
    return bool(_HARD_IMPORT_RULES.intersection(sc.contract_violations or []))


def script_to_dict(s: StepScript) -> dict[str, Any]:
    return {
        "scenario_id": s.scenario_id,
        "path_id": s.path_id,
        "step_id": s.step_id,
        "code": s.code,
        "llm_used": s.llm_used,
        "fallback_used": s.fallback_used,
        "fallback_reason": s.fallback_reason,
        "blocked": s.blocked,
        "blocked_reason": s.blocked_reason,
        "blocked_unresolved_fields": list(s.blocked_unresolved_fields),
        "contract_retry_used": s.contract_retry_used,
        "contract_violations": list(s.contract_violations),
    }
