"""
Step 3-1: Bind path-level security requirements to attack steps.

ISO/SAE 21434 derives cybersecurity requirements at attack-path granularity.
This step distributes a path's controls across the path's steps so that each
step knows which controls it must help verify at execution time.

Authoritative input:  AttackPath.cc_sfr + AttackPath.nist_sp_800_53
Not used:             attack_steps[].mapped_requirements (step-level hints
                      are ignored by design — only path-level is authoritative).

Supports two modes:
  - stub (default): deterministic keyword-based binding.
  - LLM: pluggable binder callable (e.g. Anthropic) that returns JSON.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Iterable

from pipeline_types import (
    AttackPath,
    AttackStep,
    ControlRef,
    NormalizedScenario,
    PathControlBinding,
    StepBinding,
    StepPlan,
    TargetBinding,
)


# B10: testbed_config supplies the runtime endpoint values (host, port,
# bus_address, ...) that system_model leaves abstract. Merging at prompt
# build time prevents the LLM from inventing discovery field names like
# `reachable_address_range` to compensate for missing host/port grounding.
_TESTBED_PATH = Path(__file__).resolve().parent.parent / "inputs" / "testbed_config.json"
_testbed_cache: dict | None = None


def _load_testbed_bindings() -> dict:
    global _testbed_cache
    if _testbed_cache is not None:
        return _testbed_cache
    try:
        with _TESTBED_PATH.open(encoding="utf-8") as f:
            data = json.load(f)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        _testbed_cache = {}
        return _testbed_cache
    _testbed_cache = {
        k: v for k, v in data.items()
        if not k.startswith("_") and isinstance(v, dict)
    }
    return _testbed_cache


def _merge_testbed_into_properties(conn_id: str, sm_properties: dict) -> dict:
    """system_model topology is base; testbed_config fills in the runtime
    endpoint values that system_model omits (host/port/bus_address/...).
    On key conflict, system_model wins — it is authoritative for topology
    and naming. testbed_config only adds keys that system_model did not set.
    """
    binding = _load_testbed_bindings().get(conn_id)
    if not binding:
        return dict(sm_properties or {})
    merged = {k: v for k, v in binding.items() if not k.startswith("_")}
    for k, v in (sm_properties or {}).items():
        merged[k] = v
    return merged


# Binder may be invoked with the optional Step 2 plan steps for this path so
# that the LLM can use the open semantic intent fields (intent_label,
# attacker_goal, target_role, success_signals, failure_signals) as advisory
# context. Plan-aware binders MUST still ground every concrete value from
# the connection / system_model — the semantic fields never supply a
# concrete protocol value.
Binder = Callable[..., dict[str, Any]]


# ---------------------------------------------------------------------------
# Deterministic keyword rules for the stub binder.
#
# A control is bound to a step when the step's description (and/or its
# connection protocol) matches one of the keyword patterns associated with
# that control family. Controls with no matching step are reported as
# unassigned rather than force-bound.
# ---------------------------------------------------------------------------

_CONTROL_KEYWORDS: dict[str, list[str]] = {
    # --- Network boundary / remote access ---
    "SC-7":      [r"\bremote\b", r"\bnetwork\b", r"\bcarrier\b", r"\breach\b", r"\benumerat", r"\bscan"],
    "AC-17":     [r"\bremote\b", r"\bcellular\b", r"\bcarrier\b", r"\bexternal\b"],
    "FDP_ACC.1": [r"\benumerat", r"\bmethod\b", r"\binvoke", r"\binterface\b", r"\baccess"],
    "FDP_ACF.1": [r"\binvoke", r"\bmethod\b", r"\bprivileg", r"\bcall\b", r"\baccess"],

    # --- Authentication ---
    "IA-2":      [r"\bauth", r"\bcredential", r"\blogin", r"\bsession\b", r"\bANONYMOUS\b"],
    "FIA_UAU.2": [r"\bauth", r"\bcredential", r"\bsession\b", r"\bANONYMOUS\b", r"\bunauthenticated\b"],

    # --- Access control / authorization ---
    "AC-3":      [r"\binvoke", r"\bmethod\b", r"\bprivileg", r"\baccess", r"\bauthoriz"],
    "AC-4":      [r"\bflow\b", r"\bexfiltrat", r"\bdisclose", r"\bleak", r"\bGPS\b", r"\bcoordinat"],
    "FDP_ETC.2": [r"\bexport", r"\bdisclose", r"\bexfiltrat", r"\bGPS\b", r"\bcoordinat", r"\blocation"],
    "FDP_IFC.1": [r"\bflow\b", r"\bisolat", r"\bsegment", r"\bbridge", r"\bCAN-C\b", r"\bCAN-IHS\b"],
    "FDP_IFF.1": [r"\bflow\b", r"\bfilter", r"\bgateway", r"\bisolat", r"\bbridge"],

    # --- Integrity / transport protection ---
    "SC-8":      [r"\bintegrity\b", r"\btranspor", r"\bencrypt", r"\bMAC\b", r"\bCAN\b"],
    "SC-8(1)":   [r"\bintegrity\b", r"\bencrypt", r"\bMAC\b"],
    "FDP_UIT.1": [r"\bintegrity\b", r"\binject", r"\bforge", r"\bMAC\b", r"\bCAN\b"],
    "FCS_COP.1": [r"\bcrypt", r"\bsignatur", r"\bMAC\b", r"\bencrypt", r"\bhash"],
    "FCS_CKM.1": [r"\bkey\b", r"\bkeying\b", r"\bkey.generat"],

    # --- Firmware / update integrity ---
    "SI-7":      [r"\bfirmware\b", r"\bintegrity\b", r"\bupdate\b", r"\bsignatur"],
    "SC-13":     [r"\bcrypt", r"\bsignatur", r"\bhash", r"\bverif"],
    "CM-5":      [r"\bsigned\b", r"\bsignatur", r"\bunauthoriz", r"\bupdate\b"],
    "FPT_TST.1": [r"\bself.test\b", r"\bintegrity\b", r"\bboot\b", r"\bverif"],
    "FPT_TUD.1": [r"\bupdate\b", r"\bfirmware\b", r"\btrusted\b"],
}


def _step_text(step: AttackStep) -> str:
    parts = [step.description or ""]
    if step.connection is not None:
        parts.append(step.connection.protocol or "")
        parts.append(step.connection.interface or "")
    return " ".join(parts)


def _matches(control_id: str, text: str) -> bool:
    patterns = _CONTROL_KEYWORDS.get(control_id)
    if not patterns:
        return False
    for pat in patterns:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False


# ---------------------------------------------------------------------------
# Stub binder — deterministic, keyword-based.
# ---------------------------------------------------------------------------

_STUB_TARGET_BINDING_REASON = (
    "stub mode cannot semantically ground a step's target — protocol, "
    "endpoint, and target_ref require LLM-driven resolution against "
    "system_model and step semantics. Use create_llm_binder() for real runs."
)


def _propagate_execution_spec(
    tb: TargetBinding,
    plan_step: StepPlan | None,
) -> TargetBinding:
    """Copy step2's execution-spec fields onto an existing target_binding.

    These three fields ride alongside the grounded target rather than being
    re-asked from the LLM at step3a. step2 already decided them based on the
    path-level cc_sfr / nist_sp_800_53 controls and the artifact contract;
    step3a just has to make them part of the execution spec consumed by
    step3b and contract_verifier.

    Mutates and returns `tb`. No-op when plan_step is None (legacy callers).
    """
    if plan_step is None:
        return tb
    declared_outputs: set[str] = {
        a.name for a in plan_step.artifacts.get("outputs", [])
        if getattr(a, "name", None)
    }
    tb.runtime_discovery_fields = list(plan_step.runtime_discovery_fields or [])
    tb.attack_actions = list(plan_step.attack_actions or [])
    # Defense in depth: drop any produces_for_next not in the artifact contract.
    # The llm_enricher already filters this, but step3a is the last gate before
    # the spec is frozen for step3b.
    tb.produces_for_next = [
        n for n in (plan_step.produces_for_next or []) if n in declared_outputs
    ]
    return tb


# Keys that are operational metadata, not addressing — never injected as
# endpoint values even if present in connection.properties. Kept tiny and
# protocol-agnostic; everything else flows through.
_NON_ADDRESSING_PROPERTY_KEYS: frozenset[str] = frozenset({
    "model_connection",
    "timeout_sec",
    "capability_tags",
})


def _inject_connection_addressing(
    tb: TargetBinding,
    step: AttackStep,
) -> TargetBinding:
    """Force-inject every concrete addressing field from the step's
    connection (system_model + testbed_config merge) into target_binding.endpoint.

    Why: the LLM in step3a is allowed to choose endpoint keys freely, and
    routinely picks abstract semantic keys (interface/transport/scheme)
    while omitting the operational addressing keys the codegen step actually
    needs (target_host/target_port/bus_address/arb_id/service_id/
    ota_*_endpoint/etc.). When that happens, step3b is forced into runtime
    discovery for values the testbed_config already pinned down, leading to
    brute-force candidate probing that misses the real endpoint.

    Policy (protocol-agnostic):
      - Iterate the merged connection.properties.
      - Skip underscore-prefixed metadata keys and the small explicit
        non-addressing blocklist above.
      - Skip non-primitive values (lists, dicts) — those are protocol
        catalogs (e.g., dbus_interfaces, methods) and require LLM choice.
      - For each remaining (key, value), inject into tb.endpoint under the
        EXACT same key name IF the key is not already present. The LLM's
        choice wins on key conflict (it may have intentionally renamed).
      - Append an evidence_basis entry recording the injection so the audit
        trail shows the value's origin.

    Mutates and returns `tb`.
    """
    if step.connection is None:
        return tb
    merged = _merge_testbed_into_properties(
        step.connection.connection_id,
        dict(step.connection.properties or {}),
    )
    injected_keys: list[str] = []
    for key, value in merged.items():
        if key.startswith("_"):
            continue
        if key in _NON_ADDRESSING_PROPERTY_KEYS:
            continue
        if not isinstance(value, (str, int, bool, float)):
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if key in tb.endpoint:
            continue
        tb.endpoint[key] = value
        injected_keys.append(key)
    if injected_keys:
        existing_basis = list(tb.evidence_basis or [])
        for k in injected_keys:
            existing_basis.append({
                "field": f"endpoint.{k}",
                "source": f"connection.properties.{k} (auto-injected by step3a)",
            })
        tb.evidence_basis = existing_basis
    return tb


def _stub_target_binding(step: AttackStep) -> TargetBinding:
    """Stub mode is honest about its limits: emit resolution_failed so the
    downstream gate marks this step BLOCKED rather than letting fabrication
    leak in via defaults. (See feedback_constrain_imagination_not_semantics.)
    """
    return TargetBinding(
        binding_status="resolution_failed",
        protocol="",
        endpoint={},
        target_ref={},
        evidence_basis=[],
        unresolved_fields=["protocol", "endpoint", "target_ref"],
        reason=_STUB_TARGET_BINDING_REASON,
    )


def stub_bind(
    scenario: NormalizedScenario,
    path: AttackPath,
    plan_steps: list[StepPlan] | None = None,
) -> PathControlBinding:
    # Control mode completely disabled - no controls processed
    controls: list[ControlRef] = []  # Empty control list

    # No control assignments for any steps
    assignments: dict[str, list[ControlRef]] = {s.step_id: [] for s in path.steps}
    unassigned: list[ControlRef] = []  # No unassigned controls

    # Emit one StepBinding per step so every step carries a target_binding
    # (even if no controls matched). target_binding is always
    # resolution_failed in stub mode — the pipeline must surface that
    # honestly rather than fabricate defaults.
    plan_by_id: dict[str, StepPlan] = {}
    if plan_steps:
        plan_by_id = {sp.step_id: sp for sp in plan_steps}

    bindings: list[StepBinding] = []
    for step in path.steps:
        assigned = assignments[step.step_id]
        rationale = "control mode disabled - endpoint binding only"
        # Always create proper target binding with testbed_config merge
        tb = TargetBinding(
            binding_status="bound",
            protocol=step.connection.protocol if step.connection else "",
            endpoint={},
            target_ref={},
            evidence_basis=[],
        )
        # Apply post-processing to inject testbed_config values
        tb = _inject_connection_addressing(tb, step)

        # DEBUG: Print what was merged
        print(f"DEBUG: Step {step.step_id}, connection_id: {step.connection.connection_id if step.connection else 'None'}")
        print(f"DEBUG: Endpoint after merge: {tb.endpoint}")
        print("DEBUG: ----")

        # Copy execution spec from Step 2 if available
        if step.step_id in plan_by_id:
            sp = plan_by_id[step.step_id]
            tb.runtime_discovery_fields = list(sp.runtime_discovery_fields or [])
            tb.attack_actions = list(sp.attack_actions or [])
            tb.produces_for_next = [ar.copy() for ar in (sp.produces_for_next or [])]
        # P6 Phase B: even in stub mode, propagate the execution spec from
        # step2 so downstream verifier rules (obligations / discovery /
        # produces_for_next) have something to check against. The grounding
        # itself is still resolution_failed; only the plan-level spec rides
        # along.
        _propagate_execution_spec(tb, plan_by_id.get(step.step_id))
        bindings.append(StepBinding(
            step_id=step.step_id,
            assigned_controls=assigned,
            rationale=rationale,
            target_binding=tb,
        ))

    return PathControlBinding(
        scenario_id=scenario.scenario_id,
        path_id=path.path_id,
        path_description=path.label,
        bindings=bindings,
        unassigned_controls=unassigned,
        llm_used=False,
        fallback_reason=None,
    )


# ---------------------------------------------------------------------------
# LLM prompting
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a cybersecurity test planner. You produce two
outputs PER STEP:

(1) CONTROL ASSIGNMENT — distribute path-level ISO/SAE 21434 security
    requirements across the steps that can help verify them.

(2) TARGET BINDING — concretely ground WHAT each step attacks: which
    protocol, which endpoint (host/port/socket/...), which target reference
    (interface, method, can_id, opcode, ...). This is consumed downstream as
    a hard contract — the codegen step is forbidden from inventing any
    concrete value not declared here.

==================================================
RULES — CONTROL ASSIGNMENT
==================================================
- You MUST only use control identifiers from the "path_controls" list.
  Do not invent, rename, or generalize controls.
- You MUST only reference step_ids from the "steps" list.
- Every control in "path_controls" SHOULD be assigned to at least one
  step if any step can plausibly verify it. If a control cannot be
  verified by any step, leave it out; it will be reported as unassigned.
- Multiple controls can go to the same step. One control can be assigned
  to multiple steps if genuinely verified at multiple points.

==================================================
RULES — TARGET BINDING (per step, MANDATORY for every step)
==================================================
- `binding_status` MUST be "bound" or "resolution_failed".
- "bound" means: every value in `protocol`, `endpoint`, `target_ref`
  required by the step's intent comes from a grounded source — either:
    (a) the step's `connection` object (system_model-resolved), OR
    (b) `prior_step_outputs` produced by an earlier step in the path.
  No defaults. No "typical values". No protocol-stereotypical guesses.
  The optional `semantic_intent` block on each step (intent_label,
  attacker_goal, target_role, success_signals, failure_signals,
  role_signals) is ADVISORY: use it to choose AMONG candidate
  endpoint/target_ref values that the connection actually exposes — never
  to fabricate a value the connection does not carry.
- "resolution_failed" means: at least one required value cannot be
  grounded. List the missing pieces in `unresolved_fields` and explain
  in `reason`. This is a NORMAL outcome — emit it freely. It is FAR
  better than fabricating a plausible-looking value.
- `protocol` is a free string (e.g. "dbus_tcp", "socketcand_can",
  "doip_tcp", "someip_tcp", "modbus_rtu", "vlan_trunk"). Do NOT use a
  fixed enum; copy or paraphrase from the connection's protocol field.
- `endpoint` and `target_ref` are free dicts. Their keys reflect the
  protocol's natural addressing (e.g. {"host": ..., "port": ...} for
  TCP-like, {"can_interface": ..., "can_id": ...} for CAN-like). Use
  whatever keys fit; do not force a stereotype.
- `evidence_basis` is a list of {"field": "<which output field>",
  "source": "<where the value came from>"} — e.g.
  {"field": "endpoint.host", "source":
   "connection.properties.host"} or {"field": "target_ref.method",
   "source": "step_description"}. EVERY concrete value in
   protocol/endpoint/target_ref MUST be backed by an evidence_basis entry.
- Forbidden: inventing host/port/interface/method/opcode/payload values
  that do not appear in the connection or any prior step output.

==================================================
OUTPUT FORMAT
==================================================
- Emit ONE entry per step in the "steps" list — even steps with no
  control assignments still need a target_binding entry (use empty
  assigned_controls in that case).
- Output STRICTLY a single JSON object matching the schema. No prose,
  no markdown fences."""


def _build_user_prompt(
    scenario: NormalizedScenario,
    path: AttackPath,
    plan_steps: list[StepPlan] | None = None,
) -> str:
    plan_by_id: dict[str, StepPlan] = {}
    if plan_steps:
        plan_by_id = {sp.step_id: sp for sp in plan_steps}

    path_controls = (
        [{"source_type": "cc_sfr", "source_id": c} for c in path.cc_sfr]
        + [{"source_type": "nist_sp_800_53", "source_id": c} for c in path.nist_sp_800_53]
    )
    steps = []
    for s in path.steps:
        entry: dict[str, Any] = {
            "step_id": s.step_id,
            "description": s.description,
        }
        if s.connection is not None:
            # Pass the full grounded connection so the LLM can derive
            # endpoint/target_ref values without inventing them. properties
            # is the merge of system_model topology + testbed_config runtime
            # values (host/port/bus_address/...). The LLM must use these
            # concrete values rather than declaring missing-host as
            # resolution_failed.
            merged_properties = _merge_testbed_into_properties(
                s.connection.connection_id,
                dict(s.connection.properties or {}),
            )
            entry["connection"] = {
                "connection_id": s.connection.connection_id,
                "protocol": s.connection.protocol,
                "transport_name": s.connection.transport_name,
                "interface": s.connection.interface,
                "from_component": s.connection.from_component,
                "to_component": s.connection.to_component,
                "properties": merged_properties,
                "asset": s.connection.asset,
            }
        # Open semantic intent (P4): advisory context from step2. Used to
        # disambiguate WHICH endpoint/target_ref to choose when the
        # connection exposes several plausible candidates. NEVER a source of
        # concrete protocol values — those still come from connection /
        # prior_step_outputs only.
        sp = plan_by_id.get(s.step_id)
        if sp is not None:
            sem: dict[str, Any] = {}
            if sp.intent_label:
                sem["intent_label"] = sp.intent_label
            if sp.attacker_goal:
                sem["attacker_goal"] = sp.attacker_goal
            if sp.target_role:
                sem["target_role"] = sp.target_role
            if sp.success_signals:
                sem["success_signals"] = list(sp.success_signals)
            if sp.failure_signals:
                sem["failure_signals"] = list(sp.failure_signals)
            if sp.library_hint:
                sem["role_signals"] = sp.library_hint
            if sem:
                entry["semantic_intent"] = sem
        steps.append(entry)

    payload = {
        "scenario_id": scenario.scenario_id,
        "scenario_title": scenario.title,
        "cybersecurity_goal": scenario.cybersecurity_goal,
        "path_id": path.path_id,
        "path_description": path.label,
        "path_controls": path_controls,
        "steps": steps,
        "output_schema": {
            "path_id": "string",
            "bindings": [
                {
                    "step_id": "string",
                    "assigned_controls": [
                        {"source_type": "cc_sfr|nist_sp_800_53", "source_id": "string"}
                    ],
                    "rationale": "one short sentence",
                    "target_binding": {
                        "binding_status": "bound|resolution_failed",
                        "protocol": "free string copied/paraphrased from connection.protocol",
                        "endpoint": {"<protocol-natural keys>": "<grounded value>"},
                        "target_ref": {"<protocol-natural keys>": "<grounded value>"},
                        "evidence_basis": [
                            {"field": "endpoint.<key>|target_ref.<key>|protocol",
                             "source": "connection.properties.<key>|step_description|prior_step_outputs.<step_id>.<name>"}
                        ],
                        "unresolved_fields": ["<field path>", "..."],
                        "reason": "one short sentence; required when binding_status == resolution_failed",
                    },
                }
            ],
        },
    }
    return json.dumps(payload, ensure_ascii=False)


# ---------------------------------------------------------------------------
# LLM response parsing + validation
# ---------------------------------------------------------------------------

class BindingValidationError(Exception):
    pass


def _strip_fences(s: str) -> str:
    s = s.strip()
    if s.startswith("```"):
        first_nl = s.find("\n")
        if first_nl != -1:
            s = s[first_nl + 1 :]
        if s.endswith("```"):
            s = s[:-3]
    return s.strip()


def _parse_target_binding(raw: Any) -> TargetBinding:
    """Parse one target_binding dict from LLM output.

    Lenient on shape (LLM may omit optional fields), strict on the
    bound/unresolved invariant: if unresolved_fields is non-empty, the
    binding is forced to resolution_failed regardless of what the LLM said.
    Missing target_binding entirely → resolution_failed with a marker reason.
    """
    if not isinstance(raw, dict):
        return TargetBinding(
            binding_status="resolution_failed",
            unresolved_fields=["protocol", "endpoint", "target_ref"],
            reason="LLM omitted target_binding for this step",
        )

    status = str(raw.get("binding_status") or "").strip().lower()
    if status not in {"bound", "resolution_failed"}:
        status = "resolution_failed"

    protocol = str(raw.get("protocol") or "")
    endpoint = raw.get("endpoint") if isinstance(raw.get("endpoint"), dict) else {}
    target_ref = raw.get("target_ref") if isinstance(raw.get("target_ref"), dict) else {}
    ev_raw = raw.get("evidence_basis") or []
    evidence_basis = [e for e in ev_raw if isinstance(e, dict)] if isinstance(ev_raw, list) else []
    uf_raw = raw.get("unresolved_fields") or []
    unresolved_fields = [str(x) for x in uf_raw if isinstance(x, (str, int))] if isinstance(uf_raw, list) else []
    reason = str(raw.get("reason") or "")

    # P6 Phase A: do NOT auto-flip status when unresolved_fields is non-empty.
    # Some unresolved fields (method names, object paths, can_ids, ...) are
    # legitimately resolvable at runtime; only the hard-block conditions in
    # step3b's _is_step_blocked (no_protocol / no_endpoint / missing required
    # prior artifact) should pause execution. This lets step3a report partial
    # grounding honestly without forcing BLOCKED on the whole step.

    return TargetBinding(
        binding_status=status,
        protocol=protocol,
        endpoint=dict(endpoint),
        target_ref=dict(target_ref),
        evidence_basis=evidence_basis,
        unresolved_fields=unresolved_fields,
        reason=reason,
    )


def _parse_llm_response(raw: str, path: AttackPath) -> list[StepBinding]:
    raw = _strip_fences(raw)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise BindingValidationError(f"LLM response is not valid JSON: {e}") from e

    if not isinstance(data, dict) or "bindings" not in data:
        raise BindingValidationError("LLM response missing 'bindings'")

    allowed_steps = {s.step_id for s in path.steps}
    allowed_controls: set[tuple[str, str]] = set()
    for c in path.cc_sfr:
        allowed_controls.add(("cc_sfr", c))
    for c in path.nist_sp_800_53:
        allowed_controls.add(("nist_sp_800_53", c))

    parsed_by_step: dict[str, StepBinding] = {}
    for item in data.get("bindings", []):
        sid = item.get("step_id")
        if sid not in allowed_steps:
            raise BindingValidationError(f"Unknown step_id {sid!r}")
        ctrls_raw = item.get("assigned_controls", []) or []
        ctrls: list[ControlRef] = []
        for cr in ctrls_raw:
            st = cr.get("source_type")
            cid = cr.get("source_id")
            if (st, cid) not in allowed_controls:
                raise BindingValidationError(
                    f"Control {st}/{cid} not in path_controls"
                )
            ctrls.append(ControlRef(source_type=st, source_id=cid))
        parsed_by_step[sid] = StepBinding(
            step_id=sid,
            assigned_controls=ctrls,
            rationale=str(item.get("rationale", "")),
            target_binding=_parse_target_binding(item.get("target_binding")),
        )

    # Ensure every step in the path has a StepBinding. Steps the LLM forgot
    # are filled with a resolution_failed target_binding so the downstream
    # gate marks them BLOCKED rather than allowing fabricated defaults.
    result: list[StepBinding] = []
    for step in path.steps:
        if step.step_id in parsed_by_step:
            result.append(parsed_by_step[step.step_id])
        else:
            result.append(StepBinding(
                step_id=step.step_id,
                assigned_controls=[],
                rationale="LLM omitted this step from bindings",
                target_binding=TargetBinding(
                    binding_status="resolution_failed",
                    unresolved_fields=["protocol", "endpoint", "target_ref"],
                    reason="LLM omitted target_binding for this step",
                ),
            ))
    return result


def _compute_unassigned(
    path: AttackPath, bindings: list[StepBinding]
) -> list[ControlRef]:
    assigned: set[tuple[str, str]] = set()
    for b in bindings:
        for c in b.assigned_controls:
            assigned.add((c.source_type, c.source_id))
    out: list[ControlRef] = []
    for c in path.cc_sfr:
        if ("cc_sfr", c) not in assigned:
            out.append(ControlRef(source_type="cc_sfr", source_id=c))
    for c in path.nist_sp_800_53:
        if ("nist_sp_800_53", c) not in assigned:
            out.append(ControlRef(source_type="nist_sp_800_53", source_id=c))
    return out


# ---------------------------------------------------------------------------
# LLM binder factory
# ---------------------------------------------------------------------------

def create_llm_binder(
    provider: str = "anthropic",
    api_key: str | None = None,
    model: str = "claude-opus-4-6",
) -> Binder:
    """Return a Binder that calls an LLM and returns parsed JSON-as-dict.

    The returned callable signature: (scenario, path) -> dict.
    Raises on transport/JSON errors; caller decides fallback behavior.
    """
    if provider != "anthropic":
        raise ValueError(f"Unsupported LLM provider: {provider}")

    def _binder(
        scenario: NormalizedScenario,
        path: AttackPath,
        plan_steps: list[StepPlan] | None = None,
    ) -> dict[str, Any]:
        user = _build_user_prompt(scenario, path, plan_steps=plan_steps)
        raw = _call_anthropic(_SYSTEM_PROMPT, user, api_key=api_key, model=model)
        return json.loads(_strip_fences(raw))

    return _binder


def _call_anthropic(system: str, user: str, api_key: str | None, model: str) -> str:
    """Thin wrapper so tests can patch this single function."""
    import anthropic  # local import — only needed when LLM is actually used

    client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
    resp = client.messages.create(
        model=model,
        max_tokens=8192,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    # Anthropic returns a list of content blocks; concatenate text blocks.
    return "".join(
        block.text for block in resp.content if getattr(block, "type", "") == "text"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)\s*[:/]")


def _extract_scheme(target_binding: TargetBinding) -> str:
    """Best-effort transport scheme extraction from a TargetBinding.

    Looks at endpoint values that commonly carry a `scheme:` prefix
    (bus_address, url, uri, address, ...) plus any dedicated scheme/transport
    keys. Falls back to scanning the protocol string for known scheme tokens.
    Returns lowercase scheme or "" if undetectable.
    """
    ep = target_binding.endpoint or {}
    # Direct scheme/transport keys
    for key in ("scheme", "transport", "transport_scheme"):
        v = ep.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
    # URL-like values with `scheme:` or `scheme://` prefix
    for key in ("bus_address", "url", "uri", "address", "endpoint", "connect_url"):
        v = ep.get(key)
        if isinstance(v, str):
            m = _SCHEME_RE.match(v.strip())
            if m:
                return m.group(1).lower()
    # Heuristic: protocol field often encodes "X over TCP/UDP/Unix/..."
    proto = (target_binding.protocol or "").lower()
    for tok in ("tcp", "udp", "unix", "tls", "http", "https", "ws", "wss",
                "serial", "can", "doip", "someip"):
        if re.search(rf"\b{tok}\b", proto):
            return tok
    return ""


def _endpoint_summary_for_research(target_binding: TargetBinding) -> str:
    """Build a short, content-rich summary of the endpoint for the LLM."""
    ep = target_binding.endpoint or {}
    pairs: list[str] = []
    # Surface a few common keys deterministically (no closed taxonomy).
    for key in ("bus_address", "url", "uri", "host", "port", "path"):
        v = ep.get(key)
        if v not in (None, ""):
            pairs.append(f"{key}={v}")
    if not pairs:
        # Fall back: dump up to 4 short scalar pairs.
        for k, v in list(ep.items())[:4]:
            if isinstance(v, (str, int, float, bool)):
                pairs.append(f"{k}={v}")
    return ", ".join(pairs) if pairs else "(no endpoint scalars)"


def _research_and_stamp_libraries(step_bindings: list[StepBinding]) -> None:
    """Group bindings by (protocol, scheme), call library_researcher once per
    group, stamp result onto every TargetBinding in the group.

    Failures (no API key, network error, empty result) leave
    library_candidates empty — step3b will then fall back to its existing
    soft preference and contract_verifier R14 (if enabled) becomes a no-op.
    """
    try:
        import library_researcher
    except Exception:
        return

    groups: dict[tuple[str, str], list[TargetBinding]] = {}
    summary_by_group: dict[tuple[str, str], str] = {}
    for sb in step_bindings:
        tb = sb.target_binding
        if tb is None or tb.binding_status != "bound":
            continue
        proto = (tb.protocol or "").strip().lower()
        scheme = _extract_scheme(tb)
        if not proto and not scheme:
            continue
        key = (proto, scheme)
        groups.setdefault(key, []).append(tb)
        summary_by_group.setdefault(key, _endpoint_summary_for_research(tb))

    for (proto, scheme), tbs in groups.items():
        candidates = library_researcher.research_libraries(
            protocol=proto,
            scheme=scheme,
            endpoint_summary=summary_by_group.get((proto, scheme), ""),
        )
        for tb in tbs:
            tb.library_candidates = candidates


def bind_controls_for_path(
    scenario: NormalizedScenario,
    path: AttackPath,
    binder: Binder | None = None,
    plan_steps: list[StepPlan] | None = None,
) -> PathControlBinding:
    if binder is None:
        return stub_bind(scenario, path, plan_steps=plan_steps)

    plan_by_id: dict[str, StepPlan] = {sp.step_id: sp for sp in (plan_steps or [])}

    try:
        # Try newest signature (with plan_steps for semantic intent); fall back
        # so external binders that pre-date this addition still work.
        try:
            raw = binder(scenario, path, plan_steps=plan_steps)
        except TypeError:
            raw = binder(scenario, path)
        if isinstance(raw, dict):
            raw_str = json.dumps(raw)
        else:
            raw_str = str(raw)
        step_bindings = _parse_llm_response(raw_str, path)
        # P6 Phase B: graft the execution spec onto each StepBinding's
        # target_binding from the corresponding step_plan. Done after parsing
        # so the LLM grounding (protocol/endpoint/target_ref) is independent
        # of the step2-decided spec (obligations/discovery/produces).
        step_by_id: dict[str, AttackStep] = {s.step_id: s for s in path.steps}
        for sb in step_bindings:
            if sb.target_binding is not None:
                _propagate_execution_spec(
                    sb.target_binding, plan_by_id.get(sb.step_id),
                )
                # Deterministic addressing injection: copy concrete primitive
                # fields from the merged connection.properties into endpoint
                # so step3b never has to guess host/port/path/bus_address/arb_id.
                step_obj = step_by_id.get(sb.step_id)
                if step_obj is not None:
                    _inject_connection_addressing(sb.target_binding, step_obj)
        # Path-level library research: ONE call per (protocol, scheme) pair,
        # result stamped onto every TargetBinding sharing that pair so all
        # step.py files in this path import from the same candidate pool.
        _research_and_stamp_libraries(step_bindings)
        unassigned = _compute_unassigned(path, step_bindings)
        return PathControlBinding(
            scenario_id=scenario.scenario_id,
            path_id=path.path_id,
            path_description=path.label,
            bindings=step_bindings,
            unassigned_controls=unassigned,
            llm_used=True,
            fallback_reason=None,
        )
    except Exception as e:  # noqa: BLE001 — fallback is the design
        fallback = stub_bind(scenario, path, plan_steps=plan_steps)
        fallback.fallback_reason = f"{type(e).__name__}: {e}"
        return fallback


def bind_controls_for_scenario(
    scenario: NormalizedScenario,
    binder: Binder | None = None,
    plan_by_path: dict[str, list[StepPlan]] | None = None,
) -> list[PathControlBinding]:
    plan_by_path = plan_by_path or {}
    return [
        bind_controls_for_path(
            scenario, p, binder=binder,
            plan_steps=plan_by_path.get(p.path_id),
        )
        for p in scenario.attack_paths
    ]


def _target_binding_to_dict(tb: TargetBinding | None) -> dict[str, Any] | None:
    if tb is None:
        return None
    return {
        "binding_status": tb.binding_status,
        "protocol": tb.protocol,
        "endpoint": dict(tb.endpoint),
        "target_ref": dict(tb.target_ref),
        "evidence_basis": list(tb.evidence_basis),
        "unresolved_fields": list(tb.unresolved_fields),
        "reason": tb.reason,
        "runtime_discovery_fields": list(tb.runtime_discovery_fields),
        "attack_actions": list(tb.attack_actions),
        "produces_for_next": list(tb.produces_for_next),
        "transport_constraints": list(tb.transport_constraints),
        "library_candidates": list(tb.library_candidates),
    }


def binding_to_dict(b: PathControlBinding) -> dict[str, Any]:
    """Serialize for JSON artifact output."""
    return {
        "scenario_id": b.scenario_id,
        "path_id": b.path_id,
        "path_description": b.path_description,
        "llm_used": b.llm_used,
        "fallback_reason": b.fallback_reason,
        "bindings": [
            {
                "step_id": sb.step_id,
                "assigned_controls": [c.as_dict() for c in sb.assigned_controls],
                "rationale": sb.rationale,
                "target_binding": _target_binding_to_dict(sb.target_binding),
            }
            for sb in b.bindings
        ],
        "unassigned_controls": [c.as_dict() for c in b.unassigned_controls],
    }
