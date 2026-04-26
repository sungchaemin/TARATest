"""
LLM-backed step enricher for Step 2.

Scope: artifact contract enrichment only (methodology.md §3.2).
The LLM refines:
  - artifact_inputs / artifact_outputs (name, kind, schema_hint)
  - library_hint (canonical Python library names for RAG retrieval)

That is all. No role, attack_pattern_class, security_intent, oracle_expectation,
tool_hint, step_goal, execution_family — those fields were removed from StepPlan
because no downstream module consumes them.

Supported providers:
  - anthropic (Claude)
  - openai (GPT)

Usage:
  enricher = create_llm_enricher(provider="anthropic", api_key="sk-...")
  plan = decompose_scenario(scenario, enricher=enricher)

No-API-key fallback:
  enricher = create_llm_enricher()  # returns stub_enricher
"""

from __future__ import annotations

import json
import os
from typing import Any

from pipeline_types import (
    ArtifactRef,
    NormalizedScenario,
    StepPlan,
)


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are an automotive cybersecurity test planner.
You produce the EXECUTION PLAN for a single attack step. You do NOT generate
code, you do NOT pick a library, and you do NOT pick concrete protocol
values — those decisions belong to Step 3a (target_binding) and Step 3b
(binding compiler). What you DO decide is "what must be known going in,
what may be discovered at runtime, what must be done to test the assigned
controls, and what must be handed to the next step".

You are given:
- a step description from a TARA attack path
- scenario context (precondition, cybersecurity goal, transport, protocol)
- the step's position and dependencies in the attack tree
- prior_step_outputs: names already produced by upstream steps
- path_controls: the path-level security requirements (cc_sfr / NIST SP 800-53)
  that the WHOLE PATH must verify. NOT all of them apply to this single
  step — pick only the ones this step can plausibly exercise.
- reference material from grounded sources (K-CSMS procedures, ATM techniques,
  AUTO-ISAC threats, AAD attack records)

You must return a JSON object with exactly these fields:
{
  "library_hint":     array of COARSE ROLE TOKENS — see "library_hint" below.
                      NEVER a library or package name.
  "artifact_inputs":  array of {"name": str, "kind": str, "schema_hint": dict | null},
  "artifact_outputs": array of {"name": str, "kind": str, "schema_hint": dict | null},
  "intent_label":     short snake_case verb phrase (free-form, not from a list)
                      describing what the attacker is doing in this step
                      (e.g. "establish_session", "enumerate_services",
                      "exfiltrate_secret"). Empty string if unclear.
  "attacker_goal":    one short sentence: what the attacker wants OUT of this
                      step (the immediate gain, not the scenario goal).
                      Empty string if you cannot ground it.
  "target_role":      free-form phrase describing the target's role in the
                      system as it relates to this step (e.g.
                      "diagnostic_endpoint", "configuration_service",
                      "identity_provider"). Empty string if not derivable.
  "success_signals":  array of free-form snake_case observable names that
                      WOULD BE PRESENT if the attacker succeeded
                      (e.g. ["session_established", "auth_accepted"]).
                      Empty array if you cannot ground them.
  "failure_signals":  array of free-form snake_case observable names that
                      WOULD BE PRESENT if the defender blocked the step
                      (e.g. ["auth_rejected", "connection_refused",
                      "permission_denied"]). Empty array if not derivable.
  "requires_from_prior":      array of upstream artifact NAMES this step
                              cannot start without. ONLY list names that
                              already appear in prior_step_outputs. This is
                              a HARD-BLOCK signal: if a name is here and it
                              is not produced upstream, the step will be
                              BLOCKED before codegen. Use sparingly — only
                              for genuine prerequisites (an established
                              session, a discovered endpoint, ...). Empty
                              array if the step can run standalone.
  "runtime_discovery_fields": array of FIELD NAMES this step is allowed to
                              discover at runtime. The codegen step will
                              treat these as a whitelist: the script may
                              probe / enumerate / negotiate to fill them,
                              but must NOT invent literal values for them.
                              Examples: "service_name", "object_path",
                              "method", "can_id", "session_token". Empty
                              array if no runtime discovery is needed
                              (everything is fixed by the binding).
  "attack_actions":           array of CONCRETE ACTIONS this step must
                              perform to exercise the path_controls it can
                              test. Each action is one short imperative
                              sentence describing an observable behavior the
                              code must execute (e.g. "attempt unauthorized
                              read of GPS coordinates without prior auth",
                              "send method invocation with malformed
                              destination header", "verify that the response
                              indicates either ACCESS_DENIED or
                              METHOD_RETURN"). DO NOT paraphrase the control
                              text itself — the control TEXT stays anchored
                              in path_controls. attack_actions is the
                              attacker-side translation: "what would
                              actually test this control on the wire".
                              Empty array if no path_control applies to
                              this step.
  "produces_for_next":        array of artifact NAMES (snake_case, free-
                              form) this step is expected to PRODUCE for
                              downstream consumption. Should be a subset of
                              the names in artifact_outputs (semantic
                              summary). Empty array if this is the terminal
                              step or produces nothing reusable.
}

## Artifact naming consistency across steps (CRITICAL)

Rules for artifact_inputs:
- If this step has depends_on, its artifact_inputs MUST reference names
  that appear in prior_step_outputs of the dependency steps.
- Do NOT invent new input names. Reuse the exact names produced upstream.
- Example: if depends_on=["T1"] and prior_step_outputs["T1"]=["routing_response"],
  then artifact_inputs must include {"name": "routing_response", "kind": "..."}.
- Only declare inputs that the step TRULY needs to execute.
  Do not over-declare auxiliary information as inputs.

Rules for artifact_outputs:
- Choose descriptive, reusable names (snake_case, protocol-neutral).
- Names should reflect the data's purpose (e.g. routing_activation_response,
  session_control_response, service_inventory), not a step ID.
- These names WILL be referenced verbatim by downstream steps.

schema_hint is a small dict describing the expected value structure.
Example: {"response_code": "int", "raw_message": "str"}.
When an input name matches a prior step's output, reuse its schema_hint.
When writing a new output, declare its expected structure.

## kind + schema_hint shape discipline (REQUIRED — enforced downstream)

`kind` and `schema_hint` TOGETHER describe the exact runtime value the
producer step must emit. Step 3b generates code against this contract
and the contract verifier rejects violations.

- `kind` is one of: "list", "dict", "str", "int", "bool", plus semantic
  kinds like "session", "previous_step_result", "step_result".
- Declare `kind` HONESTLY for the value the step will actually produce:
  * If the step enumerates things (services, methods, CAN frames,
    observed responses, ...), declare `kind: "list"`. Never use "str"
    for a multi-item result.
  * If the step produces a single structured record, declare
    `kind: "dict"` and put the per-field types in schema_hint.
  * If the step produces a single scalar, use "str" / "int" / "bool".
- For `kind: "list"`, the schema_hint describes the shape of EACH
  ELEMENT. Example: for a service inventory →
    {"name": "service_inventory", "kind": "list",
     "schema_hint": {"service_name": "str",
                     "object_paths": "list[str]",
                     "interfaces": "list[str]"}}
  The downstream script MUST emit a list of dicts with those fields
  at those types — not a single dict, not a comma-joined string.
- Downstream anti-patterns your contract should make unambiguous:
  * collapsing list items into a delimited string ("a,b,c") — NEVER
    describe a collection with kind "str".
  * describing a per-item field as "list[str]" when it is really a
    single scalar (or vice versa).
  * leaving fields out of schema_hint that the step will actually
    emit — undeclared output keys are a contract violation, not a
    bonus.

## library_hint (role signals only — NOT library names)

- MUST be a JSON array of COARSE ROLE TOKENS, each describing the KIND of
  capability needed, NOT the package that provides it. Examples of valid
  tokens: "transport_required", "byte_assembly_required", "http_required",
  "session_required", "tls_required". Invent additional snake_case role
  tokens if needed.
- Do NOT emit "socket", "struct", "python-can", "requests", "dbus_next",
  "doipclient", or any other Python package name. Library choice is the
  binding compiler's job at Step 3-2; if you pre-decide it here, you
  silently lock the binding to one protocol family.
- An empty array is acceptable when no role can be grounded from the
  description and reference material.

## Open semantic intent fields

- intent_label / attacker_goal / target_role / success_signals /
  failure_signals are ADVISORY context for the downstream binding compiler.
  They describe MEANING, not concrete protocol values.
- Do NOT put a host, port, method name, opcode, message ID, payload, or
  any other concrete binding value in any of these fields.
- success_signals / failure_signals are observable NAMES (snake_case),
  not values and not assertions. The binding compiler decides what
  numeric/string evidence corresponds to each name at runtime.
- If you cannot ground a field from the inputs, return an empty string or
  empty array. Do NOT fabricate to satisfy the schema.

## Execution-plan fields (requires_from_prior, runtime_discovery_fields,
##                         attack_actions, produces_for_next)

These four fields are NEW and they are the heart of the plan. They tell
Step 3a what to ground concretely, and tell Step 3b what to execute and
what to discover.

- requires_from_prior is a HARD-BLOCK signal. List ONLY names already
  produced by upstream steps (look at prior_step_outputs). If you list a
  name that is not there, the step will be marked BLOCKED. So when in
  doubt, leave it out — runtime_discovery_fields is the right place for
  values the step can find on its own.

- runtime_discovery_fields is the whitelist of values the script may
  discover at runtime. Examples that should usually go here (NOT in
  requires_from_prior):
    "service_name", "object_path", "interface", "method", "can_id",
    "opcode", "did", "session_token", "negotiated_serial".
  Hard rule: these are FIELD NAMES, not values. If you find yourself
  writing "0x6789" or "org.bluez.Manager" here, you are in the wrong
  field — those are concrete bindings, which are Step 3a's job.

- attack_actions is where the path_controls are translated into observable
  attacker behavior. The control TEXT stays in path_controls (anchor); you
  produce the action sentences. Each sentence MUST be checkable in code by
  reading the script's observations or artifacts (e.g. "attempt
  unauthorized invocation and record whether response is METHOD_RETURN or
  ERROR" is checkable; "ensure the system is secure" is not). If no
  path_control applies to this step (e.g. a pure setup step), return [].

- produces_for_next is a NAMING contract. Names listed here MUST also
  appear in artifact_outputs (otherwise nothing is actually produced).
  Names listed here are what downstream steps' requires_from_prior may
  reference. Keep the names stable and snake_case.

## path_controls handling (the anchor)

- path_controls is the AUTHORITATIVE list of controls the path tests. You
  do NOT invent or rename them. You may IGNORE controls that this single
  step cannot exercise (e.g. a transport-integrity control on a discovery
  step that does no transport work). Translate only the applicable ones
  into attack_actions.
- NEVER copy the path_control IDs (e.g. "SC-7", "FIA_UAU.2") into
  attack_actions text. attack_actions is BEHAVIOR, not a control catalog
  reference. The traceability is held by Step 3a's assigned_controls
  binding, not by this field.

## Reference material handling

- K-CSMS: procedural guidance (how the test is performed) — informs
  intent_label, attacker_goal, success_signals, failure_signals.
- ATM / AUTO-ISAC / AAD: attack and execution context — informs artifact
  naming and intent_label.
- Do NOT use K-CSMS Result sections (they are not provided).
- Do NOT copy verbatim text from references.
- Do NOT generate Python code.
- Do NOT generate verdicts or pass/fail judgments.
- Do NOT change the step description text.
- Do NOT reorder steps.

Respond with ONLY the JSON object, no markdown fencing, no explanation.
"""


def _build_user_prompt(
    step: StepPlan,
    scenario: NormalizedScenario,
    step_index: int,
    total_steps: int,
    rag_context: str = "",
    prior_outputs: dict[str, list[Any]] | None = None,
    path_controls: list[dict[str, str]] | None = None,
) -> str:
    """Build the user prompt with scenario context, RAG, and prior outputs.

    path_controls is the AUTHORITATIVE anchor list for attack_actions
    generation. Each entry is {"source_type": "cc_sfr"|"nist_sp_800_53",
    "source_id": "..."}. The LLM picks which ones this step can plausibly
    test and translates them into attack_actions sentences.
    """
    conn_info: dict[str, Any] = {}
    if step.connection:
        conn_info = {
            "connection_id": step.connection.connection_id,
            "protocol": step.connection.protocol,
            "from": step.connection.from_component,
            "to": step.connection.to_component,
            "interface": step.connection.interface,
            "properties": step.connection.properties,
        }

    # Normalize prior_outputs for the prompt: expose only name lists.
    normalized_prior: dict[str, list[str]] = {}
    for sid, outs in (prior_outputs or {}).items():
        names: list[str] = []
        for o in outs:
            if isinstance(o, dict) and "name" in o:
                names.append(o["name"])
            elif isinstance(o, str):
                names.append(o)
        normalized_prior[sid] = names

    context = {
        "scenario_id": scenario.scenario_id,
        "scenario_title": scenario.title,
        "transport_name": step.transport_name,
        "precondition": scenario.precondition,
        "cybersecurity_goal": scenario.cybersecurity_goal,
        "step": {
            "step_id": step.step_id,
            "description": step.description,
            "index": step_index,
            "total_steps": total_steps,
            "depends_on": step.depends_on,
            "connection": conn_info,
        },
        "prior_step_outputs": normalized_prior,
        "path_controls": path_controls or [],
    }

    prompt = json.dumps(context, indent=2, ensure_ascii=False)

    if rag_context:
        prompt += "\n\n--- Reference Material ---\n" + rag_context

    return prompt


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def _parse_llm_response(raw_text: str) -> dict[str, Any]:
    """Parse LLM JSON response. Returns {} on any parse failure."""
    text = raw_text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


def _apply_llm_result(
    data: dict[str, Any],
    step: StepPlan,
    scenario: NormalizedScenario,
    step_index: int,
    total_steps: int,
) -> StepPlan:
    """Apply parsed LLM result to a StepPlan, with stub fallbacks."""
    from step2_decompose_attack import (
        _infer_artifacts,
        _infer_library_hint,
    )

    # library_hint: accept list or comma-separated string → canonical list string.
    # The prompt now requires ROLE TOKENS (transport_required, ...) rather
    # than library names; we don't enforce that here, the prompt does. We
    # still strip "import ..." and version pins defensively in case the
    # model slips and emits package strings.
    raw_lib = data.get("library_hint")
    if isinstance(raw_lib, list):
        library_hint = ", ".join(str(x) for x in raw_lib if x)
    elif isinstance(raw_lib, str) and raw_lib:
        parts = [p.strip().removeprefix("import ").split("==")[0].split(">=")[0].strip()
                 for p in raw_lib.replace(";", ",").split(",")]
        library_hint = ", ".join(p for p in parts if p)
    else:
        library_hint = _infer_library_hint(step.transport_name, step.description)

    # artifacts: prefer LLM when it supplied both; fall back to rule-based otherwise.
    llm_inputs = data.get("artifact_inputs")
    llm_outputs = data.get("artifact_outputs")
    if llm_inputs is not None and llm_outputs is not None:
        artifacts = {
            "inputs": [
                ArtifactRef(name=a["name"], kind=a["kind"],
                            schema_hint=a.get("schema_hint"))
                for a in llm_inputs
            ],
            "outputs": [
                ArtifactRef(name=a["name"], kind=a["kind"],
                            schema_hint=a.get("schema_hint"))
                for a in llm_outputs
            ],
        }
    else:
        artifacts = _infer_artifacts(step, step_index, total_steps)

    # Open semantic intent fields (P4). Free-form, advisory. Default to
    # empty when the LLM doesn't supply them — never synthesize, since
    # fabricating intent here defeats the whole point of the field.
    def _str_or_empty(key: str) -> str:
        v = data.get(key)
        return v.strip() if isinstance(v, str) else ""

    def _str_list(key: str) -> list[str]:
        v = data.get(key)
        if not isinstance(v, list):
            return []
        return [str(x).strip() for x in v if isinstance(x, (str, int)) and str(x).strip()]

    # P6 Phase B: execution-plan fields. requires_from_prior is a hard-block
    # signal — silently filter out any name the LLM listed that is NOT in
    # the upstream outputs we just declared via artifacts (defense in depth
    # against the LLM hallucinating a prior dependency that doesn't exist).
    upstream_names: set[str] = set()
    for ref in artifacts.get("inputs", []):
        if getattr(ref, "name", None):
            upstream_names.add(ref.name)
    declared_outputs: set[str] = set()
    for ref in artifacts.get("outputs", []):
        if getattr(ref, "name", None):
            declared_outputs.add(ref.name)

    requires_from_prior_raw = _str_list("requires_from_prior")
    requires_from_prior = [n for n in requires_from_prior_raw if n in upstream_names]
    runtime_discovery_fields = _str_list("runtime_discovery_fields")
    attack_actions = _str_list("attack_actions")
    produces_for_next_raw = _str_list("produces_for_next")
    # produces_for_next must be a subset of declared outputs (else nothing
    # is actually produced). Filter silently rather than fail — the prompt
    # already explains the rule; mismatch usually means the LLM dropped a
    # name from outputs but kept it in produces_for_next.
    produces_for_next = [n for n in produces_for_next_raw if n in declared_outputs]

    return StepPlan(
        step_id=step.step_id,
        description=step.description,
        transport_name=step.transport_name,
        connection=step.connection,
        depends_on=step.depends_on,
        artifacts=artifacts,
        library_hint=library_hint,
        intent_label=_str_or_empty("intent_label"),
        attacker_goal=_str_or_empty("attacker_goal"),
        target_role=_str_or_empty("target_role"),
        success_signals=_str_list("success_signals"),
        failure_signals=_str_list("failure_signals"),
        requires_from_prior=requires_from_prior,
        runtime_discovery_fields=runtime_discovery_fields,
        attack_actions=attack_actions,
        produces_for_next=produces_for_next,
    )


# ---------------------------------------------------------------------------
# Provider adapters
# ---------------------------------------------------------------------------

def _call_anthropic(
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
) -> str:
    """Call Anthropic Claude API (temperature=0 → deterministic)."""
    import anthropic

    # Cost tracking disabled in standalone version
    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=model,
        max_tokens=4096,
        temperature=0.0,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )
    try:
        cost_tracker.record(
            model=model,
            input_tokens=message.usage.input_tokens,
            output_tokens=message.usage.output_tokens,
            label="step2_enrich",
        )
    except Exception:
        pass
    return message.content[0].text


def _call_openai(
    api_key: str,
    model: str,
    system_prompt: str,
    user_prompt: str,
) -> str:
    """Call OpenAI API (temperature=0 → deterministic)."""
    import openai

    client = openai.OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        max_tokens=4096,
        temperature=0.0,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    )
    return response.choices[0].message.content


# ---------------------------------------------------------------------------
# LLM enricher factory
# ---------------------------------------------------------------------------

def create_llm_enricher(
    provider: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
    rag_dir: str | None = None,
) -> Any:
    """Create an enricher callable.

    Args:
        provider: "anthropic", "openai", or None for stub fallback.
        api_key: API key. If None, falls back to env vars or stub.
        model: Model name override.
        rag_dir: Path to RAG/STEP2 directory. None uses default.

    Returns:
        A callable matching the StepEnricher protocol.
    """
    # Resolve provider and API key.
    if provider is None:
        if api_key or os.environ.get("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif os.environ.get("OPENAI_API_KEY"):
            provider = "openai"
        else:
            from step2_decompose_attack import stub_enricher
            return stub_enricher

    if api_key is None:
        env_map = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
        }
        env_var = env_map.get(provider, "")
        api_key = os.environ.get(env_var, "")
        if not api_key:
            from step2_decompose_attack import stub_enricher
            return stub_enricher

    default_models = {
        "anthropic": "claude-sonnet-4-6",
        "openai": "gpt-4o",
    }
    if model is None:
        model = default_models.get(provider, "")

    call_fns = {
        "anthropic": _call_anthropic,
        "openai": _call_openai,
    }
    call_fn = call_fns.get(provider)
    if call_fn is None:
        from step2_decompose_attack import stub_enricher
        return stub_enricher

    from rag_retriever import RAGContext
    rag = RAGContext(rag_dir=rag_dir)

    def llm_enricher(
        step: StepPlan,
        scenario: NormalizedScenario,
        step_index: int,
        total_steps: int,
        prior_outputs: dict[str, list[Any]] | None = None,
        path_controls: list[dict[str, str]] | None = None,
    ) -> StepPlan:
        rag_text = rag.retrieve(step, scenario)
        user_prompt = _build_user_prompt(
            step, scenario, step_index, total_steps,
            rag_context=rag_text,
            prior_outputs=prior_outputs,
            path_controls=path_controls,
        )

        try:
            raw_response = call_fn(api_key, model, _SYSTEM_PROMPT, user_prompt)
        except Exception:
            from step2_decompose_attack import stub_enricher
            return stub_enricher(step, scenario, step_index, total_steps, prior_outputs)

        data = _parse_llm_response(raw_response)
        if not data:
            from step2_decompose_attack import stub_enricher
            return stub_enricher(step, scenario, step_index, total_steps, prior_outputs)

        return _apply_llm_result(data, step, scenario, step_index, total_steps)

    return llm_enricher
