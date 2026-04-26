"""
Step 2 — Artifact contract decomposition.

Converts Step 1 NormalizedScenario objects into ScenarioPlan objects.
This is execution planning only — no code generation, no verdict.

Per methodology.md §3.2, Step 2 is the **artifact contract layer**:
  - depends_on        : derived from attack_tree edges (so downstream steps
                        know which predecessors must have produced outputs)
  - artifacts         : declared inputs/outputs, each with a schema_hint,
                        so Step 3-2 generates code that reads prior-step
                        outputs by declared key rather than redeclaring
                        structure inside CONTEXT (§3.3 contract redeclaration).
  - library_hint      : LLM-provided Python library suggestion consumed by
                        the RAG retriever in Step 3-2 to narrow snippets.

No phase decomposition. No role / attack_pattern_class / security_intent /
oracle_expectation inference. Those enum fields were removed from StepPlan
because no downstream module (Step 3a, Step 3b, Step 4a, Step 4b v3,
Step 5 v3) consumes them.
"""

from __future__ import annotations

from typing import Any, Protocol

from pipeline_types import (
    ArtifactRef,
    NormalizedScenario,
    PathPlan,
    ScenarioPlan,
    StepPlan,
)


# ---------------------------------------------------------------------------
# Dependency extraction (rule-based)
# ---------------------------------------------------------------------------

def _extract_dependencies(scenario: NormalizedScenario) -> dict[str, list[str]]:
    """Derive step dependencies from attack_tree edges.

    Returns {step_id: [list of step_ids it depends on]}.
    Falls back to sequential ordering if attack_tree has no edges.
    """
    deps: dict[str, list[str]] = {
        step.step_id: [] for step in scenario.attack_path
    }

    edges = scenario.attack_tree.get("edges", [])
    if edges:
        for edge in edges:
            src = edge.get("from", "")
            dst = edge.get("to", "")
            if dst in deps and src:
                deps[dst].append(src)
    else:
        step_ids = [s.step_id for s in scenario.attack_path]
        for i in range(1, len(step_ids)):
            deps[step_ids[i]].append(step_ids[i - 1])

    return deps


# ---------------------------------------------------------------------------
# Artifact schema hint catalog
# ---------------------------------------------------------------------------
#
# Intentionally EMPTY (P4): the previous catalog hard-coded protocol-specific
# artifact names (routing_activation_response, dbus_service_inventory,
# session_control_response, ...). That is a closed-taxonomy violation — it
# pre-decides protocol identity at Step 2, which is the binding gate's job.
# Schema shape now comes from one of:
#   1. the LLM enricher (when it returns a schema_hint per artifact), or
#   2. an upstream step's output schema (chained through prior_outputs), or
#   3. None (the binding compiler in Step 3-2 derives shape from the
#      grounded target_binding, not from a Step 2 lookup).
# Keep the dict + lookup helper so call sites don't change shape — they
# just always miss now.
_ARTIFACT_SCHEMA_HINTS: dict[str, dict[str, str]] = {}


def _lookup_schema_hint(name: str) -> dict[str, str] | None:
    """Return schema hint for a well-known artifact name, or None.

    The catalog is empty by design (see _ARTIFACT_SCHEMA_HINTS comment).
    Retained as a stable seam in case a TRULY generic, protocol-neutral
    hint set is ever justified — but it must not reintroduce
    protocol-specific names like "routing_activation_response".
    """
    return _ARTIFACT_SCHEMA_HINTS.get(name)


# ---------------------------------------------------------------------------
# Artifact inference
# ---------------------------------------------------------------------------

def _infer_artifacts(
    step: StepPlan,
    step_index: int,
    total_steps: int,
) -> dict[str, list[ArtifactRef]]:
    """Infer structured input/output artifacts for one step.

    - Every depends_on predecessor contributes one input named
      "{prev}_result".
    - Every step produces one output named "{step_id}_result".
    - Steps whose description suggests a persistent session (connect,
      routing_activation, etc.) additionally produce "{step_id}_session".
    """
    inputs: list[ArtifactRef] = []
    outputs: list[ArtifactRef] = []

    for dep in step.depends_on:
        name = f"{dep}_result"
        inputs.append(ArtifactRef(
            name=name, kind="previous_step_result",
            schema_hint=_lookup_schema_hint(name),
        ))

    out_name = f"{step.step_id}_result"
    outputs.append(ArtifactRef(
        name=out_name, kind="step_result",
        schema_hint=_lookup_schema_hint(out_name),
    ))

    lower = step.description.lower()
    if any(kw in lower for kw in ["connect", "establish", "activate", "routing"]):
        sess_name = f"{step.step_id}_session"
        outputs.append(ArtifactRef(
            name=sess_name, kind="session",
            schema_hint=_lookup_schema_hint(sess_name),
        ))

    return {"inputs": inputs, "outputs": outputs}


# ---------------------------------------------------------------------------
# Library hint inference (transport-driven default for RAG retrieval)
# ---------------------------------------------------------------------------

def _infer_library_hint(transport_name: str | None, description: str) -> str:
    """Emit ROLE SIGNALS (NOT library names) for Step 3-2 RAG retrieval.

    Returns a comma-separated list of coarse role tokens such as
    "transport_required", "byte_assembly_required", "http_required".

    We deliberately do NOT map "can" → "python-can" or default to "socket"
    here. Library/transport choice is a binding decision that belongs to
    Step 3a (target_binding.protocol) and to the LLM acting as a binding
    compiler in Step 3-2. A Step 2 lookup that imposes a library is a
    closed-taxonomy violation: it secretly pre-decides protocol identity
    before the binding gate ever runs.
    """
    lower = description.lower()
    signals: list[str] = []

    if transport_name:
        signals.append("transport_required")

    if any(kw in lower for kw in ["0x", "hex", "payload", "byte",
                                   "arb_id", "arbitration"]):
        signals.append("byte_assembly_required")

    if any(kw in lower for kw in ["json", "http", "https", "rest"]):
        signals.append("http_required")

    return ", ".join(dict.fromkeys(signals))


# ---------------------------------------------------------------------------
# Rule-based skeleton builders
# ---------------------------------------------------------------------------

def _build_step_skeleton(
    attack_step,  # AttackStep
    scenario: NormalizedScenario,
    deps: list[str],
) -> StepPlan:
    """Build a rule-based StepPlan skeleton for one AttackStep.

    Fields left empty are filled by the enricher layer (stub or LLM).
    """
    conn = attack_step.connection
    return StepPlan(
        step_id=attack_step.step_id,
        description=attack_step.description,
        transport_name=conn.transport_name if conn else scenario.transport_name,
        connection=conn,
        depends_on=list(deps),
        artifacts={},
        library_hint="",
    )


def _build_skeleton(scenario: NormalizedScenario) -> ScenarioPlan:
    """Build a rule-based execution plan skeleton (legacy linear schema)."""
    deps = _extract_dependencies(scenario)

    steps: list[StepPlan] = []
    for attack_step in scenario.attack_path:
        steps.append(_build_step_skeleton(
            attack_step, scenario, deps.get(attack_step.step_id, []),
        ))

    return ScenarioPlan(
        scenario_id=scenario.scenario_id,
        transport_name=scenario.transport_name,
        steps=steps,
        selected_controls=list(scenario.selected_controls),
    )


# ---------------------------------------------------------------------------
# Enrichment interface
# ---------------------------------------------------------------------------

class StepEnricher(Protocol):
    """Interface for step enrichment (LLM or stub).

    prior_outputs: mapping of {prior_step_id: [{"name", "schema_hint"}, ...]}.
    The enricher MUST align input names with prior step outputs
    when the current step depends on them.

    path_controls: list of {"source_type", "source_id"} dicts naming the
    path-level security requirements (cc_sfr / NIST SP 800-53). The
    enricher uses this as the AUTHORITATIVE anchor when generating
    attack_actions: pick the controls this step can plausibly exercise and
    translate them into observable attacker behavior. None / empty means
    no path-level controls were declared.
    """

    def __call__(
        self,
        step: StepPlan,
        scenario: NormalizedScenario,
        step_index: int,
        total_steps: int,
        prior_outputs: dict[str, list[Any]] | None = None,
        path_controls: list[dict[str, str]] | None = None,
    ) -> StepPlan: ...


# ---------------------------------------------------------------------------
# Keyword-based stub enricher (no LLM, no API key)
# ---------------------------------------------------------------------------

def stub_enricher(
    step: StepPlan,
    scenario: NormalizedScenario,
    step_index: int,
    total_steps: int,
    prior_outputs: dict[str, list[Any]] | None = None,
    path_controls: list[dict[str, str]] | None = None,
) -> StepPlan:
    """Keyword-based stub enricher. No LLM, no API key.

    Fills in artifacts and library_hint from step description + transport.

    The open semantic intent fields (intent_label, attacker_goal,
    target_role, success_signals, failure_signals) are LEFT EMPTY here on
    purpose: synthesizing them from the bare step description without
    LLM/RAG would be fabrication of meaning the operator never gave us.
    The downstream binding compiler treats empty values as "no advisory
    hint" — it must still ground every concrete choice in target_binding
    and artifacts.
    """
    artifacts = _infer_artifacts(step, step_index, total_steps)
    library_hint = _infer_library_hint(step.transport_name, step.description)

    return StepPlan(
        step_id=step.step_id,
        description=step.description,
        transport_name=step.transport_name,
        connection=step.connection,
        depends_on=step.depends_on,
        artifacts=artifacts,
        library_hint=library_hint,
        intent_label="",
        attacker_goal="",
        target_role="",
        success_signals=[],
        failure_signals=[],
    )


# ---------------------------------------------------------------------------
# Enrichment loop
# ---------------------------------------------------------------------------

def _enrich_chain(
    steps_seq: list[StepPlan],
    scenario: NormalizedScenario,
    enricher: StepEnricher,
    path_controls: list[dict[str, str]] | None = None,
) -> list[StepPlan]:
    """Run the enrichment loop on an ordered sequence of StepPlans, threading
    prior_outputs so each step aligns its input schemas with predecessors.
    path_controls is forwarded unchanged to every step in the sequence so the
    enricher can translate path-level cc_sfr / nist_sp_800_53 into per-step
    attack_actions. Returns the enriched list (same length, same order)."""
    enriched_steps: list[StepPlan] = []
    prior_outputs: dict[str, list[dict[str, Any]]] = {}
    total = len(steps_seq)
    for i, step in enumerate(steps_seq):
        try:
            enriched = enricher(
                step, scenario, i, total, prior_outputs,
                path_controls=path_controls,
            )
        except TypeError:
            # Backward-compat: enricher predates path_controls kwarg.
            enriched = enricher(step, scenario, i, total, prior_outputs)

        # PRIORITY for input schemas: catalog > prior output's schema > LLM hint.
        updated_inputs: list[ArtifactRef] = []
        for a in enriched.artifacts.get("inputs", []):
            catalog_hint = _lookup_schema_hint(a.name)
            if catalog_hint is not None:
                hint = catalog_hint
            else:
                hint = a.schema_hint
                for prior_list in prior_outputs.values():
                    for prior in prior_list:
                        if prior["name"] == a.name:
                            ph = prior.get("schema_hint")
                            if ph is not None:
                                hint = ph
                            break
            updated_inputs.append(ArtifactRef(
                name=a.name, kind=a.kind, schema_hint=hint,
            ))

        updated_outputs: list[ArtifactRef] = []
        for a in enriched.artifacts.get("outputs", []):
            catalog_hint = _lookup_schema_hint(a.name)
            hint = catalog_hint if catalog_hint is not None else a.schema_hint
            updated_outputs.append(ArtifactRef(
                name=a.name, kind=a.kind, schema_hint=hint,
            ))

        enriched.artifacts = {"inputs": updated_inputs, "outputs": updated_outputs}
        enriched_steps.append(enriched)

        prior_outputs[enriched.step_id] = [
            {"name": a.name, "schema_hint": a.schema_hint}
            for a in enriched.artifacts.get("outputs", [])
        ]
    return enriched_steps


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def decompose_scenario(
    scenario: NormalizedScenario,
    enricher: StepEnricher | None = None,
) -> ScenarioPlan:
    """Convert a NormalizedScenario into a ScenarioPlan.

    For new Schneier-tree schema (scenario.attack_paths populated), one
    PathPlan per enumerated path is produced. Each PathPlan is enriched
    with a per-step cache so repeated step_ids across paths enrich once.
    For legacy schema, a single linear ScenarioPlan.steps is produced.
    """
    if enricher is None:
        enricher = stub_enricher

    # ---------- New schema: per-path ----------
    if scenario.attack_paths:
        import copy as _copy

        path_plans: list[PathPlan] = []
        all_unique_steps: dict[str, StepPlan] = {}
        enrichment_cache: dict[str, StepPlan] = {}

        for path in scenario.attack_paths:
            # Path-level controls are the AUTHORITATIVE anchor for translating
            # security requirements into per-step attack_actions. They never
            # leave step2 — only their names flow through, no fabricated text.
            path_controls: list[dict[str, str]] = (
                [{"source_type": "cc_sfr", "source_id": c} for c in path.cc_sfr]
                + [{"source_type": "nist_sp_800_53", "source_id": c}
                   for c in path.nist_sp_800_53]
            )

            seq_for_path: list[StepPlan] = []
            steps_to_enrich: list[StepPlan] = []
            indices_needing_enrich: list[int] = []
            for idx, atk_step in enumerate(path.steps):
                deps = [path.steps[idx - 1].step_id] if idx > 0 else []
                if atk_step.step_id in enrichment_cache:
                    cached = _copy.deepcopy(enrichment_cache[atk_step.step_id])
                    cached.depends_on = list(deps)
                    seq_for_path.append(cached)
                else:
                    skel = _build_step_skeleton(atk_step, scenario, deps)
                    seq_for_path.append(skel)
                    steps_to_enrich.append(skel)
                    indices_needing_enrich.append(idx)
            if steps_to_enrich:
                enriched_subset = _enrich_chain(
                    steps_to_enrich, scenario, enricher,
                    path_controls=path_controls,
                )
                for j, idx in enumerate(indices_needing_enrich):
                    seq_for_path[idx] = enriched_subset[j]
                    enrichment_cache[seq_for_path[idx].step_id] = enriched_subset[j]

            path_plans.append(PathPlan(
                path_id=path.path_id,
                label=path.label,
                steps=seq_for_path,
            ))
            for sp in seq_for_path:
                if sp.step_id not in all_unique_steps:
                    all_unique_steps[sp.step_id] = sp

        return ScenarioPlan(
            scenario_id=scenario.scenario_id,
            transport_name=scenario.transport_name,
            steps=list(all_unique_steps.values()),
            selected_controls=list(scenario.selected_controls),
            paths=path_plans,
        )

    # ---------- Legacy schema: linear ----------
    plan = _build_skeleton(scenario)
    plan.steps = _enrich_chain(plan.steps, scenario, enricher)
    return plan


def decompose_scenarios(
    scenarios: list[NormalizedScenario],
    enricher: StepEnricher | None = None,
) -> list[ScenarioPlan]:
    """Batch version of decompose_scenario."""
    return [decompose_scenario(s, enricher) for s in scenarios]


def create_enricher(
    provider: str | None = None,
    api_key: str | None = None,
    model: str | None = None,
) -> StepEnricher:
    """Create an enricher — delegates to llm_enricher.create_llm_enricher.

    Args:
        provider: "anthropic", "openai", or None (auto-detect / stub fallback).
        api_key: API key. None → env var → stub.
        model: Model name override.

    Returns:
        A callable matching the StepEnricher protocol.
    """
    from llm_enricher import create_llm_enricher
    return create_llm_enricher(provider=provider, api_key=api_key, model=model)
