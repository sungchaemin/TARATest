"""
pipeline_v7 shared data model.

Protocol-agnostic type system for the TARA -> test-script pipeline.
All transport/protocol values are free strings resolved at runtime.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class StepStatus(enum.Enum):
    """Runtime execution status of a single attack step."""
    SUCCESS = "success"
    REJECTED = "rejected"
    ERROR = "error"
    TIMEOUT = "timeout"
    MIXED = "mixed"
    INCONCLUSIVE = "inconclusive"


class Verdict(enum.Enum):
    """Final security verdict for a step or scenario.

    BLOCKED is an intentional pause emitted when step3a could not ground a
    step's target_binding. It is NOT an execution failure (ERROR), NOT a test
    failure (FAIL), and must never be folded into either during aggregation.
    """
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED = "BLOCKED"


# ---------------------------------------------------------------------------
# Step 1 types
# ---------------------------------------------------------------------------

@dataclass
class ConnectionRef:
    """Resolved connection from system_model.json."""
    connection_id: str
    from_component: str
    to_component: str
    interface: str
    protocol: str               # raw string from system_model, never normalized
    transport_name: str | None   # internal pipeline name, e.g. "doip_tcp"
    asset: str
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackStep:
    """Single step in an attack path."""
    step_id: str
    description: str
    connection_id: str | None = None        # plain CONN id from step_binding_hints
    connection: ConnectionRef | None = None  # resolved later by Step 1


class TreeNodeType(enum.Enum):
    """Logical node type in a Schneier-style attack tree."""
    OR = "OR"      # any one child sufficient
    AND = "AND"    # all children required
    LEAF = "LEAF"  # references an atomic attack_step


@dataclass
class AttackTreeNode:
    """Hierarchical Schneier-style attack tree node.

    - LEAF nodes carry `step_ref` pointing into NormalizedScenario.attack_steps.
    - OR/AND nodes carry `children` (list of nested AttackTreeNode).
    """
    id: str
    type: TreeNodeType
    label: str = ""
    children: list["AttackTreeNode"] = field(default_factory=list)
    step_ref: str | None = None  # only set when type == LEAF


@dataclass
class AttackPath:
    """One concrete execution path enumerated from an OR-traversal of the
    attack tree. Each path is an ordered sequence of AttackSteps and is
    executed independently.
    """
    path_id: str                  # e.g. "PATH_ABS"
    label: str                    # human-readable
    steps: list[AttackStep]
    leaf_chain: list[str] = field(default_factory=list)  # ordered step_ids
    # Path-level security requirements (ISO/SAE 21434 derives requirements at
    # attack-path granularity). Populated from v3 attack_paths[].cc_sfr /
    # nist_sp_800_53. These are authoritative for Step 3 requirement binding.
    cc_sfr: list[str] = field(default_factory=list)
    nist_sp_800_53: list[str] = field(default_factory=list)


@dataclass
class NormalizedScenario:
    """Step 1 output — one per threat_scenario.

    New schema (Schneier tree) populates `attack_steps` (flat dict of step
    definitions) and `attack_tree_root` (hierarchical tree). Legacy schema
    populates `attack_path` (linear list). Both may be present during
    transition; `attack_paths` (the enumerated execution paths) is the
    authoritative input to Step 2.
    """
    scenario_id: str
    title: str
    asset_id: str
    asset_name: str
    attack_path: list[AttackStep]                       # legacy linear (kept for back-compat)
    attack_tree: dict[str, Any]                         # raw JSON (legacy)
    selected_controls: list[str]
    transport_name: str | None
    precondition: str
    cybersecurity_goal: str
    metadata: dict[str, Any] = field(default_factory=dict)
    # New tree-based fields:
    attack_steps: dict[str, AttackStep] = field(default_factory=dict)
    attack_tree_root: AttackTreeNode | None = None
    attack_paths: list[AttackPath] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Step 3-1 types — path-level control → step binding
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ControlRef:
    """A single security requirement identifier with its source framework.

    source_type is a free string but must be one of:
      "cc_sfr"           — Common Criteria Security Functional Requirement
      "nist_sp_800_53"   — NIST SP 800-53 control
    """
    source_type: str
    source_id: str

    def as_dict(self) -> dict[str, str]:
        return {"source_type": self.source_type, "source_id": self.source_id}


@dataclass
class TargetBinding:
    """Step3a output — concrete grounded target for one attack step.

    Protocol-agnostic by design: `protocol`, `endpoint`, `target_ref` are
    free-form (str / dict) so any protocol fits without a closed taxonomy.

    `binding_status`:
      - "bound"             → all required values grounded, codegen may proceed
      - "resolution_failed" → at least one required value cannot be grounded
                              from system_model / upstream artifacts; codegen
                              MUST be skipped, step inherits Verdict.BLOCKED.

    `unresolved_fields` is the authoritative non-empty signal of failure.
    `evidence_basis` records WHERE each grounded value came from (system_model
    path, upstream artifact name, RAG snippet id) so contract_verifier can
    cross-check against fabrication.
    """
    binding_status: str                                   # "bound" | "resolution_failed"
    protocol: str = ""                                    # free string, e.g. "dbus_tcp", "vlan_trunk"
    endpoint: dict[str, Any] = field(default_factory=dict)   # free shape (host/port/socket/...)
    target_ref: dict[str, Any] = field(default_factory=dict) # free shape (interface, method, can_id, ...)
    evidence_basis: list[dict[str, Any]] = field(default_factory=list)
    unresolved_fields: list[str] = field(default_factory=list)
    reason: str = ""                                      # short explanation, esp. for resolution_failed
    # ---- P6 Phase B: execution spec carried alongside the grounded target ----
    # These fields are propagated *deterministically* from the matching
    # StepPlan (no LLM involvement at step3a). They form the closed contract
    # that step3b's bounded-discovery prompt and the contract_verifier read.
    #   runtime_discovery_fields — whitelist of FIELD NAMES (not values) the
    #     generated script is permitted to discover at runtime. Anything
    #     outside this list is fabrication.
    #   attack_actions — concrete attacker behavior that translates the
    #     path's cc_sfr / nist_sp_800_53 controls into observable steps the
    #     script MUST implement (anchor for verifier rule "obligations
    #     ignored").
    #   produces_for_next — artifact names this step is committed to actually
    #     emitting in its return value (subset of step_plan.artifacts.outputs).
    runtime_discovery_fields: list[str] = field(default_factory=list)
    attack_actions: list[str] = field(default_factory=list)
    produces_for_next: list[str] = field(default_factory=list)
    # ---- Phase 2: executability self-assessment ----
    # Token-formatted constraints (KEY=VALUE) the codegen library MUST
    # satisfy. Open vocabulary (no closed taxonomy of keys at the type
    # level) but the KEY=VALUE shape is enforced by the step3a prompt and
    # trivially parseable by step3b / future verifier rules.
    # Initial 4-key vocabulary (provisional, prompt-side):
    #   MUST_SUPPORT_TRANSPORT=<value>     e.g. tcp | unix | udp | tls
    #   CARRIER_REQUIRED=<value>           e.g. can_bus | http | raw_ethernet
    #   REQUIRES_TLS_HANDSHAKE=true|false
    #   WIRE_FRAMING=<value>               e.g. sasl_anonymous | socketcand
    # Vocabulary will be revised after the first measurement round.
    transport_constraints: list[str] = field(default_factory=list)
    # ---- Library research output (per-path lock) ----
    # Populated by library_researcher.py at step3a time, ONCE per (protocol,
    # scheme) pair, and stamped onto every TargetBinding in the path so that
    # all generated step.py files in a given path import from the same
    # candidate pool. Contract: step3b MUST import only from these modules;
    # contract_verifier R14 enforces.
    # Each entry shape:
    #   {"name": "dbus_next",
    #    "import_module": "dbus_next",   # the importable module name
    #    "rationale": "...",             # why this lib fits protocol+transport
    #    "evidence_url": "https://...",  # docs URL the LLM cited
    #    "evidence_quote": "..."}        # short quote from those docs
    library_candidates: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class StepBinding:
    """Which controls from the parent path are verified at this step.

    `target_binding` is the new step3a grounding output. None means legacy
    callers haven't populated it; new code paths must always set it.
    `assigned_controls` remains traceability-only (per CLAUDE.md / project rules).
    """
    step_id: str
    assigned_controls: list[ControlRef] = field(default_factory=list)
    rationale: str = ""
    target_binding: TargetBinding | None = None


@dataclass
class StepScript:
    """Step 3-2 output — generated test script for a single step.

    `code` is a Python source string that MUST define a top-level function:
        def run_step(context: dict, artifacts: dict) -> dict
    whose return value matches the StepRunResult contract (see Step 4A/4B).

    `blocked` marks scripts emitted by the unresolved-gate (between step3a
    and step3b): step3a returned binding_status=resolution_failed for this
    step, OR a prior step in the same path was blocked and execution_blocked
    propagated. Blocked scripts contain only a marker stub — no attack code
    is generated. This is distinct from `fallback_used`, which means LLM
    codegen failed and we fell back to the stub generator. BLOCKED is an
    intentional pause from binding; FALLBACK is a generation error.
    """
    scenario_id: str
    path_id: str
    step_id: str
    code: str
    llm_used: bool = False
    fallback_used: bool = False
    fallback_reason: str | None = None
    blocked: bool = False
    blocked_reason: str | None = None
    blocked_unresolved_fields: list[str] = field(default_factory=list)
    # P5: contract-verifier outcome metadata.
    # `contract_retry_used` is True when the verifier flagged the first
    # generation and the LLM was re-invoked once with feedback.
    # `contract_violations` lists rule IDs (R3_return_shape, ...) that
    # SURVIVED the retry, i.e. are still present in the final emitted code.
    # Empty list = code passed verification (with or without retry).
    contract_retry_used: bool = False
    contract_violations: list[str] = field(default_factory=list)


@dataclass
class PathControlBinding:
    """Step 3-1 output — one per attack path.

    Distributes the path's ISO/SAE 21434-derived security requirements
    (path-level cc_sfr + nist_sp_800_53) across the steps of that path.
    """
    scenario_id: str
    path_id: str
    path_description: str
    bindings: list[StepBinding] = field(default_factory=list)
    unassigned_controls: list[ControlRef] = field(default_factory=list)
    llm_used: bool = False
    fallback_reason: str | None = None


# ---------------------------------------------------------------------------
# Step 2 types
# ---------------------------------------------------------------------------

@dataclass
class ArtifactRef:
    """A single named artifact flowing between steps."""
    name: str
    kind: str   # e.g. "step_result", "session", "previous_step_result"
    schema_hint: dict[str, Any] | None = None
    # schema_hint describes the expected value structure, e.g.:
    #   {"response_code": "int", "raw_message": "str"}
    # Upstream step writes a dict matching this shape; downstream step
    # reads fields by those keys. None means structure is unspecified.


@dataclass
class StepPlan:
    """Execution plan for a single attack step (Step 2 output).

    Artifact contract layer (methodology.md §3.2):
    - depends_on: which prior step_ids must have produced outputs before this
      step can run (derived from attack_tree edges).
    - artifacts: declared inputs/outputs with schema_hint, so downstream steps
      read artifacts by declared key rather than redeclaring in generated code.

    library_hint is a coarse role signal (NOT a library name) used by the
    Step 3-2 RAG retriever. Library choice belongs to the binding compiler;
    Step 2 must not pre-decide it.

    Open semantic fields (P4) — free-form strings, NOT closed enums. They
    capture the meaning of the step ("what is the attacker trying to achieve
    here, and what would success look like") so Step 3a can ground the
    target_binding around that intent and Step 3b can choose observations
    that bear on it. They are deliberately advisory: they MUST NOT be used
    as a closed taxonomy or as inputs to verdict logic.
    """
    step_id: str
    description: str
    transport_name: str | None
    connection: ConnectionRef | None      # None when unresolved / unsupported
    depends_on: list[str] = field(default_factory=list)
    artifacts: dict[str, list[ArtifactRef]] = field(default_factory=dict)
    library_hint: str = ""                # role signals (NOT library names)
    # ---- Open semantic intent fields (advisory, free-form) ----
    intent_label: str = ""                # short snake_case verb phrase
    attacker_goal: str = ""               # one sentence: what the attacker wants
    target_role: str = ""                 # the target's role in the system (free)
    success_signals: list[str] = field(default_factory=list)  # observable names
    failure_signals: list[str] = field(default_factory=list)  # observable names
    # ---- P6 Phase A: hard-block input ----
    # Names of artifacts this step requires from any prior step in the same
    # path. Consumed by step3b's hard-block gate: if any name here is not
    # found among prior_artifact_names, the step is BLOCKED before codegen.
    # Empty list (default) means "no upstream dependency"; the step can run
    # standalone. Free-form strings — no closed taxonomy.
    requires_from_prior: list[str] = field(default_factory=list)
    # ---- P6 Phase B: bounded-discovery + control-as-action plan ----
    # Field names this step is permitted to discover at RUNTIME (not in the
    # generated source). The codegen prompt uses this as a whitelist: the
    # script may probe/enumerate to fill these names, but must not invent
    # literal values for them. Names are free-form (e.g. "service_name",
    # "object_path", "method", "can_id", "session_token") and reflect what
    # the connection / step semantics naturally expose.
    runtime_discovery_fields: list[str] = field(default_factory=list)
    # Concrete attack ACTIONS this step must perform to exercise its assigned
    # controls. This is the LLM's free-form translation of "what would
    # actually test this control" (e.g. "attempt unauthorized read of
    # location data", "send malformed length field", "invoke privileged
    # method without prior auth"). The control TEXT itself stays anchored
    # in path.cc_sfr / path.nist_sp_800_53 — never fabricated. Only the
    # action description is generated; codegen treats this as a checklist
    # the script must implement.
    attack_actions: list[str] = field(default_factory=list)
    # Names of artifacts this step is expected to PRODUCE for downstream
    # steps. Semantic summary that complements artifacts["outputs"] (which
    # carries the structured ArtifactRef + schema_hint). Free-form names.
    produces_for_next: list[str] = field(default_factory=list)
    # ---- Upstream-failure handling policy (free-form, advisory) ----
    # How this step's generated script should behave when an artifact named
    # in requires_from_prior is missing or empty at runtime. Free-form
    # snake_case string consumed by step3b's codegen prompt; NOT a closed
    # enum and NOT a hard-block axis. Examples step2 may emit:
    #   ""                    — no policy declared; codegen falls back to
    #                           the prompt's general "record exception
    #                           observation, do not fabricate" behaviour.
    #   "abort"               — script records the missing artifact and
    #                           returns a partial-result observation
    #                           without attempting downstream actions.
    #   "proceed_with_empty"  — script substitutes an empty/default value
    #                           and continues, recording degradation in
    #                           observations for step4 review.
    #   "rediscover"          — script attempts a self-contained discovery
    #                           pass to derive the missing input from the
    #                           target before falling back to abort/empty.
    # The strings are advisory: codegen treats them as guidance for LLM
    # behaviour, not as a closed taxonomy verifier-side. Stays protocol-
    # agnostic and scenario-agnostic — no hardcoded "if D-Bus do X" logic.
    on_missing_input: str = ""


@dataclass
class ScenarioPlan:
    """Full execution plan for one scenario (Step 2 output).

    For new Schneier-tree schema, `paths` holds one PathPlan per enumerated
    OR-path. Each PathPlan carries its own ordered StepPlan sequence.
    For legacy schema, `steps` holds the linear sequence and `paths` is empty.
    """
    scenario_id: str
    transport_name: str | None
    steps: list[StepPlan] = field(default_factory=list)
    selected_controls: list[str] = field(default_factory=list)
    paths: list["PathPlan"] = field(default_factory=list)


@dataclass
class PathPlan:
    """One enumerated OR-path's execution plan (Step 2 sub-output).

    All steps in `steps` execute in order with shared CONTEXT (AND semantics).
    Different PathPlans within the same ScenarioPlan execute independently.
    """
    path_id: str
    label: str
    steps: list[StepPlan] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Step 3 types
# ---------------------------------------------------------------------------

@dataclass
class CodeBlock:
    """Generated code for a single attack step (Step 3 output)."""
    step_id: str
    code: str
    transport_name: str | None
    attack_pattern: str


# ---------------------------------------------------------------------------
# Step 4 types
# ---------------------------------------------------------------------------

@dataclass
class StepResult:
    """Runtime result written by generated code (contract)."""
    step_id: str
    status: StepStatus
    transport_name: str | None
    attack_pattern: str
    observations: list[dict[str, Any]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None


@dataclass
class StepVerdict:
    """Verdict for a single step (Step 4B output)."""
    step_id: str
    verdict: Verdict
    observable_class: str
    reason: str
    path_id: str = ""  # set when result came from a Schneier-tree path execution


@dataclass
class PathVerdict:
    """Aggregated verdict for one OR-path (AND of its step verdicts)."""
    path_id: str
    label: str
    verdict: Verdict
    reason: str
    step_verdicts: list[StepVerdict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Step 5 types
# ---------------------------------------------------------------------------

@dataclass
class ScenarioResult:
    """Final pipeline output for one scenario.

    For Schneier-tree scenarios, `path_verdicts` carries per-path aggregations
    and `verdict` is the scenario-level OR aggregation. `step_verdicts`
    flat-lists every step verdict across paths (each tagged with path_id).
    For legacy linear scenarios, `path_verdicts` is empty.
    """
    scenario_id: str
    verdict: Verdict
    reason: str
    step_verdicts: list[StepVerdict]
    selected_controls: list[str]
    script_path: str
    timestamp: str
    path_verdicts: list[PathVerdict] = field(default_factory=list)
