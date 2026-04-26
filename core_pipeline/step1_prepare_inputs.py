"""
Step 1 — Input preparation.

Pure parser. No LLM. No API keys.
Loads threats.json + system_model.json, flattens threat_scenarios,
binds connections, resolves transport, and outputs NormalizedScenario list.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pipeline_types import (
    AttackPath,
    AttackStep,
    AttackTreeNode,
    ConnectionRef,
    NormalizedScenario,
    TreeNodeType,
)


# ---------------------------------------------------------------------------
# Transport resolver
# ---------------------------------------------------------------------------

# Alias normalization map (substring in protocol string -> canonical MVP name).
# Unmatched protocols are NOT errors: they flow through as-is (lowercased),
# so downstream generators still receive an identifier. The whitelist concept
# is abolished — transport "support" is a runtime property, not a Step 1
# decision.
_TRANSPORT_RESOLVE_TABLE: list[tuple[str, str]] = [
    ("d-bus",       "dbus_tcp"),
    ("dbus",        "dbus_tcp"),
    ("socketcand",  "socketcand_can"),
    ("can",         "socketcand_can"),
    ("doip",        "doip_tcp"),
    ("some/ip",     "someip_tcp"),
    ("someip",      "someip_tcp"),
]


def resolve_transport(protocol: str) -> str | None:
    """Resolve a raw protocol string to a canonical transport name.

    Z-behavior (whitelist abolished):
      - matched alias  -> canonical MVP name (e.g. "D-Bus over TCP" -> "dbus_tcp")
      - unmatched      -> lowercased+stripped raw string (e.g. "SPI" -> "spi")
      - empty / blank  -> None
    """
    lower = protocol.lower().strip()
    if not lower:
        return None
    for substr, name in _TRANSPORT_RESOLVE_TABLE:
        if substr in lower:
            return name
    return lower


# ---------------------------------------------------------------------------
# Connection index builder
# ---------------------------------------------------------------------------

def _build_connection_index(
    system_model: dict[str, Any],
) -> dict[str, ConnectionRef]:
    """Build CONN_ID -> ConnectionRef lookup from system_model connections."""
    index: dict[str, ConnectionRef] = {}
    for conn in system_model.get("connections", []):
        conn_id = conn["id"]
        protocol = conn.get("protocol", "")
        transport_name = resolve_transport(protocol)

        # Collect protocol-specific properties (everything beyond the
        # standard connection fields).
        standard_keys = {"id", "from", "to", "interface", "protocol",
                         "asset", "description"}
        properties = {k: v for k, v in conn.items() if k not in standard_keys}

        index[conn_id] = ConnectionRef(
            connection_id=conn_id,
            from_component=conn.get("from", ""),
            to_component=conn.get("to", ""),
            interface=conn.get("interface", ""),
            protocol=protocol,
            transport_name=transport_name,
            asset=conn.get("asset", ""),
            properties=properties,
        )
    return index


# ---------------------------------------------------------------------------
# Scenario flattener
# ---------------------------------------------------------------------------

# Fields that are mapped to dedicated NormalizedScenario attributes.
_SCENARIO_KNOWN_FIELDS = {
    "id", "asset_id", "asset_name", "threat_scenario",
    "attack_path", "attack_tree", "attack_steps", "selected_controls",
    "step_binding_hints", "precondition", "cybersecurity_goal",
}


def _flatten_scenarios(
    threats: dict[str, Any],
) -> list[dict[str, Any]]:
    """Flatten nested damage_scenarios -> threat_scenarios."""
    flat: list[dict[str, Any]] = []
    for ds in threats.get("damage_scenarios", []):
        for ts in ds.get("threat_scenarios", []):
            flat.append(ts)
    return flat


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class Step1ValidationError(Exception):
    """Raised when a truly required field is missing."""


def _is_new_schema(raw: dict[str, Any]) -> bool:
    """Detect Schneier-style schema (attack_steps + tree-structured attack_tree)."""
    if "attack_steps" not in raw:
        return False
    tree = raw.get("attack_tree", {})
    return isinstance(tree, dict) and tree.get("type") in ("OR", "AND", "LEAF")


def _is_v3_schema(raw: dict[str, Any]) -> bool:
    """Detect generalized-tree (v3) schema.

    Marks: attack_tree has {root, nodes:[...]} (schema_version 2.0 style)
    and scenario has first-class attack_paths[] with path_steps.
    """
    if "attack_steps" not in raw:
        return False
    tree = raw.get("attack_tree", {})
    if not isinstance(tree, dict):
        return False
    if "nodes" not in tree or "root" not in tree:
        return False
    paths = raw.get("attack_paths")
    return isinstance(paths, list) and len(paths) > 0


def _validate_raw_scenario(raw: dict[str, Any]) -> None:
    """Fail loudly for missing required data."""
    scenario_id = raw.get("id")
    if not scenario_id:
        raise Step1ValidationError("threat_scenario missing 'id'")

    if _is_new_schema(raw) or _is_v3_schema(raw):
        steps_dict = raw.get("attack_steps") or {}
        if not isinstance(steps_dict, dict) or not steps_dict:
            raise Step1ValidationError(
                f"Scenario {scenario_id}: 'attack_steps' must be a non-empty dict"
            )
        for sid, sdef in steps_dict.items():
            if not isinstance(sdef, dict) or not sdef.get("description"):
                raise Step1ValidationError(
                    f"Scenario {scenario_id}: attack_steps[{sid}] missing 'description'"
                )
        if _is_v3_schema(raw):
            for i, p in enumerate(raw["attack_paths"]):
                if not p.get("path_id") or not isinstance(p.get("path_steps"), list):
                    raise Step1ValidationError(
                        f"Scenario {scenario_id}: attack_paths[{i}] missing 'path_id' or 'path_steps'"
                    )
                unknown = [s for s in p["path_steps"] if s not in steps_dict]
                if unknown:
                    raise Step1ValidationError(
                        f"Scenario {scenario_id}: attack_paths[{i}] references unknown step ids {unknown}"
                    )
        return

    # Legacy schema validation
    attack_path = raw.get("attack_path")
    if not attack_path:
        raise Step1ValidationError(
            f"Scenario {scenario_id}: missing or empty 'attack_path'"
        )
    for i, step in enumerate(attack_path):
        if not (step.get("step_id") or step.get("threat_id")):
            raise Step1ValidationError(
                f"Scenario {scenario_id}: attack_path[{i}] missing 'step_id' or 'threat_id'"
            )
        if not step.get("description"):
            raise Step1ValidationError(
                f"Scenario {scenario_id}: attack_path[{i}] missing 'description'"
            )


# ---------------------------------------------------------------------------
# Schneier-style tree parsing + path enumeration
# ---------------------------------------------------------------------------

def _parse_tree(raw_node: dict[str, Any]) -> AttackTreeNode:
    """Recursively parse a Schneier-style attack tree node from raw JSON."""
    if "ref" in raw_node:
        # Leaf reference to attack_steps
        return AttackTreeNode(
            id=raw_node["ref"],
            type=TreeNodeType.LEAF,
            label="",
            step_ref=raw_node["ref"],
        )
    node_type = raw_node.get("type", "LEAF").upper()
    if node_type not in ("OR", "AND", "LEAF"):
        raise Step1ValidationError(f"unknown tree node type: {node_type}")
    children = [_parse_tree(c) for c in raw_node.get("children", [])]
    return AttackTreeNode(
        id=raw_node.get("id", ""),
        type=TreeNodeType(node_type),
        label=raw_node.get("label", ""),
        children=children,
        step_ref=raw_node.get("ref"),
    )


def _enumerate_paths(
    node: AttackTreeNode,
) -> list[tuple[str, str, list[str]]]:
    """Enumerate concrete execution paths via OR-traversal.

    Returns: list of (path_id, path_label, ordered_leaf_step_ids).

    Semantics:
      LEAF       → one path containing just that leaf's step_ref
      AND(c1..n) → cartesian: each child's paths combined sequentially
                   (most attack trees have AND children = LEAFs in order;
                    nested AND-of-OR also handled via cartesian product)
      OR(c1..n)  → union: each child's paths returned independently
    """
    if node.type == TreeNodeType.LEAF:
        return [(node.id or node.step_ref or "", node.label, [node.step_ref])]
    if node.type == TreeNodeType.OR:
        out: list[tuple[str, str, list[str]]] = []
        for child in node.children:
            out.extend(_enumerate_paths(child))
        # OR node label is the goal — children carry path labels.
        return out
    if node.type == TreeNodeType.AND:
        from itertools import product
        per_child = [_enumerate_paths(c) for c in node.children]
        if not per_child:
            return [(node.id, node.label, [])]
        out2: list[tuple[str, str, list[str]]] = []
        for combo in product(*per_child):
            chain: list[str] = []
            # Determine the path identity from the most-specific (non-LEAF)
            # combo element. A leaf-only combo element has pid == its leaf
            # step_id; a sub-path produced via OR/AND has a descriptive pid
            # distinct from the contained leaves. Prefer such descriptive
            # pids; fall back to this AND node's own id.
            chosen_id = node.id
            chosen_label = node.label
            for (pid, plabel, leaves) in combo:
                chain.extend(leaves)
                if pid and (not leaves or pid not in leaves):
                    chosen_id = pid
                    chosen_label = plabel
            out2.append((chosen_id, chosen_label, chain))
        return out2
    return []


# ---------------------------------------------------------------------------
# Generalized-tree (v3) parsing
# ---------------------------------------------------------------------------

def _parse_v3_tree(tree: dict[str, Any]) -> AttackTreeNode:
    """Parse a schema_version 2.0 generalized tree.

    Nodes carry node_type in {goal, logic, condition, step} and optionally
    a `logic` field ("AND"|"OR") for internal nodes. We map:
      step      -> LEAF with step_ref
      goal      -> AND/OR by its logic field (defaults to AND)
      logic     -> AND/OR by its logic field
      condition -> LEAF with step_ref=None (precondition marker; not executed)
    """
    root_id = tree["root"]
    nodes_by_id = {n["id"]: n for n in tree.get("nodes", [])}
    if root_id not in nodes_by_id:
        raise Step1ValidationError(
            f"attack_tree.root '{root_id}' not present in nodes"
        )

    def build(nid: str) -> AttackTreeNode:
        n = nodes_by_id[nid]
        nt = (n.get("node_type") or "").lower()
        if nt == "step":
            return AttackTreeNode(
                id=nid,
                type=TreeNodeType.LEAF,
                label=n.get("label", ""),
                step_ref=n.get("step_ref"),
            )
        if nt == "condition":
            return AttackTreeNode(
                id=nid,
                type=TreeNodeType.LEAF,
                label=n.get("label", ""),
                step_ref=None,
            )
        if nt in ("goal", "logic"):
            logic = (n.get("logic") or "AND").upper()
            if logic not in ("AND", "OR"):
                raise Step1ValidationError(
                    f"attack_tree node {nid}: unknown logic '{logic}'"
                )
            children = [build(cid) for cid in n.get("children", [])]
            return AttackTreeNode(
                id=nid,
                type=TreeNodeType(logic),
                label=n.get("label", ""),
                children=children,
            )
        raise Step1ValidationError(
            f"attack_tree node {nid}: unknown node_type '{nt}'"
        )

    return build(root_id)


# ---------------------------------------------------------------------------
# Core: build NormalizedScenario
# ---------------------------------------------------------------------------

def _build_normalized_scenario(
    raw: dict[str, Any],
    conn_index: dict[str, ConnectionRef],
) -> NormalizedScenario:
    """Convert a single raw threat_scenario dict to NormalizedScenario."""
    _validate_raw_scenario(raw)

    scenario_id = raw["id"]

    # ---------- Generalized-tree schema (v3) ----------
    if _is_v3_schema(raw):
        return _build_v3_scenario(raw, conn_index)

    # ---------- Schneier-style schema (new) ----------
    if _is_new_schema(raw):
        steps_dict_raw = raw["attack_steps"]
        # Build AttackStep objects keyed by id
        attack_steps_dict: dict[str, AttackStep] = {}
        for sid, sdef in steps_dict_raw.items():
            conn_id = sdef.get("binding")
            conn_ref: ConnectionRef | None = None
            if conn_id is not None:
                if conn_id not in conn_index:
                    raise Step1ValidationError(
                        f"Scenario {scenario_id}: step {sid} binds to connection "
                        f"'{conn_id}' which does not exist in system_model"
                    )
                conn_ref = conn_index[conn_id]
            attack_steps_dict[sid] = AttackStep(
                step_id=sid,
                description=sdef["description"],
                connection_id=conn_id,
                connection=conn_ref,
            )

        # Parse tree + enumerate execution paths.
        tree_root = _parse_tree(raw["attack_tree"])
        path_tuples = _enumerate_paths(tree_root)

        # Materialize AttackPath objects
        paths: list[AttackPath] = []
        for path_id, label, leaf_chain in path_tuples:
            unknown = [s for s in leaf_chain if s not in attack_steps_dict]
            if unknown:
                raise Step1ValidationError(
                    f"Scenario {scenario_id}: tree references unknown step ids {unknown}"
                )
            paths.append(AttackPath(
                path_id=path_id,
                label=label,
                steps=[attack_steps_dict[s] for s in leaf_chain],
                leaf_chain=list(leaf_chain),
            ))

        # Legacy attack_path = union of all unique steps in declaration order
        # (preserves back-compat for any code still reading this field).
        seen: set[str] = set()
        legacy_steps: list[AttackStep] = []
        for sid in steps_dict_raw.keys():
            if sid not in seen:
                legacy_steps.append(attack_steps_dict[sid])
                seen.add(sid)
        attack_steps_legacy = legacy_steps

        # Scenario-level transport from any concrete connection
        transport_name: str | None = None
        seen_transports: list[str | None] = []
        for st in attack_steps_legacy:
            if st.connection is not None:
                tn = st.connection.transport_name
                if tn not in seen_transports:
                    seen_transports.append(tn)
                if transport_name is None:
                    transport_name = tn

        all_transports = [{"transport_name": tn} for tn in seen_transports]
        metadata = {k: v for k, v in raw.items() if k not in _SCENARIO_KNOWN_FIELDS}
        if len(all_transports) > 1:
            metadata["all_transports"] = all_transports

        return NormalizedScenario(
            scenario_id=scenario_id,
            title=raw.get("threat_scenario", ""),
            asset_id=raw.get("asset_id", ""),
            asset_name=raw.get("asset_name", ""),
            attack_path=attack_steps_legacy,
            attack_tree=raw.get("attack_tree", {}),
            selected_controls=list(raw.get("selected_controls", [])),
            transport_name=transport_name,
            precondition=raw.get("precondition", ""),
            cybersecurity_goal=raw.get("cybersecurity_goal", ""),
            metadata=metadata,
            attack_steps=attack_steps_dict,
            attack_tree_root=tree_root,
            attack_paths=paths,
        )

    # ---------- Legacy schema (back-compat) ----------
    step_binding_hints = raw.get("step_binding_hints", {})

    attack_steps: list[AttackStep] = []
    for step_raw in raw["attack_path"]:
        sid = step_raw.get("step_id") or step_raw.get("threat_id")
        conn_id = step_binding_hints.get(sid)
        conn_ref: ConnectionRef | None = None
        if conn_id is not None:
            if conn_id not in conn_index:
                raise Step1ValidationError(
                    f"Scenario {scenario_id}: step {sid} references "
                    f"connection '{conn_id}' which does not exist in system_model"
                )
            conn_ref = conn_index[conn_id]
        attack_steps.append(AttackStep(
            step_id=sid,
            description=step_raw["description"],
            connection_id=conn_id,
            connection=conn_ref,
        ))

    # Collect all distinct transports across steps.
    seen_transports: list[str | None] = []
    for step in attack_steps:
        if step.connection is not None:
            tn = step.connection.transport_name
            if tn not in seen_transports:
                seen_transports.append(tn)

    # Scenario-level transport: use first resolved connection (primary).
    transport_name: str | None = None
    for step in attack_steps:
        if step.connection is not None:
            transport_name = step.connection.transport_name
            break

    # If multiple transports exist, record them in metadata.
    all_transports = [{"transport_name": tn} for tn in seen_transports]

    # Collect extra TARA fields into metadata.
    metadata = {k: v for k, v in raw.items() if k not in _SCENARIO_KNOWN_FIELDS}
    if len(all_transports) > 1:
        metadata["all_transports"] = all_transports

    return NormalizedScenario(
        scenario_id=scenario_id,
        title=raw.get("threat_scenario", ""),
        asset_id=raw.get("asset_id", ""),
        asset_name=raw.get("asset_name", ""),
        attack_path=attack_steps,
        attack_tree=raw.get("attack_tree", {}),
        selected_controls=list(raw.get("selected_controls", [])),
        transport_name=transport_name,
        precondition=raw.get("precondition", ""),
        cybersecurity_goal=raw.get("cybersecurity_goal", ""),
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# v3 scenario builder
# ---------------------------------------------------------------------------

def _build_v3_scenario(
    raw: dict[str, Any],
    conn_index: dict[str, ConnectionRef],
) -> NormalizedScenario:
    """Build NormalizedScenario from a v3 (generalized-tree) raw scenario.

    Path authority: attack_paths[] is the primary execution source.
    Tree is parsed for traceability but NOT enumerated into paths.
    """
    scenario_id = raw["id"]
    steps_dict_raw = raw["attack_steps"]

    # Resolve binding: v3 allows str or list[str] — take first when list.
    def _resolve_binding(sid: str, binding: Any) -> tuple[str | None, ConnectionRef | None]:
        if binding is None:
            return None, None
        if isinstance(binding, list):
            binding = binding[0] if binding else None
        if binding is None:
            return None, None
        if binding not in conn_index:
            raise Step1ValidationError(
                f"Scenario {scenario_id}: step {sid} binds to connection "
                f"'{binding}' which does not exist in system_model"
            )
        return binding, conn_index[binding]

    attack_steps_dict: dict[str, AttackStep] = {}
    for sid, sdef in steps_dict_raw.items():
        conn_id, conn_ref = _resolve_binding(sid, sdef.get("binding"))
        attack_steps_dict[sid] = AttackStep(
            step_id=sid,
            description=sdef["description"],
            connection_id=conn_id,
            connection=conn_ref,
        )

    # Tree parsed for traceability and (when attack_paths[] absent) enumeration.
    tree_root = _parse_v3_tree(raw["attack_tree"])

    # Path source: attack_paths[] is authoritative when present.
    # Fallback: enumerate AND/OR paths from the tree itself, filtering out
    # condition LEAFs (step_ref=None) so only executable steps remain.
    paths: list[AttackPath] = []
    raw_paths = raw.get("attack_paths") or []
    if raw_paths:
        for p in raw_paths:
            step_ids = list(p["path_steps"])
            paths.append(AttackPath(
                path_id=p["path_id"],
                label=p.get("path_description", ""),
                steps=[attack_steps_dict[s] for s in step_ids],
                leaf_chain=step_ids,
                cc_sfr=list(p.get("cc_sfr", [])),
                nist_sp_800_53=list(p.get("nist_sp_800_53", [])),
            ))
    else:
        # Auto-enumerate from tree. Path-level cc_sfr / nist_sp_800_53 are
        # unavailable in this mode; downstream Step 3-1 should degrade
        # gracefully (unassigned_controls remains empty).
        for (pid, plabel, leaf_chain) in _enumerate_paths(tree_root):
            # Drop condition LEAFs (step_ref=None) — preconditions, not steps.
            exec_chain = [sid for sid in leaf_chain if sid]
            # Only include steps present in attack_steps_dict.
            exec_chain = [sid for sid in exec_chain if sid in attack_steps_dict]
            if not exec_chain:
                continue
            paths.append(AttackPath(
                path_id=pid,
                label=plabel or "",
                steps=[attack_steps_dict[s] for s in exec_chain],
                leaf_chain=exec_chain,
                cc_sfr=[],
                nist_sp_800_53=[],
            ))

    # Legacy flat list: unique steps in declaration order of attack_steps dict.
    legacy_steps = [attack_steps_dict[sid] for sid in steps_dict_raw.keys()]

    # Scenario-level transport from first resolved connection.
    transport_name: str | None = None
    seen_transports: list[str | None] = []
    for st in legacy_steps:
        if st.connection is not None:
            tn = st.connection.transport_name
            if tn not in seen_transports:
                seen_transports.append(tn)
            if transport_name is None:
                transport_name = tn

    # Normalize precondition: v3 ships a list; Step 2/3 consume a string.
    pre_raw = raw.get("preconditions") or raw.get("precondition") or ""
    if isinstance(pre_raw, list):
        precondition = " ".join(str(x) for x in pre_raw)
    else:
        precondition = str(pre_raw)

    # Carry path-level requirements/TAF/CAL and step-level mapped_requirements
    # into metadata for downstream traceability (Step 3 prompts, Step 5 report).
    metadata = {k: v for k, v in raw.items() if k not in _SCENARIO_KNOWN_FIELDS}
    metadata["schema_version"] = "2.0"
    metadata["paths_meta"] = [
        {
            "path_id": p["path_id"],
            "path_description": p.get("path_description", ""),
            "cc_sfr": p.get("cc_sfr", []),
            "nist_sp_800_53": p.get("nist_sp_800_53", []),
            "TAF": p.get("TAF"),
            "CAL": p.get("CAL"),
            "impact": p.get("impact"),
        }
        for p in raw["attack_paths"]
    ]
    metadata["step_mapped_requirements"] = {
        sid: sdef.get("mapped_requirements", {})
        for sid, sdef in steps_dict_raw.items()
    }
    if len(seen_transports) > 1:
        metadata["all_transports"] = [
            {"transport_name": tn} for tn in seen_transports
        ]

    # selected_controls: flatten scenario-level selected_security_requirements.
    sel_req = raw.get("selected_security_requirements", {}) or {}
    selected_controls = list(sel_req.get("cc_sfr", [])) + list(sel_req.get("nist_sp_800_53", []))

    return NormalizedScenario(
        scenario_id=scenario_id,
        title=raw.get("title", "") or raw.get("threat_scenario", ""),
        asset_id=raw.get("asset_id", ""),
        asset_name=raw.get("asset_name", ""),
        attack_path=legacy_steps,
        attack_tree=raw.get("attack_tree", {}),
        selected_controls=selected_controls,
        transport_name=transport_name,
        precondition=precondition,
        cybersecurity_goal=raw.get("cybersecurity_goal", ""),
        metadata=metadata,
        attack_steps=attack_steps_dict,
        attack_tree_root=tree_root,
        attack_paths=paths,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_json(path: Path | str) -> dict[str, Any]:
    """Load a JSON file."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def prepare_inputs(
    threats_path: Path | str,
    system_model_path: Path | str,
    scenario_ids: list[str] | None = None,
) -> list[NormalizedScenario]:
    """Run Step 1: parse, flatten, bind, resolve, validate.

    Args:
        threats_path: path to threats.json
        system_model_path: path to system_model.json
        scenario_ids: optional filter — if provided, only these scenarios
                      are returned. None means all.

    Returns:
        List of NormalizedScenario, deterministic and ready for Step 2.
    """
    threats = load_json(threats_path)
    system_model = load_json(system_model_path)
    conn_index = _build_connection_index(system_model)

    flat = _flatten_scenarios(threats)
    results: list[NormalizedScenario] = []
    for raw in flat:
        ns = _build_normalized_scenario(raw, conn_index)
        if scenario_ids is None or ns.scenario_id in scenario_ids:
            results.append(ns)

    return results
