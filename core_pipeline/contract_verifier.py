"""
Static contract verification for v4 step scripts.

Inputs:
  - the LLM-generated Python source code for one step
  - the step's StepPlan (carries declared artifact_inputs / artifact_outputs)
  - optionally the step's TargetBinding (for fabrication-literal whitelisting)

Output:
  - list[ContractViolation]: each is a structured rule failure with a short,
    LLM-friendly `feedback` string. An empty list means the code conforms.

Rules (v4 contract, see step3b prompt):
  R1 parse              — code parses as Python.
  R2 signature          — `def run_step(context, artifacts) -> dict` exists.
  R3 return_shape       — at least one explicit `return {...}` whose dict
                          literal has top-level keys ⊆ {observations,
                          artifacts, notes} AND contains "observations"
                          + "artifacts". Extra keys (e.g. step_id, status,
                          assertion_results, expected_type, kind) are
                          forbidden — the harness injects them.
  R4 artifact_input_read  — every declared artifact_inputs[*].name MUST
                            appear in an `artifacts["<name>"]` or
                            `artifacts.get("<name>", ...)` AST access.
  R5 artifact_output_write — when the returned dict literal's "artifacts"
                             value is itself a dict literal, every declared
                             artifact_outputs[*].name MUST appear as a key.
                             If the "artifacts" value is opaque (variable,
                             call, comprehension), this rule is SKIPPED
                             (we cannot prove the contract is broken).
  R6 forbidden_fabricated_literals — explicit literals listed as ABSOLUTE
                                     PROHIBITIONS in the step3b prompt
                                     (127.0.0.1, localhost, /tmp/,
                                     0xDEADBEEF, 0xCABEEEF, well-known
                                     diag/automotive ports, etc.) trigger
                                     a violation when they appear as bare
                                     literals AND are not justified by a
                                     matching value in TargetBinding.
  R7 attack_actions_unimplemented — when target_binding.attack_actions is
                                    non-empty (step2 translated path
                                    cc_sfr / nist_sp_800_53 controls into
                                    N concrete attacker behaviors), the
                                    script body MUST emit at least N
                                    distinct observation entries. Far
                                    fewer = the script silently dropped
                                    obligations.
  R9 produces_for_next_missing — when target_binding.produces_for_next
                                 declares names this step is committed to
                                 actually producing, every name MUST appear
                                 as a key in the returned artifacts dict
                                 literal. Subset of R5 but stricter: R5
                                 checks against artifact_outputs (the full
                                 contract); R9 checks against the smaller
                                 produces_for_next sub-list (the chaining
                                 commitment).
  R10 signature_mismatch — for every Call whose callee can be statically
                           resolved through the module's import map (bare
                           Name from `from X import Y`, or
                           `Alias.attr` where Alias was imported), import
                           the underlying module and inspect.signature() the
                           callable. Every kwarg used at the call site MUST
                           exist as a parameter in that signature (or the
                           signature must accept **kwargs). Catches LLM
                           hallucinated library APIs (e.g.
                           open_dbus_connection(auth_types=...) when
                           jeepney has no such kwarg). Skips silently on
                           any import / introspection failure — false
                           negatives are cheaper than false positives.
  R10 import_name_missing — for every top-level `from <module> import <name>`
                            where <module> is importable, <name> MUST be
                            an attribute of the imported module
                            (hasattr-checked, so module __getattr__ /
                            lazy attrs count). Catches LLM hallucinated
                            symbol names (e.g. AuthAnnounceOnly when the
                            real export is AuthAnnonymous), which slip
                            past the kwarg check because the failure is
                            at import time, not call time. Feedback
                            includes difflib's closest-match candidates
                            from the module's actual exports so the LLM
                            can self-correct without re-introspection.
  R11 arity_mismatch     — every Call's positional + required-arg count must
                            match the resolved callable's signature, validated
                            by simulating inspect.Signature.bind() with
                            placeholder values (kwargs that R10 already
                            flagged are dropped to avoid double-fire). Catches
                            positional arity errors (struct.pack format vs
                            args), missing-required positional / keyword-only,
                            and duplicate-argument cases the kwarg-only R10
                            check cannot see. v1 skips silently when:
                              * callee is an unbound-method-on-class pattern
                                (first param named self/cls — Cls.method() vs
                                bound inst.method() ambiguity),
                              * signature has *args (any positional count
                                valid),
                              * call site uses *args / **kwargs unpack (arity
                                unpredictable),
                              * inspect.signature() raises (C extensions).
                            Out of v1 scope (deferred): return-value unpack
                            arity (e.g. `data, _ = msg.serialise()` when
                            serialise returns just bytes) — needs return-type
                            data flow R11 v1 deliberately doesn't carry.

The verifier is intentionally conservative: false negatives (missing a real
violation) are cheaper than false positives (rejecting a legitimate script
and burning a retry). When a rule cannot be statically decided, it skips
rather than flags.

R8 (runtime_discovery_fields whitelist) is intentionally NOT implemented:
deciding statically whether a literal "is a discovered value for field X"
would require protocol semantics the verifier deliberately doesn't carry
(open-protocol principle). The prompt enforces it; runtime evidence will
catch leaks step4 won't observe values for fields outside the whitelist.
"""

from __future__ import annotations

import ast
import importlib
import inspect as _inspect
from dataclasses import dataclass
from typing import Any, Iterable

from pipeline_types import StepPlan, TargetBinding


@dataclass
class ContractViolation:
    rule: str
    detail: str

    def feedback(self) -> str:
        return f"[{self.rule}] {self.detail}"


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _find_run_step(tree: ast.Module) -> ast.FunctionDef | None:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "run_step":
            return node
    return None


def _literal_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _subscript_key(slc: ast.AST) -> str | None:
    if isinstance(slc, ast.Index):  # type: ignore[attr-defined]
        slc = slc.value  # type: ignore[attr-defined]
    return _literal_str(slc)


def _iter_artifact_reads(fn: ast.FunctionDef) -> Iterable[str]:
    """Yield string keys read from `artifacts` via:
        artifacts["k"]
        artifacts.get("k", ...)
        artifacts.get("k")
        artifacts.pop("k", ...)
    Dynamic keys are not yielded.
    """
    for n in ast.walk(fn):
        if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name) \
                and n.value.id == "artifacts":
            k = _subscript_key(n.slice)
            if k:
                yield k
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                and isinstance(n.func.value, ast.Name) \
                and n.func.value.id == "artifacts" \
                and n.func.attr in ("get", "pop", "setdefault") \
                and n.args:
            k = _literal_str(n.args[0])
            if k:
                yield k


def _iter_returned_dicts(fn: ast.FunctionDef) -> Iterable[ast.Dict]:
    """Yield every `return {...}` dict literal in run_step."""
    for n in ast.walk(fn):
        if isinstance(n, ast.Return) and isinstance(n.value, ast.Dict):
            yield n.value


def _dict_literal_str_keys(d: ast.Dict) -> set[str]:
    keys: set[str] = set()
    for k in d.keys:
        if k is not None:
            s = _literal_str(k)
            if s:
                keys.add(s)
    return keys


def _dict_literal_value_for(d: ast.Dict, key: str) -> ast.AST | None:
    for k, v in zip(d.keys, d.values):
        if k is not None and _literal_str(k) == key:
            return v
    return None


def _count_observation_emissions(fn: ast.FunctionDef) -> int:
    """Count observation entries emitted by run_step.

    Counts:
      - `observations.append({...})` and `observations.extend([{...}, ...])`
      - dict entries inside `observations = [{...}, {...}, ...]` literal
        assignments (typical pattern: build the list once, return it)
      - dict entries directly inside the `observations` value of a
        returned dict literal (when the script returns
        `return {"observations": [{...}, {...}], "artifacts": ...}`)
    Never double-counts: each entry is bound to its source location.
    """
    count = 0
    seen: set[int] = set()  # ast node ids already counted

    for n in ast.walk(fn):
        # Pattern A: `observations.append({...})` / `.extend([...])`
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                and isinstance(n.func.value, ast.Name) \
                and n.func.value.id == "observations":
            if n.func.attr == "append" and n.args:
                count += 1
                seen.add(id(n.args[0]))
            elif n.func.attr == "extend" and n.args \
                    and isinstance(n.args[0], (ast.List, ast.Tuple)):
                for elt in n.args[0].elts:
                    count += 1
                    seen.add(id(elt))

        # Pattern B: `observations = [{...}, {...}]` assignment
        elif isinstance(n, ast.Assign):
            for tgt in n.targets:
                if isinstance(tgt, ast.Name) and tgt.id == "observations" \
                        and isinstance(n.value, (ast.List, ast.Tuple)):
                    for elt in n.value.elts:
                        if id(elt) not in seen:
                            count += 1
                            seen.add(id(elt))

        # Pattern C: dict entries inside returned `{"observations": [...]}`
        elif isinstance(n, ast.Return) and isinstance(n.value, ast.Dict):
            obs_val = _dict_literal_value_for(n.value, "observations")
            if isinstance(obs_val, (ast.List, ast.Tuple)):
                for elt in obs_val.elts:
                    if id(elt) not in seen:
                        count += 1
                        seen.add(id(elt))

    return count


# ---------------------------------------------------------------------------
# Forbidden literal set (ABSOLUTE PROHIBITIONS in the step3b prompt).
# ---------------------------------------------------------------------------
# String tokens that, if they appear as bare literals in the generated code
# AND are not present in TargetBinding's endpoint/target_ref/protocol, are
# treated as fabricated defaults. Substring match (case-insensitive) — these
# tokens are characteristic enough that incidental appearance in a
# legitimate string is rare.
_FORBIDDEN_STRING_TOKENS: tuple[str, ...] = (
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "/tmp/",
    "vcan0",
)

# Integer literals that are well-known protocol-default ports / opcodes the
# binding compiler must NOT use as a fallback when the binding is missing.
# (LLMs reach for these exact constants when they don't know the real value.)
_FORBIDDEN_INT_LITERALS: frozenset[int] = frozenset({
    13400,        # ISO 13400 / DoIP default
    30490,        # SOME/IP default
    6800,         # socketcand default
    0xDEADBEEF,
    0xCAFEBABE,
    0xCABEEEF,
})


def _binding_value_corpus(target_binding: TargetBinding | None) -> tuple[set[str], set[int]]:
    """Flatten every literal value reachable through TargetBinding into
    (set of strings, set of ints). Used to whitelist literals that the
    binding actually carries — those are LEGITIMATELY hardcoded."""
    strs: set[str] = set()
    ints: set[int] = set()
    if target_binding is None:
        return strs, ints
    if target_binding.protocol:
        strs.add(target_binding.protocol)

    def _walk(value: Any) -> None:
        if isinstance(value, str):
            strs.add(value)
        elif isinstance(value, bool):
            return  # avoid polluting int set with True/False
        elif isinstance(value, int):
            ints.add(value)
        elif isinstance(value, dict):
            for v in value.values():
                _walk(v)
        elif isinstance(value, (list, tuple)):
            for v in value:
                _walk(v)

    _walk(target_binding.endpoint)
    _walk(target_binding.target_ref)
    return strs, ints


# ---------------------------------------------------------------------------
# R10 helpers — static signature inspection for kwarg existence.
# ---------------------------------------------------------------------------
# Approach (deliberately conservative, no hardcoded library knowledge):
#   1. Walk module top-level Import / ImportFrom to build {local_alias: FQN}.
#   2. For every Call, resolve the callee through that map IF the callee is
#      either a bare Name or `Alias.attr` (where Alias is in the map).
#      Anything else (instance methods, attribute chains, dynamic) → skip.
#   3. importlib.import_module() the longest importable prefix of the FQN,
#      then getattr() down the rest. Wrap every step in try/except — any
#      failure means we cannot statically prove a violation, so we skip.
#   4. inspect.signature() the resolved object. If it accepts **kwargs
#      (VAR_KEYWORD), accept any kwarg. Otherwise, every keyword.arg in the
#      Call must appear in signature.parameters.
#
# False negatives (a real bug we can't see — instance methods, decorators
# that hide the signature, C-extension callables) are accepted by design.
# False positives (rejecting valid code) would burn a retry — so we
# err very far on the side of skipping.


def _build_import_map(tree: ast.Module) -> dict[str, str]:
    """alias_name -> fully-qualified import path.

    Examples:
      `from dbus_next.aio import MessageBus`           → 'MessageBus' → 'dbus_next.aio.MessageBus'
      `from jeepney.io.blocking import open_dbus_connection as odc`
                                                        → 'odc' → 'jeepney.io.blocking.open_dbus_connection'
      `import socket`                                   → 'socket' → 'socket'
      `import xml.etree.ElementTree as ET`              → 'ET' → 'xml.etree.ElementTree'
    Relative imports and `import *` are skipped.
    """
    imap: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            if (node.level or 0) > 0:
                continue
            mod = node.module or ""
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                imap[local] = f"{mod}.{alias.name}" if mod else alias.name
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    imap[alias.asname] = alias.name
                else:
                    # `import a.b.c` binds 'a' locally as the top package.
                    top = alias.name.split(".")[0]
                    imap[top] = top
    return imap


def _resolve_call_fqn(
    call: ast.Call,
    import_map: dict[str, str],
    type_map: dict[str, str] | None = None,
) -> str | None:
    """Resolve a Call's callee to a dotted FQN. None if out of v1 scope.

    With type_map (var → ClassFQN), additionally resolves
    `instance_var.method(...)` → `ClassFQN.method`. type_map is built by
    `_build_type_map` from simple `var = ClassName(...)` patterns and from
    chained-call return-annotations (e.g., `bus = await MessageBus(...).
    connect()` works because connect's return annotation is the class).
    """
    func = call.func
    # Case 1: bare name → from-import'd function
    if isinstance(func, ast.Name):
        return import_map.get(func.id)
    # Case 2: Alias.attr  → ClassName.method  OR  module.func
    #         instance_var.method  → ClassFQN.method (type_map lookup)
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        base = func.value.id
        if base in import_map:
            return f"{import_map[base]}.{func.attr}"
        if type_map and base in type_map:
            return f"{type_map[base]}.{func.attr}"
        return None
    return None


def _signature_for_fqn(
    fqn: str,
) -> tuple[_inspect.Signature | None, Any, str]:
    """Try to import + introspect the FQN.

    Returns (signature, resolved_object, status). status ∈
      'found'        — sig is non-None and reflects the real callable
      'no_signature' — obj resolved but inspect.signature failed
                       (C extension, exotic descriptor, etc.)
      'attr_missing' — module imported but attribute chain broke. This is
                       DEFINITIVE evidence the symbol does not exist in
                       this library; instance-method R10 uses it.
      'unimportable' — no module prefix imports successfully — cannot
                       decide either way; callers must skip.
    """
    parts = fqn.split(".")
    for split in range(len(parts) - 1, 0, -1):
        mod_path = ".".join(parts[:split])
        attrs = parts[split:]
        try:
            mod = importlib.import_module(mod_path)
        except Exception:  # noqa: BLE001 — any failure → try shorter prefix
            continue
        # From here the module imported, so we can decide definitively.
        obj: Any = mod
        ok = True
        for a in attrs:
            try:
                obj = getattr(obj, a)
            except AttributeError:
                ok = False
                break
        if not ok:
            return (None, None, "attr_missing")
        try:
            return (_inspect.signature(obj), obj, "found")
        except (ValueError, TypeError):
            return (None, obj, "no_signature")
        except Exception:  # noqa: BLE001 — exotic descriptors, etc.
            return (None, obj, "no_signature")
    return (None, None, "unimportable")


def _annotation_to_class_fqn(
    ann: Any,
    import_map: dict[str, str],
    self_fqn: str | None = None,
) -> str | None:
    """Best-effort: convert an inspect.Signature.return_annotation into
    a class FQN, so `_resolve_value_type` can chain `Cls(...).method()`
    into the method's return type.

    Handles:
      Parameter.empty                   → None
      a class object                    → '<module>.<qualname>'
      typing.Self                       → self_fqn (the caller's own class)
      a forward-ref string ('MessageBus') → import_map[name] if known, or
                                            self_fqn when the bare name
                                            matches the receiver class.
      Awaitable[X] / Optional[X] / Coroutine[..., ..., X] → unwrap by
                                            recursing into the last
                                            __args__ entry.
    Conservative: any case we cannot decide returns None.
    """
    if ann is _inspect.Parameter.empty or ann is _inspect.Signature.empty:
        return None
    if _inspect.isclass(ann):
        try:
            return f"{ann.__module__}.{ann.__qualname__}"
        except Exception:  # noqa: BLE001
            return None
    # typing.Self (Python 3.11+) — class returning itself
    try:
        from typing import Self  # type: ignore[attr-defined]
        if ann is Self and self_fqn:
            return self_fqn
    except ImportError:
        pass
    # Forward-reference string annotation
    if isinstance(ann, str):
        bare = ann.strip().strip("'\"")
        if self_fqn and bare.split(".")[-1] == self_fqn.split(".")[-1]:
            return self_fqn
        return import_map.get(bare)
    # Generic alias: Awaitable[X], Optional[X], Coroutine[A, B, X], …
    args = getattr(ann, "__args__", None)
    if args:
        # For Union (incl. Optional[X] = Union[X, None]) prefer the
        # first non-None member — using NoneType would let a single
        # `Optional` return annotation poison the type_map with
        # `builtins.NoneType` and produce a flood of false-positive
        # method-not-found violations on every downstream attribute
        # access. For Coroutine[YieldT, SendT, ReturnT] the interesting
        # one is ReturnT (last). For everything else with one __arg__,
        # last == first.
        non_none = [a for a in args if a is not type(None)]
        pick = non_none[-1] if non_none else args[-1]
        return _annotation_to_class_fqn(pick, import_map, self_fqn)
    return None


def _resolve_value_type(
    value: ast.AST,
    import_map: dict[str, str],
    type_map: dict[str, str],
) -> str | None:
    """Best-effort: figure out the class FQN that an expression evaluates
    to. Returns None when we cannot decide statically (the type_map then
    silently omits the binding — false negatives are accepted).

    Recognized shapes:
      ClassName(args)              — constructor call (must resolve through
                                     import_map AND inspect to a class)
      await Expr                   — pass-through to Expr's resolution
      var                          — type_map[var.id]
      Cls.classmethod(args)        — return annotation of the classmethod
                                     (often the class itself)
      receiver.method(args)        — receiver's type → method's return
                                     annotation; supports chained calls
                                     like `MessageBus(...).connect()`.
    """
    # Unwrap await
    if isinstance(value, ast.Await):
        return _resolve_value_type(value.value, import_map, type_map)
    # Bare name
    if isinstance(value, ast.Name):
        return type_map.get(value.id)
    # Call
    if isinstance(value, ast.Call):
        func = value.func
        # Constructor: ClassName(args) where ClassName is a known import
        if isinstance(func, ast.Name):
            fqn = import_map.get(func.id)
            if fqn is None:
                return None
            _sig, obj, status = _signature_for_fqn(fqn)
            if status == "found" and obj is not None and _inspect.isclass(obj):
                return fqn
            return None
        # Attribute call on a Name: Alias.staticmethod(...) or
        # localvar.method(...) (chained later or assigned)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            base = func.value.id
            recv_type: str | None = None
            if base in import_map:
                # Could be a classmethod / staticmethod / module-level func.
                # Look up its return annotation.
                callee_fqn = f"{import_map[base]}.{func.attr}"
                sig, _obj, status = _signature_for_fqn(callee_fqn)
                if status != "found" or sig is None:
                    return None
                return _annotation_to_class_fqn(
                    sig.return_annotation, import_map, import_map[base]
                )
            recv_type = type_map.get(base)
            if recv_type:
                method_fqn = f"{recv_type}.{func.attr}"
                sig, _obj, status = _signature_for_fqn(method_fqn)
                if status != "found" or sig is None:
                    return None
                return _annotation_to_class_fqn(
                    sig.return_annotation, import_map, recv_type
                )
            return None
        # Chained call: Foo(...).bar(...).baz(...)
        if isinstance(func, ast.Attribute):
            recv_type = _resolve_value_type(func.value, import_map, type_map)
            if recv_type is None:
                return None
            method_fqn = f"{recv_type}.{func.attr}"
            sig, _obj, status = _signature_for_fqn(method_fqn)
            if status != "found" or sig is None:
                return None
            return _annotation_to_class_fqn(
                sig.return_annotation, import_map, recv_type
            )
    return None


def _build_type_map(
    tree: ast.Module,
    import_map: dict[str, str],
) -> dict[str, str]:
    """Walk Assign / AnnAssign nodes; record var → class-FQN when
    resolvable. Last-write-wins (no SSA / branching analysis); good
    enough for the typical step-script flow where each variable holds
    one type for its lifetime.

    Examples successfully tracked (with the helpers above):
      bus = await MessageBus(bus_address=...).connect()
        → {'bus': 'dbus_next.aio.MessageBus'}
      sock = socket.socket(...)
        → {'sock': 'socket.socket'}
      conn = open_dbus_connection(...)         # if return-annotated
        → {'conn': '<annotated-return-class>'}
    Anything else is silently skipped.
    """
    tmap: dict[str, str] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            if len(n.targets) != 1:
                continue
            tgt = n.targets[0]
            if not isinstance(tgt, ast.Name):
                continue
            t = _resolve_value_type(n.value, import_map, tmap)
            if t:
                tmap[tgt.id] = t
        elif isinstance(n, ast.AnnAssign):
            if not isinstance(n.target, ast.Name) or n.value is None:
                continue
            t = _resolve_value_type(n.value, import_map, tmap)
            if t:
                tmap[n.target.id] = t
    return tmap


def _doc_first_line(obj: Any) -> str:
    """Return the first non-empty line of an object's cleaned docstring,
    truncated to keep the violation feedback compact. Empty string when
    there is no useful docstring."""
    if obj is None:
        return ""
    try:
        doc = _inspect.getdoc(obj) or ""
    except Exception:  # noqa: BLE001
        return ""
    for line in doc.splitlines():
        s = line.strip()
        if s:
            return s[:160]
    return ""


def _signature_accepts_var_keyword(sig: _inspect.Signature) -> bool:
    return any(
        p.kind == _inspect.Parameter.VAR_KEYWORD
        for p in sig.parameters.values()
    )


def _iter_signature_violations(
    tree: ast.Module,
) -> Iterable[tuple[str, str, list[str], str, str]]:
    """Yield (fqn, bad_kwarg, valid_param_names, sig_repr, doc_first_line)
    for every kwarg in any Call whose callee resolves to an inspectable
    signature that does NOT contain that kwarg name. Deduplicated by
    (fqn, bad_kwarg) at the caller. `sig_repr` is `str(signature)` (e.g.
    `(bus, *, enable_fds=False, auth_timeout=10.0)`); `doc_first_line`
    is the first non-empty line of the callable's docstring (empty if
    none). These are attached so the LLM's retry feedback shows the
    real API shape, not just a list of parameter names.

    Now also resolves attribute calls on locally-tracked instances via
    `_build_type_map`, so kwarg checks extend to `bus.call(param=...)`
    style usage (previously only bare / alias.attr calls were checked).
    """
    import_map = _build_import_map(tree)
    type_map = _build_type_map(tree, import_map)
    # Cache: fqn -> (sig, obj, status)
    sig_cache: dict[str, tuple[_inspect.Signature | None, Any, str]] = {}
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call) or not n.keywords:
            continue
        fqn = _resolve_call_fqn(n, import_map, type_map)
        if fqn is None:
            continue
        if fqn not in sig_cache:
            sig_cache[fqn] = _signature_for_fqn(fqn)
        sig, obj, _status = sig_cache[fqn]
        if sig is None:
            continue
        if _signature_accepts_var_keyword(sig):
            continue
        params = sig.parameters
        try:
            sig_repr = str(sig)
        except Exception:  # noqa: BLE001
            sig_repr = ""
        doc = _doc_first_line(obj)
        for kw in n.keywords:
            if kw.arg is None:  # `**kwargs` unpack at the call site → skip
                continue
            if kw.arg not in params:
                yield (fqn, kw.arg, list(params.keys()), sig_repr, doc)


def _iter_method_not_found_violations(
    tree: ast.Module,
) -> Iterable[tuple[str, str, str, list[str]]]:
    """Yield (class_fqn, method_name, full_attr_fqn, close_matches) for
    every attribute-call whose receiver is a tracked instance of an
    imported class AND whose method name does not exist on that class.

    Distinct from the kwarg / arity checks because the failure mode is
    "this method is hallucinated entirely" — the LLM invented a
    reasonable-sounding method name (send_message_await_reply,
    call_method, get_introspection) that is simply not in the library's
    real public API. Caught by _signature_for_fqn returning status
    'attr_missing' (module imported, attribute walk broke).

    close_matches: up to 5 difflib suggestions from the class's real
    public attributes, so the retry feedback can name concrete
    alternatives.
    """
    import difflib
    import_map = _build_import_map(tree)
    type_map = _build_type_map(tree, import_map)
    seen: set[tuple[str, str]] = set()
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        func = n.func
        if not isinstance(func, ast.Attribute):
            continue
        if not isinstance(func.value, ast.Name):
            # Chained call `x.y().z(...)` — out of scope for v1 (would need
            # a separate chained-type resolution pass; skip to stay
            # conservative).
            continue
        base = func.value.id
        class_fqn: str | None = None
        if base in type_map:
            class_fqn = type_map[base]
        else:
            # Alias.method patterns are already handled by R10 kwarg /
            # R11 arity when the method exists; when it doesn't, they
            # silently skip. Handle them here too so fabricated
            # classmethods (e.g. MessageBus.open_bus) are caught.
            if base in import_map:
                class_fqn = import_map[base]
        if class_fqn is None:
            continue
        key = (class_fqn, func.attr)
        if key in seen:
            continue
        # Introspect the class itself first — if the class can't be
        # imported, we cannot decide.
        cls_sig, cls_obj, cls_status = _signature_for_fqn(class_fqn)
        if cls_status != "found" or cls_obj is None:
            # Class itself failed to resolve (rare; usually means type_map
            # was over-eager). Skip conservatively.
            continue
        # Is the attribute present on the class?
        try:
            exists = hasattr(cls_obj, func.attr)
        except Exception:  # noqa: BLE001 — exotic __getattr__
            exists = True
        if exists:
            continue
        # Confirmed: method is hallucinated. Gather close matches from
        # public attributes for actionable feedback.
        try:
            real_attrs = [
                a for a in dir(cls_obj) if not a.startswith("_")
            ]
        except Exception:  # noqa: BLE001
            real_attrs = []
        matches = difflib.get_close_matches(
            func.attr, real_attrs, n=5, cutoff=0.5
        )
        seen.add(key)
        full_attr_fqn = f"{class_fqn}.{func.attr}"
        yield (class_fqn, func.attr, full_attr_fqn, matches)


def _iter_runtime_import_nodes(tree: ast.Module) -> Iterable[ast.stmt]:
    """Yield every Import / ImportFrom statement that runs at module load.

    Walks `tree.body` and recurses into `try/except` (both `body` and
    `handlers[*].body`) so fallback-branch imports are checked too — the
    pattern `try: from A import X; except ImportError: from B import X` is
    a common LLM hallucination shape (B doesn't actually export X).

    Skips `if TYPE_CHECKING:` true-branches (those never run at import
    time); other `if` branches are walked since they may be guarded by
    sys.version_info etc. and still execute.
    """
    def _walk(stmts: list[ast.stmt]) -> Iterable[ast.stmt]:
        for node in stmts:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                yield node
                continue
            if isinstance(node, ast.If):
                test = node.test
                is_type_checking = (
                    (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING")
                    or (isinstance(test, ast.Attribute)
                        and test.attr == "TYPE_CHECKING")
                )
                if is_type_checking:
                    yield from _walk(node.orelse)
                else:
                    yield from _walk(node.body)
                    yield from _walk(node.orelse)
                continue
            if isinstance(node, ast.Try):
                yield from _walk(node.body)
                for handler in node.handlers:
                    yield from _walk(handler.body)
                yield from _walk(node.orelse)
                yield from _walk(node.finalbody)
                continue
            try_star_cls = getattr(ast, "TryStar", None)
            if try_star_cls is not None and isinstance(node, try_star_cls):
                yield from _walk(node.body)
                for handler in node.handlers:
                    yield from _walk(handler.body)
                yield from _walk(node.orelse)
                yield from _walk(node.finalbody)
                continue
    yield from _walk(tree.body)


def _iter_import_violations(
    tree: ast.Module,
) -> Iterable[tuple[str, str, list[str]]]:
    """Yield (module_path, missing_name, candidate_names) for every
    `from <module> import <name>` where the module imports successfully
    but <name> is not an attribute of it.

    Walks `tree.body` AND try/except handler bodies (see
    `_iter_runtime_import_nodes`), so fallback-branch hallucinations
    (`try: from dbus_next import MessageBus; except: from dbus_fast
    import MessageBus`) are caught — `dbus_fast` is installed but does
    not export `MessageBus` at top level.

    candidate_names is up to 5 difflib close-matches drawn from
    `dir(module)`, so the retry feedback can suggest concrete
    alternatives (e.g. AuthAnnounceOnly → AuthAnnonymous).

    Skips when:
      - relative import (`from . import X`) — we can't resolve the package
      - `from X import *` — no specific name to validate
      - module fails to import for reasons other than ModuleNotFoundError
        (side-effect import errors, etc.) — conservative.
    """
    import difflib
    mod_cache: dict[str, Any] = {}
    for node in _iter_runtime_import_nodes(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if (node.level or 0) > 0:
            continue
        mod_name = node.module or ""
        if not mod_name:
            continue
        if mod_name not in mod_cache:
            try:
                mod_cache[mod_name] = importlib.import_module(mod_name)
            except Exception:  # noqa: BLE001 — any failure → skip module
                mod_cache[mod_name] = None
        mod = mod_cache[mod_name]
        if mod is None:
            continue
        try:
            available = [a for a in dir(mod) if not a.startswith("_")]
        except Exception:  # noqa: BLE001
            continue
        for alias in node.names:
            if alias.name == "*":
                continue
            try:
                if hasattr(mod, alias.name):
                    continue
            except Exception:  # noqa: BLE001 — exotic __getattr__ raising
                continue
            candidates = difflib.get_close_matches(
                alias.name, available, n=5, cutoff=0.6
            )
            yield (mod_name, alias.name, candidates)


def _iter_module_not_found(
    tree: ast.Module,
) -> Iterable[tuple[str, str, list[str]]]:
    """Yield (module_path, kind, candidate_names) for every top-level
    `import X` / `import X.Y` / `from X import Y` whose module path
    fails with ModuleNotFoundError.

    Distinguished from `_iter_import_violations` because the failure
    mode is different: there the module loads but the symbol is wrong;
    here the module path itself is hallucinated (e.g. `jeepney.routing`
    when only `jeepney` exists). ModuleNotFoundError is a hard signal —
    no installed-vs-missing ambiguity, no side-effect noise.

    candidate_names: for dotted imports `X.Y` where X loads but Y is
    not a submodule, suggests up to 5 closest real submodule names
    via dir(X). Empty list otherwise.

    Walks `tree.body` AND try/except handler bodies (see
    `_iter_runtime_import_nodes`); skips `if TYPE_CHECKING:` true-branches.
    """
    import difflib

    def _check(mod_name: str) -> tuple[bool, list[str]]:
        # Returns (is_module_not_found, candidates).
        try:
            importlib.import_module(mod_name)
            return (False, [])
        except ModuleNotFoundError:
            pass
        except Exception:  # noqa: BLE001 — other ImportError types: skip
            return (False, [])
        # ModuleNotFoundError. If dotted (X.Y), try parent and offer
        # close-match siblings as candidates.
        cands: list[str] = []
        if "." in mod_name:
            parent, _, leaf = mod_name.rpartition(".")
            try:
                parent_mod = importlib.import_module(parent)
                siblings = [a for a in dir(parent_mod) if not a.startswith("_")]
                cands = difflib.get_close_matches(leaf, siblings, n=5, cutoff=0.5)
            except Exception:  # noqa: BLE001 — parent missing too: no cands
                cands = []
        return (True, cands)

    seen: set[str] = set()
    for node in _iter_runtime_import_nodes(tree):
        names_to_check: list[str] = []
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name:
                    names_to_check.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if (node.level or 0) > 0:
                continue
            if node.module:
                names_to_check.append(node.module)
        for mod_name in names_to_check:
            if mod_name in seen:
                continue
            seen.add(mod_name)
            is_mnf, cands = _check(mod_name)
            if is_mnf:
                yield (mod_name, "module_not_found", cands)


# ---------------------------------------------------------------------------
# R11 helpers — positional / required-arg arity check via Signature.bind().
# ---------------------------------------------------------------------------
# Builds on R10's import-map + FQN resolution. Only adds the arity simulation:
# call inspect.Signature.bind() with placeholder values matching the call site
# shape, then categorize any TypeError. Skips MORE aggressively than R10 on
# Cls.method patterns because arity is sensitive to bound-vs-unbound (whereas
# kwarg validity is the same either way).


def _looks_like_unbound_method(obj: Any, sig: _inspect.Signature) -> bool:
    """Heuristic: obj is likely an unbound method, called class-style.

    Triggers when the resolved obj is a function whose first positional
    parameter is named 'self' or 'cls'. For these, validating arity
    statically is ambiguous: the call site might be `Cls.m(inst, arg)` or
    `inst.m(arg)` — both legal, different bound-arg counts. R11 v1 skips
    both with effective reason 'attribute_target_unresolved' rather than
    risking a false positive (which would burn an LLM retry on valid code).
    """
    if not (_inspect.isfunction(obj) or _inspect.ismethod(obj)):
        return False
    params = list(sig.parameters.values())
    if not params:
        return False
    first = params[0]
    if first.kind not in (
        _inspect.Parameter.POSITIONAL_OR_KEYWORD,
        _inspect.Parameter.POSITIONAL_ONLY,
    ):
        return False
    return first.name in ("self", "cls")


def _iter_arity_violations(
    tree: ast.Module,
) -> Iterable[tuple[str, str, str, str]]:
    """Yield (fqn, error_kind, error_detail, sig_repr) for each Call whose
    positional / required-arg shape doesn't bind to its resolved signature.

    error_kind ∈ {'too_many_positional', 'missing_required',
                  'duplicate_argument'}.

    Resolution is shared with R10 (`_resolve_call_fqn` + `_signature_for_fqn`).
    Compared to R10's kwarg-only check, this rule additionally skips:
      * unbound-method-on-class patterns (see _looks_like_unbound_method),
      * signatures with VAR_POSITIONAL (any positional count then valid),
      * call sites containing *args / **kwargs unpack (unpredictable arity).
    Unknown kwargs found by R10 are deliberately dropped from the simulated
    binding so this rule does not double-fire on the same defect.
    """
    import_map = _build_import_map(tree)
    type_map = _build_type_map(tree, import_map)
    sig_cache: dict[str, tuple[_inspect.Signature | None, Any, str]] = {}

    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue

        # Call-site shape gates: any unpacking → can't predict arity.
        if any(isinstance(a, ast.Starred) for a in n.args):
            continue
        if any(kw.arg is None for kw in n.keywords):
            continue

        fqn = _resolve_call_fqn(n, import_map, type_map)
        if fqn is None:
            continue
        if fqn not in sig_cache:
            sig_cache[fqn] = _signature_for_fqn(fqn)
        sig, obj, _status = sig_cache[fqn]
        if sig is None:
            continue

        # Decide if this call is a definitively-bound instance method
        # (receiver is in type_map). When True, the 'self' first param
        # will be filled by Python at call time, so we add a phantom
        # placeholder before bind() to mirror runtime semantics. When
        # False (or unknown), retain the original conservative skip on
        # unbound-method patterns to avoid false positives on
        # `Cls.method(inst, arg)`-style calls.
        is_bound_instance_call = (
            isinstance(n.func, ast.Attribute)
            and isinstance(n.func.value, ast.Name)
            and n.func.value.id in type_map
        )

        if not is_bound_instance_call and _looks_like_unbound_method(obj, sig):
            continue

        # Signature-shape gate: VAR_POSITIONAL → any positional count valid.
        params = sig.parameters
        if any(p.kind == _inspect.Parameter.VAR_POSITIONAL
               for p in params.values()):
            continue

        has_var_kw = any(p.kind == _inspect.Parameter.VAR_KEYWORD
                         for p in params.values())

        # Build placeholder bind. Drop kwargs R10 would flag (unknown name)
        # so binding noise from those doesn't mask the arity check.
        # For bound instance calls, prepend a phantom 'self' so the bind
        # simulation matches runtime arg count.
        actual_pos = len(n.args) + (1 if is_bound_instance_call else 0)
        fake_pos: list[Any] = [None] * actual_pos
        fake_kw: dict[str, Any] = {}
        for kw in n.keywords:
            if kw.arg in params or has_var_kw:
                fake_kw[kw.arg] = None
            # else: silently dropped — R10's domain.

        try:
            sig.bind(*fake_pos, **fake_kw)
        except TypeError as e:
            try:
                sig_repr = str(sig)
            except Exception:  # noqa: BLE001
                sig_repr = ""
            msg = str(e)
            low = msg.lower()
            if "too many positional arguments" in low:
                kind = "too_many_positional"
            elif "missing" in low and "argument" in low:
                kind = "missing_required"
            elif "multiple values for argument" in low:
                kind = "duplicate_argument"
            else:
                # Any other TypeError shape — likely incidental from our
                # placeholder values interacting with a custom __init__
                # validator. Skip rather than risk a false positive.
                continue
            yield (fqn, kind, msg, sig_repr)
        except Exception:  # noqa: BLE001 — exotic descriptors etc.
            continue


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_STRUCT_PREFIX = set("@=<>!")
_STRUCT_NOARG = set("x")
# Format chars where count is bytes-of-payload (1 arg total), not arg
# multiplier. e.g. "10s" = one 10-byte bytes object.
_STRUCT_BYTES_AS_ONE = set("sp")


def _struct_pack_arg_count(fmt: str) -> int | None:
    """Return the number of values struct.pack expects to consume for
    `fmt`, or None if the format contains anything we don't know how to
    score (so we skip rather than false-positive).

    Conservative: any non-format char (whitespace is fine; unknown char
    is not) returns None.
    """
    if not fmt:
        return None
    i = 0
    if fmt[0] in _STRUCT_PREFIX:
        i = 1
    total = 0
    n = 0
    while i < len(fmt):
        c = fmt[i]
        if c.isspace():
            i += 1
            continue
        if c.isdigit():
            n = n * 10 + int(c)
            i += 1
            continue
        # c is a format char
        count = max(n, 1)
        if c in _STRUCT_NOARG:
            pass
        elif c in _STRUCT_BYTES_AS_ONE:
            total += 1
        elif c in "cbB?hHiIlLqQnNefdgPxsp":
            total += count
        else:
            return None  # unknown char — skip
        n = 0
        i += 1
    if n != 0:
        return None  # trailing digits with no format char
    return total


def _iter_struct_pack_violations(
    tree: ast.Module,
) -> Iterable[tuple[str, int, int]]:
    """Yield (fmt, expected_args, actual_args) for every `struct.pack(fmt, *args)`
    where `fmt` is a string literal whose declared arg count does not
    match the number of positional args at the call site.

    Conservative skips:
      - fmt is not a string literal (dynamic format) — skip
      - any positional arg uses *unpack — skip (we cannot count)
      - format contains an unknown char — skip
    """
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # Match struct.pack and struct.pack_into (latter has buffer+offset
        # as first two args, then format).
        callee = node.func
        is_pack = False
        is_pack_into = False
        if isinstance(callee, ast.Attribute) and isinstance(callee.value, ast.Name):
            if callee.value.id == "struct":
                if callee.attr == "pack":
                    is_pack = True
                elif callee.attr == "pack_into":
                    is_pack_into = True
        if not (is_pack or is_pack_into):
            continue
        fmt_idx = 2 if is_pack_into else 0
        if len(node.args) <= fmt_idx:
            continue
        fmt_node = node.args[fmt_idx]
        if not (isinstance(fmt_node, ast.Constant) and isinstance(fmt_node.value, str)):
            continue
        fmt = fmt_node.value
        expected = _struct_pack_arg_count(fmt)
        if expected is None:
            continue
        # Count the trailing positional args. Skip if any uses *unpack.
        value_args = node.args[fmt_idx + 1:]
        if any(isinstance(a, ast.Starred) for a in value_args):
            continue
        actual = len(value_args)
        if actual != expected:
            yield (fmt, expected, actual)


def verify(
    code: str,
    step_plan: StepPlan | None = None,
    target_binding: TargetBinding | None = None,
) -> list[ContractViolation]:
    """Run all rules against the generated code. Returns [] when conforming.

    `step_plan` and `target_binding` are optional: missing step_plan disables
    R4/R5 (artifact contract), missing target_binding makes R6 stricter
    (every flagged literal becomes a violation since nothing whitelists it).
    """
    violations: list[ContractViolation] = []

    # R1: parse.
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        violations.append(ContractViolation(
            rule="R1_parse",
            detail=f"code is not valid Python: {e}",
        ))
        return violations

    # R2: signature (kept here so verify() is self-contained even when the
    # caller skipped the lighter validate_code() check).
    fn = _find_run_step(tree)
    if fn is None:
        violations.append(ContractViolation(
            rule="R2_signature",
            detail="run_step() is not defined at module top level",
        ))
        return violations
    arg_names = [a.arg for a in fn.args.args]
    if arg_names[:2] != ["context", "artifacts"]:
        violations.append(ContractViolation(
            rule="R2_signature",
            detail=(
                f"run_step must take (context, artifacts); "
                f"got {arg_names!r}"
            ),
        ))
        # Keep going — most other rules don't depend on the signature.

    # R3: return_shape — at least one return must be a dict literal whose
    # top-level keys are a subset of {observations, artifacts, notes} AND
    # contains both "observations" and "artifacts".
    returned_dicts = list(_iter_returned_dicts(fn))
    if not returned_dicts:
        violations.append(ContractViolation(
            rule="R3_return_shape",
            detail=(
                "run_step has no `return {...}` dict literal. The harness "
                "needs a literal-shaped return so it can validate the "
                "{observations, artifacts, notes} contract."
            ),
        ))
    else:
        allowed = {"observations", "artifacts", "notes"}
        any_conforming = False
        offenders: list[str] = []
        for d in returned_dicts:
            keys = _dict_literal_str_keys(d)
            extra = keys - allowed
            if "observations" in keys and "artifacts" in keys and not extra:
                any_conforming = True
                break
            if extra:
                offenders.append(f"extra keys {sorted(extra)}")
            else:
                missing = {"observations", "artifacts"} - keys
                offenders.append(f"missing keys {sorted(missing)}")
        if not any_conforming:
            violations.append(ContractViolation(
                rule="R3_return_shape",
                detail=(
                    "no return dict matches the v4 contract (top-level keys "
                    "must be ⊆ {observations, artifacts, notes} and include "
                    "BOTH 'observations' and 'artifacts'). Offenders: "
                    f"{offenders}. Do not add step_id/status/error/"
                    "assertion_results/expected_type — the harness injects "
                    "those."
                ),
            ))

    # R4: artifact_input_read.
    if step_plan is not None and step_plan.artifacts:
        declared_inputs = [
            a.name for a in step_plan.artifacts.get("inputs", []) if a.name
        ]
        if declared_inputs:
            reads = set(_iter_artifact_reads(fn))
            missing_reads = [n for n in declared_inputs if n not in reads]
            if missing_reads:
                violations.append(ContractViolation(
                    rule="R4_artifact_input_read",
                    detail=(
                        f"declared artifact_inputs not read from `artifacts` "
                        f"dict: {missing_reads}. Read each via "
                        f"artifacts['<name>'] or artifacts.get('<name>', ...). "
                        f"Do NOT rename or invent synonyms."
                    ),
                ))

    # R5: artifact_output_write — only enforceable when the returned
    # "artifacts" value is a dict LITERAL (so we can statically inspect keys).
    # Enforces BOTH directions: every declared output must be emitted, AND
    # every emitted key must be declared (no hallucinated outputs — they
    # poison downstream steps that read by declared name and silently
    # ignore the extras).
    if step_plan is not None and step_plan.artifacts:
        declared_out_refs = [
            a for a in step_plan.artifacts.get("outputs", []) if a.name
        ]
        declared_outputs = [a.name for a in declared_out_refs]
        if declared_outputs and returned_dicts:
            for d in returned_dicts:
                artifacts_val = _dict_literal_value_for(d, "artifacts")
                if artifacts_val is None:
                    continue
                if not isinstance(artifacts_val, ast.Dict):
                    break  # opaque — cannot prove
                emitted = _dict_literal_str_keys(artifacts_val)
                missing_outs = [n for n in declared_outputs if n not in emitted]
                extra_outs = [n for n in sorted(emitted)
                              if n not in declared_outputs]
                if missing_outs:
                    violations.append(ContractViolation(
                        rule="R5_artifact_output_write",
                        detail=(
                            f"returned artifacts dict literal does not emit "
                            f"declared outputs {missing_outs}. Emit each "
                            f"under its EXACT declared name."
                        ),
                    ))
                if extra_outs:
                    violations.append(ContractViolation(
                        rule="R5_artifact_output_write",
                        detail=(
                            f"returned artifacts dict literal contains keys "
                            f"not declared in artifact_outputs: {extra_outs}. "
                            f"Declared names: {declared_outputs}. Move any "
                            f"useful-but-undeclared value into an "
                            f"OBSERVATION — hallucinated artifact keys are "
                            f"rejected because downstream steps read by "
                            f"declared name and will silently drop them."
                        ),
                    ))
                break

    # R7: attack_actions implementation count.
    # Heuristic: if step2 declared N attacker behaviors, the script must
    # record at least N observation entries. We count both
    # `observations.append(...)` calls AND inline dict entries inside an
    # `observations=[{...}, {...}]` literal. This is weak (a script could
    # game it by emitting filler observations) but reliably catches the
    # common failure mode where the LLM enumerates 5 actions in the prompt
    # then implements only 1.
    if target_binding is not None and target_binding.attack_actions:
        required = len(target_binding.attack_actions)
        observed = _count_observation_emissions(fn)
        if observed < required:
            violations.append(ContractViolation(
                rule="R7_attack_actions_unimplemented",
                detail=(
                    f"target_binding.attack_actions declares {required} "
                    f"attacker behavior(s) but run_step records only "
                    f"{observed} observation entries. Each declared "
                    f"action must map to at least one observation (or "
                    f"to an `exception` observation naming the action "
                    f"verbatim if it could not be performed). Actions: "
                    f"{list(target_binding.attack_actions)}"
                ),
            ))

    # R9: produces_for_next must be emitted in returned artifacts dict.
    # Same shape as R5 but tightened to the produces_for_next sub-list,
    # which is the explicit chaining commitment (not just the contract
    # declaration). Skipped when "artifacts" value is opaque, same as R5.
    if target_binding is not None and target_binding.produces_for_next \
            and returned_dicts:
        required_outs = list(target_binding.produces_for_next)
        for d in returned_dicts:
            artifacts_val = _dict_literal_value_for(d, "artifacts")
            if artifacts_val is None:
                continue
            if not isinstance(artifacts_val, ast.Dict):
                break  # opaque — cannot prove
            emitted = _dict_literal_str_keys(artifacts_val)
            missing_chain = [n for n in required_outs if n not in emitted]
            if missing_chain:
                violations.append(ContractViolation(
                    rule="R9_produces_for_next_missing",
                    detail=(
                        f"target_binding.produces_for_next requires this "
                        f"step to produce {required_outs}, but the returned "
                        f"artifacts dict literal is missing {missing_chain}. "
                        f"Downstream steps depend on these names; emit each "
                        f"under its EXACT declared name (use a partial / "
                        f"failure record value rather than omitting the key)."
                    ),
                ))
            break

    # R6: forbidden_fabricated_literals.
    binding_strs, binding_ints = _binding_value_corpus(target_binding)
    bad_strs: list[str] = []
    bad_ints: list[int] = []
    for n in ast.walk(fn):
        if not isinstance(n, ast.Constant):
            continue
        v = n.value
        if isinstance(v, str):
            low = v.lower()
            for tok in _FORBIDDEN_STRING_TOKENS:
                if tok in low and v not in binding_strs:
                    bad_strs.append(v)
                    break
        elif isinstance(v, bool):
            continue  # bools are ints in Python; we don't care
        elif isinstance(v, int):
            if v in _FORBIDDEN_INT_LITERALS and v not in binding_ints:
                bad_ints.append(v)
    if bad_strs or bad_ints:
        parts: list[str] = []
        if bad_strs:
            parts.append(f"forbidden string literals {sorted(set(bad_strs))}")
        if bad_ints:
            parts.append(f"forbidden int literals {sorted(set(bad_ints))}")
        violations.append(ContractViolation(
            rule="R6_forbidden_fabricated_literals",
            detail=(
                "; ".join(parts)
                + ". These are characteristic fallback defaults. Read every "
                "concrete value from target_binding (endpoint / target_ref / "
                "protocol) or from artifacts. If the binding does not carry "
                "the value you need, record an exception observation — do "
                "NOT substitute."
            ),
        ))

    # R10: signature_mismatch — every Call's kwargs must exist in the resolved
    # callable's inspect.signature. Skips silently when the callee can't be
    # statically resolved (instance method, dynamic dispatch) or when the
    # module/object can't be imported/introspected. Dedup by (fqn, kwarg) so
    # a kwarg used inside a loop only fires once.
    try:
        sig_pairs = list(_iter_signature_violations(tree))
    except Exception:  # noqa: BLE001 — verifier never raises on user code
        sig_pairs = []
    seen_pairs: set[tuple[str, str]] = set()
    for fqn, bad_kw, valid_params, sig_repr, doc in sig_pairs:
        key = (fqn, bad_kw)
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        short = fqn.rsplit(".", 1)[-1]
        # Build a richer feedback block: the LLM sees the real signature
        # and a one-line docstring so it can pick the right kwarg from the
        # ACTUAL API instead of (a) re-inventing another wrong kwarg or
        # (b) abandoning the library and hand-rolling the protocol — the
        # observed escape pattern when feedback was just a name list.
        sig_line = f"{short}{sig_repr}" if sig_repr else ""
        parts = [
            f"{short}() got unexpected keyword argument '{bad_kw}'.",
            f"Resolved callable: {fqn}.",
        ]
        if sig_line:
            parts.append(f"Real signature: {sig_line}.")
        parts.append(f"Valid parameters: {valid_params}.")
        if doc:
            parts.append(f"Docstring: {doc}")
        parts.append(
            "Fix this by USING THE LIBRARY CORRECTLY: drop the bad kwarg, "
            "rename it to one in the valid list, or pick a different "
            "callable from the same library. Do NOT invent kwargs. Do "
            "NOT abandon the library and hand-roll the protocol with raw "
            "sockets / struct.pack — that path leads to deeper bugs the "
            "verifier cannot catch (alignment, framing, auth retry)."
        )
        violations.append(ContractViolation(
            rule="R10_signature_mismatch",
            detail=" ".join(parts),
        ))

    # R10 method_not_found — attribute call on a tracked instance whose
    # method does not exist on the resolved class. Catches LLM hallucinated
    # instance methods (e.g. bus.send_message_await_reply when dbus_next.aio
    # MessageBus only has .call / .send). _signature_for_fqn returning
    # status='attr_missing' is the definitive signal: the class imported
    # but the attribute walk broke.
    try:
        method_pairs = list(_iter_method_not_found_violations(tree))
    except Exception:  # noqa: BLE001 — verifier never raises on user code
        method_pairs = []
    seen_methods: set[tuple[str, str]] = set()
    for class_fqn, method_name, full_attr_fqn, candidates in method_pairs:
        key = (class_fqn, method_name)
        if key in seen_methods:
            continue
        seen_methods.add(key)
        cls_short = class_fqn.rsplit(".", 1)[-1]
        parts = [
            f"{cls_short}.{method_name}() does not exist on class "
            f"{class_fqn}.",
        ]
        if candidates:
            parts.append(
                f"Closest real attributes: {candidates}. Pick one of "
                f"these (or another real attribute) — do NOT keep the "
                f"hallucinated method name."
            )
        else:
            parts.append(
                f"No similar names found on the class. Re-check the "
                f"library's public API; the method you wrote does not "
                f"exist in any spelling."
            )
        parts.append(
            "Fix this by USING THE LIBRARY CORRECTLY: pick a real "
            "method from the resolved class. Do NOT abandon the library "
            "and hand-roll the protocol with raw sockets / struct.pack — "
            "that path leads to deeper bugs the verifier cannot catch "
            "(alignment, framing, auth retry)."
        )
        violations.append(ContractViolation(
            rule="R10_method_not_found",
            detail=" ".join(parts),
        ))

    # R10 module_not_found — `import X` / `import X.Y` / `from X import Y`
    # where the module path itself raises ModuleNotFoundError. Catches
    # hallucinated submodules like `jeepney.routing` (jeepney exists,
    # .routing does not) that previously slipped through silently because
    # the import-name check skips modules that fail to import.
    try:
        mnf_pairs = list(_iter_module_not_found(tree))
    except Exception:  # noqa: BLE001 — verifier never raises on user code
        mnf_pairs = []
    seen_mnf: set[str] = set()
    for mod_name, _kind, candidates in mnf_pairs:
        if mod_name in seen_mnf:
            continue
        seen_mnf.add(mod_name)
        parts = [
            f"`import {mod_name}` (or `from {mod_name} import ...`) will "
            f"fail at import time: module '{mod_name}' is not installed "
            f"or does not exist.",
        ]
        if candidates:
            parts.append(
                f"Closest real names under the parent package: {candidates}. "
                f"Pick a real submodule — do NOT keep the hallucinated path."
            )
        else:
            parts.append(
                "No similar names found under the parent package (or the "
                "parent itself is missing). Re-check the library's actual "
                "module layout; the path you wrote does not exist."
            )
        parts.append(
            "Do NOT respond by hand-rolling the protocol with raw sockets. "
            "Either pick a real module from the same library, or switch to "
            "a different library that does exist in the environment."
        )
        violations.append(ContractViolation(
            rule="R10_module_not_found",
            detail=" ".join(parts),
        ))

    # R10 import_name_missing — `from X import Y` where Y is not an attribute
    # of X. Catches symbol hallucination (e.g. AuthAnnounceOnly which simply
    # does not exist in dbus_next.auth) — these slip past the kwarg check
    # because the failure is at module load time, before any Call runs.
    try:
        import_pairs = list(_iter_import_violations(tree))
    except Exception:  # noqa: BLE001 — verifier never raises on user code
        import_pairs = []
    seen_imp: set[tuple[str, str]] = set()
    for mod_name, missing_name, candidates in import_pairs:
        key = (mod_name, missing_name)
        if key in seen_imp:
            continue
        seen_imp.add(key)
        parts = [
            f"`from {mod_name} import {missing_name}` will fail at "
            f"import time: '{missing_name}' is not an attribute of "
            f"module '{mod_name}'.",
        ]
        if candidates:
            parts.append(
                f"Closest real names in that module: {candidates}. "
                f"Pick one of these (or another real export) — do NOT "
                f"keep the hallucinated name."
            )
        else:
            parts.append(
                f"No similar names found in {mod_name}. Re-check the "
                f"library's public API; the symbol you wrote does not "
                f"exist in any spelling."
            )
        parts.append(
            "Do NOT respond by abandoning the library and hand-rolling "
            "the protocol — fix the import to a real symbol from the "
            "same library, or switch to a different callable in the "
            "library that achieves the same goal."
        )
        violations.append(ContractViolation(
            rule="R10_import_name_missing",
            detail=" ".join(parts),
        ))

    # R11: arity_mismatch — every Call's positional + required-arg shape must
    # bind cleanly to the resolved callable's inspect.signature. Catches
    # struct.pack format/arg count mismatches, missing required positional /
    # keyword-only arguments, and duplicate-argument cases the kwarg-only R10
    # check cannot see. Conservative: skips unbound-method patterns and any
    # call site / signature with VAR_POSITIONAL / unpack semantics. Dedup by
    # (fqn, kind, detail) so a buggy call inside a loop only fires once.
    try:
        arity_pairs = list(_iter_arity_violations(tree))
    except Exception:  # noqa: BLE001 — verifier never raises on user code
        arity_pairs = []
    seen_arity: set[tuple[str, str, str]] = set()
    for fqn, kind, detail, sig_repr in arity_pairs:
        key = (fqn, kind, detail)
        if key in seen_arity:
            continue
        seen_arity.add(key)
        short = fqn.rsplit(".", 1)[-1]
        sig_line = f"{short}{sig_repr}" if sig_repr else ""
        parts = [
            f"{short}() argument-shape error: {detail}.",
            f"Resolved callable: {fqn}.",
        ]
        if sig_line:
            parts.append(f"Real signature: {sig_line}.")
        if kind == "too_many_positional":
            parts.append(
                "Pass fewer positional arguments. If the format/spec string "
                "(e.g. struct format, printf-style template) implies more "
                "values, fix the format to match the args you actually have, "
                "or supply the missing values from the binding/artifacts."
            )
        elif kind == "missing_required":
            parts.append(
                "Supply the missing required argument(s). Read the value "
                "from target_binding (endpoint / target_ref / protocol) or "
                "from artifacts; do NOT pass a fabricated default and do "
                "NOT silently drop the argument."
            )
        elif kind == "duplicate_argument":
            parts.append(
                "An argument was passed both positionally and as a keyword. "
                "Choose one form and remove the other."
            )
        parts.append(
            "Do NOT respond by abandoning the library and hand-rolling "
            "the protocol — fix the call site to match the real signature."
        )
        violations.append(ContractViolation(
            rule="R11_arity_mismatch",
            detail=" ".join(parts),
        ))

    # R13: struct_pack_arg_count_mismatch — `struct.pack(fmt, *args)` where
    # fmt is a string literal and len(args) does not match the format's
    # declared field count. R11 cannot catch this (struct.pack has
    # VAR_POSITIONAL signature), but it is a hard runtime crash.
    try:
        struct_pairs = list(_iter_struct_pack_violations(tree))
    except Exception:  # noqa: BLE001
        struct_pairs = []
    seen_struct: set[tuple[str, int, int]] = set()
    for fmt, expected, actual in struct_pairs:
        key = (fmt, expected, actual)
        if key in seen_struct:
            continue
        seen_struct.add(key)
        violations.append(ContractViolation(
            rule="R13_struct_pack_arity",
            detail=(
                f"struct.pack format '{fmt}' expects {expected} value(s) "
                f"but the call site passes {actual}. This will raise "
                f"struct.error at runtime. Either fix the format string "
                f"to match the values you actually have (drop unused "
                f"fields, change widths) or supply the missing values "
                f"from target_binding / artifacts. Do NOT pad with zeros "
                f"or fabricated defaults."
            ),
        ))

    # R12: endpoint_key_unused (WARN) — every key present in
    # target_binding.endpoint that does NOT appear as a string literal
    # anywhere in the generated code. Catches the "step3a injected the
    # value but the LLM ignored it and used a default" failure mode.
    # WARN-grade: detail starts with "WARN" so the retry loop / human
    # reader can distinguish it from hard violations. Conservative:
    # skips keys whose name starts with '_' (binding metadata).
    if target_binding is not None and target_binding.endpoint:
        endpoint_keys = [
            k for k in target_binding.endpoint.keys()
            if isinstance(k, str) and k and not k.startswith("_")
        ]
        if endpoint_keys:
            literals_in_code: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    literals_in_code.add(node.value)
            unused = [k for k in endpoint_keys if k not in literals_in_code]
            for key in unused:
                value = target_binding.endpoint.get(key)
                value_repr = repr(value) if value is not None else "<None>"
                if len(value_repr) > 80:
                    value_repr = value_repr[:77] + "..."
                violations.append(ContractViolation(
                    rule="R12_endpoint_key_unused",
                    detail=(
                        f"WARN: target_binding.endpoint has key '{key}' "
                        f"(value={value_repr}) but the generated code does "
                        f"not reference '{key}' anywhere as a string literal. "
                        f"If your action needs this value, read it via "
                        f"endpoint['{key}'] (or the equivalent unpack) — "
                        f"do NOT substitute a default. If your action "
                        f"genuinely does not need it, this WARN is safe "
                        f"to ignore."
                    ),
                ))

    # R14: library_lock — when target_binding.library_candidates is non-empty,
    # the script may import the protocol-bearing client ONLY from the listed
    # `import_module` names. Auxiliary stdlib modules and a small allow-list
    # of generic helpers (asyncio, json, socket, struct, time, hashlib, re,
    # os, sys, typing, dataclasses, enum, itertools, functools, collections,
    # xml.etree.ElementTree, base64, binascii, ssl, ipaddress, uuid, urllib,
    # http.client, datetime, math, random) are always permitted alongside the
    # locked candidate. This rule catches the failure mode where step3a
    # researched and stamped, say, `dbus_next` for D-Bus over TCP, but the
    # LLM still imported `jeepney` from imagination — guaranteeing a
    # transport-incompatible runtime failure.
    if target_binding is not None and target_binding.library_candidates:
        allowed_protocol_modules = {
            (c.get("import_module") or "").strip().lower()
            for c in target_binding.library_candidates
            if c.get("import_module")
        }
        # Auxiliary modules that don't carry the binding's protocol semantics
        # — always allowed alongside the locked candidate.
        stdlib_aux_modules = {
            "asyncio", "json", "socket", "struct", "time", "hashlib", "re",
            "os", "sys", "typing", "dataclasses", "enum", "itertools",
            "functools", "collections", "xml", "base64", "binascii", "ssl",
            "ipaddress", "uuid", "urllib", "http", "datetime", "math",
            "random", "logging", "io", "pathlib", "contextlib", "threading",
            "queue", "tempfile", "warnings", "traceback", "abc", "copy",
            "string", "shlex",
        }
        # Walk top-level imports
        seen_protocol_lib: set[str] = set()
        offending: list[tuple[str, str]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = (alias.name or "").split(".")[0].lower()
                    if not top:
                        continue
                    if top in stdlib_aux_modules:
                        continue
                    if top in allowed_protocol_modules:
                        seen_protocol_lib.add(top)
                        continue
                    offending.append(("import", alias.name))
            elif isinstance(node, ast.ImportFrom):
                mod = (node.module or "")
                top = mod.split(".")[0].lower() if mod else ""
                if not top:
                    continue
                if top in stdlib_aux_modules:
                    continue
                if top in allowed_protocol_modules:
                    seen_protocol_lib.add(top)
                    continue
                offending.append(("from", mod))

        candidate_summary = ", ".join(
            sorted(allowed_protocol_modules)
        ) or "(none)"
        for kind, name in offending:
            violations.append(ContractViolation(
                rule="R14_library_lock_violation",
                detail=(
                    f"step3a researched and locked the library candidate(s) "
                    f"[{candidate_summary}] for this binding's "
                    f"protocol+transport pair, with documentation citations. "
                    f"Your code introduced an import ({kind} {name}) that is "
                    f"NOT in the locked candidate list and NOT in the stdlib "
                    f"auxiliary allow-list. Replace it with one of the "
                    f"locked candidates. If you believe none of the candidates "
                    f"can do what you need, prefer the FIRST listed candidate "
                    f"and call its lower-level API instead of switching "
                    f"libraries — the research already verified transport "
                    f"support for this combination."
                ),
            ))
        # Also flag if the script doesn't import any of the locked candidates.
        # This catches the "fully hand-rolled" path the LLM sometimes takes
        # (raw socket + struct.pack) when a vetted library was available.
        if not seen_protocol_lib:
            violations.append(ContractViolation(
                rule="R14_library_lock_violation",
                detail=(
                    f"step3a locked library candidate(s) [{candidate_summary}] "
                    f"for this binding, but the generated code does not "
                    f"import ANY of them. Hand-rolling the protocol on raw "
                    f"transport primitives is not permitted when a researched "
                    f"library is available. Import the first listed candidate "
                    f"and use its documented API."
                ),
            ))

    return violations


def format_feedback(violations: list[ContractViolation]) -> str:
    """Render a violation list as a short LLM-readable feedback block."""
    if not violations:
        return ""
    lines = [
        "Your previous attempt failed contract verification. Fix the "
        "following issues and emit a corrected run_step. Do NOT change "
        "anything else; do NOT add explanations.",
    ]
    for v in violations:
        lines.append(f"- {v.feedback()}")
    return "\n".join(lines)
