"""
Step 5 (pipeline_v7): Assemble per-step scripts into one executable file.

Input:  per-path directory with steps/T*.py (Step 3-2 output)
Output: a single .py that defines _step_<id>(context, artifacts) for each
        step and a main() that chains them, prints per-step assertion
        results, and exits with a verdict code.

No LLM. Pure source rewrite — renames each file's `run_step` symbol to
`_step_<step_id>` so all step bodies can coexist in one module.
"""

from __future__ import annotations

import ast
import datetime as _dt
import re
import sys
from pathlib import Path

from pipeline_types import AttackPath, NormalizedScenario


_HEADER = '''\
"""
Auto-generated attack test script.

Scenario:  {scenario_id}
Path:      {path_id} — {label}
Steps:     {step_ids}
Generated: {timestamp}

Produced by step5_assemble_v3. Do NOT edit manually.
Run:       python {filename}
"""
from __future__ import annotations

import json
import sys
import threading
import traceback

# Force UTF-8 stdout so unicode in observations/notes and non-ASCII
# characters in harness messages do not crash on cp949 / cp1252 consoles.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass
'''


_MAIN_TEMPLATE = '''

# ---------------------------------------------------------------------------
# Runtime harness — OBSERVATIONS ONLY (no verdict computed here).
#
# Contract (v4a):
#   run_step returns {{observations: [...], artifacts: {{...}}, notes: <str|null>}}.
#   The harness injects step_id / status / error and applies a compat shim
#   (assertion_results=[], evidence=[], _script_contract="v4a") so that
#   downstream evaluators that still read the old keys do not KeyError.
#
#   A 15-second wall-clock timeout protects against infinite loops in
#   LLM-generated code. On timeout, status="timeout" and _timeout=True
#   disambiguate from a plain exception.
#
# Verdict classification (PASS/FAIL/INCONCLUSIVE) is the job of a
# downstream evaluator (Step 4B). The harness here records only what
# happened at runtime.
# ---------------------------------------------------------------------------

_STEP_TIMEOUT_SECONDS = 15.0


def _run_with_timeout(fn, context, artifacts):
    """Run fn(context, artifacts) on a daemon thread; enforce wall-clock
    timeout via join. Returns (value, error_exc, timed_out).

    Note: if the step times out, the thread keeps running in the
    background (Python has no safe thread-kill). daemon=True ensures the
    interpreter exits cleanly on main() return. For the MVP this is
    acceptable — operator wraps the whole run in its own outer timeout.
    """
    box = {{"value": None, "error": None}}
    def _target():
        try:
            box["value"] = fn(dict(context), dict(artifacts))
        except BaseException as e:  # noqa: BLE001
            box["error"] = e
    t = threading.Thread(target=_target, daemon=True)
    t.start()
    t.join(_STEP_TIMEOUT_SECONDS)
    return box["value"], box["error"], t.is_alive()


def _compat_shim(entry):
    """Inject the backcompat keys Step4 may still read. Call once per
    entry AFTER status/error/observations/artifacts/notes are set."""
    entry.setdefault("observations", [])
    entry.setdefault("artifacts", {{}})
    entry.setdefault("notes", None)
    entry["assertion_results"] = []
    entry["evidence"] = []
    entry["_script_contract"] = "v4a"


def main():
    context = {context_literal}
    artifacts = {{}}
    record = {{
        "scenario_id": {scenario_id!r},
        "path_id": {path_id!r},
        "steps": [],
    }}

    steps = [
{step_tuples}
    ]

    for step_id, fn in steps:
        print(f"=== {{step_id}} ===")
        entry = {{"step_id": step_id}}

        value, err, timed_out = _run_with_timeout(fn, context, artifacts)

        if timed_out:
            print(f"  [TIMEOUT] exceeded {{_STEP_TIMEOUT_SECONDS}}s")
            entry["status"] = "timeout"
            entry["error"] = {{"type": "Timeout",
                              "message": f"exceeded {{_STEP_TIMEOUT_SECONDS}}s wall-clock"}}
            entry["_timeout"] = True
            _compat_shim(entry)
            record["steps"].append(entry)
            continue

        if err is not None:
            print(f"  [EXCEPTION] {{type(err).__name__}}: {{err}}")
            traceback.print_exception(type(err), err, err.__traceback__)
            entry["status"] = "exception"
            entry["error"] = {{"type": type(err).__name__, "message": str(err)}}
            _compat_shim(entry)
            record["steps"].append(entry)
            continue

        if not isinstance(value, dict):
            print(f"  [BAD RETURN] run_step returned {{type(value).__name__}}")
            entry["status"] = "bad_return_type"
            entry["error"] = {{"type": "BadReturnType",
                              "message": f"expected dict, got {{type(value).__name__}}"}}
            _compat_shim(entry)
            record["steps"].append(entry)
            continue

        observations = value.get("observations") or []
        step_artifacts = value.get("artifacts") or {{}}
        notes = value.get("notes")

        artifacts.update(step_artifacts)

        entry["status"] = "ok"
        entry["error"] = None
        entry["observations"] = observations
        entry["artifacts"] = step_artifacts
        entry["notes"] = notes
        _compat_shim(entry)
        record["steps"].append(entry)

        print(f"  observations: {{len(observations)}}; "
              f"artifacts: {{list(step_artifacts.keys())}}")

    print()
    print("=== observations recorded (no verdict — use downstream evaluator) ===")
    print(json.dumps(record, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


_FUTURE_IMPORT_RE = re.compile(
    r"^[ \t]*from __future__ import[^\n]*\n?",
    flags=re.MULTILINE,
)


def _strip_future_imports(source: str) -> str:
    """Remove ``from __future__ import ...`` lines from a step body.

    The assembled file's _HEADER declares the needed future imports once
    at the module top. When step bodies are concatenated below the
    header, any additional ``from __future__`` line ends up past the
    beginning of the file and Python raises SyntaxError.
    """
    return _FUTURE_IMPORT_RE.sub("", source)


_FALLBACK_STUB_BODY_TEMPLATE = '''
def {fn_name}(context, artifacts):
    return {{
        "observations": [{{"name": {marker!r}, "value": True}}],
        "artifacts": {{}},
        "notes": {reason!r},
    }}
'''


def _check_compilable(source: str, label: str) -> tuple[bool, str | None]:
    """Try compile() on source. Return (True, None) on success,
    (False, reason) on failure.

    Unlike ast.parse this also catches compile-phase errors that the
    parser lets through — e.g. "name 'x' is parameter and global",
    duplicate __future__ import detection, or other bytecode-gen rejects.
    """
    try:
        compile(source, label, "exec")
        return True, None
    except SyntaxError as e:
        return False, f"SyntaxError: {e.msg} at line {e.lineno}"
    except ValueError as e:
        return False, f"ValueError: {e}"


def _rename_run_step(source: str, new_name: str) -> str:
    """Rewrite `def run_step(` occurrences to `def <new_name>(`.

    Uses AST to confirm a top-level `run_step` function exists, then
    does a conservative string replace (run_step must be a module-level
    identifier in Step 3-2 output, so this is safe for generated code).
    """
    tree = ast.parse(source)
    found = any(
        isinstance(n, ast.FunctionDef) and n.name == "run_step"
        for n in tree.body
    )
    if not found:
        raise ValueError("run_step not found at module scope")
    return source.replace("def run_step(", f"def {new_name}(", 1)


def assemble_path(
    scenario: NormalizedScenario,
    path: AttackPath,
    steps_dir: Path,
    out_dir: Path,
) -> Path:
    step_ids: list[str] = [s.step_id for s in path.steps]
    bodies: list[str] = []

    ctx_label = f"{scenario.scenario_id}/{path.path_id}"
    for sid in step_ids:
        src_path = steps_dir / f"{sid}.py"
        if not src_path.exists():
            print(
                f"[step5] {ctx_label}/{sid} missing step file "
                f"({src_path}) — inserting missing-step stub",
                file=sys.stderr,
            )
            bodies.append(_FALLBACK_STUB_BODY_TEMPLATE.format(
                fn_name=f"_step_{sid}",
                marker="step5_missing_step_file",
                reason=f"step5: source file not found in steps_dir ({src_path.name})",
            ))
            continue
        source = src_path.read_text(encoding="utf-8")
        source = _strip_future_imports(source)
        try:
            renamed = _rename_run_step(source, f"_step_{sid}")
        except ValueError:
            renamed = source + (
                f"\n\ndef _step_{sid}(context, artifacts):\n"
                f"    return run_step(context, artifacts)\n"
            )
        # Per-body compile() check: catches SyntaxError/ValueError that
        # ast.parse alone misses (e.g. parameter-and-global conflict).
        # Failure isolates to this step only; other steps proceed normally.
        ok, reason = _check_compilable(renamed, f"<step:{ctx_label}/{sid}>")
        if not ok:
            print(
                f"[step5] {ctx_label}/{sid} replaced with compile-fallback "
                f"stub: {reason}",
                file=sys.stderr,
            )
            renamed = _FALLBACK_STUB_BODY_TEMPLATE.format(
                fn_name=f"_step_{sid}",
                marker="step5_compile_fallback",
                reason=f"step5 compile check failed: {reason}",
            )
        bodies.append("\n# " + "-" * 70
                      + f"\n# {sid}\n# " + "-" * 70 + "\n" + renamed)

    # Build primary context from the path's first connection (if any).
    ctx = {}
    for st in path.steps:
        if st.connection is not None:
            props = dict(st.connection.properties or {})
            ctx = {
                "connection_id": st.connection.connection_id,
                "protocol": st.connection.protocol,
                "host": props.get("host"),
                "port": props.get("port"),
                "connection_properties": props,
            }
            break

    filename = f"{scenario.scenario_id}__{path.path_id}.py"
    header = _HEADER.format(
        scenario_id=scenario.scenario_id,
        path_id=path.path_id,
        label=(path.label or path.path_id).replace("\n", " "),
        step_ids=", ".join(step_ids),
        timestamp=_dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        filename=filename,
    )

    step_tuples = "\n".join(
        f'        ("{sid}", _step_{sid}),' for sid in step_ids
    )
    main_block = _MAIN_TEMPLATE.format(
        context_literal=repr(ctx),
        step_tuples=step_tuples,
        scenario_id=scenario.scenario_id,
        path_id=path.path_id,
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / filename
    assembled_source = header + "\n" + "\n".join(bodies) + main_block
    out_path.write_text(assembled_source, encoding="utf-8")
    # Sanity-check the produced file with compile() — stricter than
    # ast.parse. If this fails, it is a step5 assembly bug (body
    # concat / header / main_block interaction), not LLM output, since
    # individual bodies were already compile-checked above.
    ok, reason = _check_compilable(assembled_source, str(out_path))
    if not ok:
        raise RuntimeError(
            f"assembled file fails compile() — this is a step5 bug, "
            f"not LLM output: {out_path} — {reason}"
        )
    return out_path
