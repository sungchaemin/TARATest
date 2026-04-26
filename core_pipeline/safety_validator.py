"""Safety validator — AST blacklist for LLM-generated run_step code.

Phase A4 of the pipeline_v7 generation refactor. Replaces the old
per-transport import whitelist (removed in A2) with a content-level
blacklist of forbidden primitives.

Forbidden (hard — code is rejected):
  1. os.system(...)
  2. subprocess.* with shell=True
  3. subprocess.Popen / run / call / check_* launching a shell interpreter
     (/bin/sh, /bin/bash, sh, bash, cmd, powershell)
  4. eval(...), exec(...)
  5. __import__(...) called dynamically
  6. open(path, mode) with write mode on /etc, /boot, /sys, /proc, or /dev
     — except /dev/vcan*, /dev/can* which are legitimate vehicle-bus
     interfaces.
  7. pathlib.Path(literal).write_text(...) / .write_bytes(...) into the
     same forbidden prefixes.

Alias tracking:
  Import bindings like `import subprocess as sp` or `from subprocess
  import run` are resolved before call-site checks, so
      sp.run("sh", shell=True)
      run("sh", shell=True)
  both match the `subprocess.run` rules.

  Limitation (accepted): the alias table is module-flat (not
  scope-aware). An alias introduced in one function body is visible
  when resolving calls in another. In practice the only consequence is
  mild over-eager matching, which is tolerable for a security blacklist.
  Reflection via getattr()/__import__ is deliberately NOT tracked;
  __import__ is already blocked as a separate rule.

Design decisions:
  - AST-only; no runtime instrumentation. Cheap, no side effects,
    works on code that may not import cleanly in the current env.
  - Violations include (rule_id, lineno, message) so a retry prompt
    can tell the LLM exactly what to fix.
  - Conservative: when in doubt, allow. The harness wall-clock timeout
    (Phase A6) and operator review catch runtime issues not detectable
    in static AST (e.g. infinite loops with break, external-IP leaks).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass


_FORBIDDEN_FS_PREFIXES = ("/etc", "/boot", "/sys", "/proc")
_FORBIDDEN_DEV_EXCEPTIONS = ("/dev/vcan", "/dev/can")
_SHELL_INTERPRETERS = ("sh", "bash", "cmd", "powershell")


@dataclass(frozen=True)
class Violation:
    rule_id: str
    lineno: int
    message: str

    def __str__(self) -> str:
        return f"[{self.rule_id} line {self.lineno}] {self.message}"


def check(code: str) -> tuple[bool, list[str]]:
    """Return (is_safe, violation_messages).

    Syntax errors are reported as a single SAFETY_SYNTAX violation so
    callers can distinguish "unparseable" from "contains forbidden calls".
    """
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return False, [f"[SAFETY_SYNTAX line {e.lineno or 0}] {e.msg}"]
    visitor = _BlacklistVisitor()
    visitor.visit(tree)
    return (not visitor.violations), [str(v) for v in visitor.violations]


class _BlacklistVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.violations: list[Violation] = []
        # local_name -> original dotted module path
        #   import subprocess as sp        -> {"sp": "subprocess"}
        #   from subprocess import run     -> {"run": "subprocess.run"}
        #   from os import system as s     -> {"s": "os.system"}
        self._aliases: dict[str, str] = {}

    # --- alias collection ---------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name
            self._aliases[local] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            for alias in node.names:
                local = alias.asname or alias.name
                self._aliases[local] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    def _resolve(self, dotted: str) -> str:
        """Expand the leftmost name through the alias table.

        'sp.run'              (with sp=subprocess) -> 'subprocess.run'
        'run'                 (from subprocess)    -> 'subprocess.run'
        's'                   (from os import s)   -> 'os.system'
        'os.system'           (no alias)           -> 'os.system'
        """
        if not dotted:
            return dotted
        head, _, tail = dotted.partition(".")
        expanded = self._aliases.get(head, head)
        return f"{expanded}.{tail}" if tail else expanded

    # --- call-site checks ---------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        fn_name = self._resolve(_callable_name(node.func))

        if fn_name == "os.system":
            self._add("FORBIDDEN_OS_SYSTEM", node.lineno,
                      "os.system() is forbidden")

        if fn_name.startswith("subprocess."):
            if _has_kwarg_true(node, "shell"):
                self._add("FORBIDDEN_SHELL_TRUE", node.lineno,
                          f"{fn_name}(..., shell=True) is forbidden")
            if fn_name in ("subprocess.Popen", "subprocess.call",
                           "subprocess.run", "subprocess.check_call",
                           "subprocess.check_output"):
                first = node.args[0] if node.args else None
                if _is_shell_invocation_target(first):
                    self._add("FORBIDDEN_SHELL_PROCESS", node.lineno,
                              f"{fn_name}() launching a shell interpreter "
                              f"is forbidden")

        if fn_name in ("eval", "exec"):
            self._add("FORBIDDEN_EVAL_EXEC", node.lineno,
                      f"{fn_name}() is forbidden")

        if fn_name == "__import__":
            self._add("FORBIDDEN_DYNAMIC_IMPORT", node.lineno,
                      "__import__() called at runtime is forbidden")

        if fn_name in ("open", "io.open"):
            self._check_open_write(node)

        if (isinstance(node.func, ast.Attribute)
                and node.func.attr in ("write_text", "write_bytes")):
            self._check_path_method_write(node)

        self.generic_visit(node)

    def _check_open_write(self, node: ast.Call) -> None:
        if not node.args:
            return
        path = _literal_str(node.args[0])
        if path is None:
            return
        mode = "r"
        if len(node.args) >= 2:
            mode = _literal_str(node.args[1]) or mode
        for kw in node.keywords:
            if kw.arg == "mode":
                mode = _literal_str(kw.value) or mode
        if any(c in mode for c in ("w", "a", "x", "+")):
            if _is_forbidden_path(path):
                self._add("FORBIDDEN_FS_WRITE", node.lineno,
                          f"write to {path!r} (forbidden prefix)")

    def _check_path_method_write(self, node: ast.Call) -> None:
        obj = node.func.value if isinstance(node.func, ast.Attribute) else None
        path = _trace_path_literal(obj)
        if path and _is_forbidden_path(path):
            attr = node.func.attr  # type: ignore[attr-defined]
            self._add("FORBIDDEN_FS_WRITE", node.lineno,
                      f"write to {path!r} via {attr}()")

    def _add(self, rule_id: str, lineno: int, msg: str) -> None:
        self.violations.append(Violation(rule_id, lineno, msg))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _callable_name(node: ast.expr) -> str:
    """Best-effort dotted name for an ast.Call.func; empty string if unknown."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _callable_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _has_kwarg_true(node: ast.Call, name: str) -> bool:
    for kw in node.keywords:
        if (kw.arg == name
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True):
            return True
    return False


def _literal_str(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_forbidden_path(path: str) -> bool:
    p = path.strip()
    if not p.startswith("/"):
        return False
    if any(p.startswith(exc) for exc in _FORBIDDEN_DEV_EXCEPTIONS):
        return False
    if p.startswith("/dev"):
        return True
    return p.startswith(_FORBIDDEN_FS_PREFIXES)


def _is_shell_invocation_target(node: ast.expr | None) -> bool:
    s = _literal_str(node)
    if s is None:
        return False
    s = s.strip()
    if s.endswith("/sh") or s.endswith("/bash"):
        return True
    return s in _SHELL_INTERPRETERS


def _trace_path_literal(node: ast.expr | None) -> str | None:
    """If `node` is Path('/some/literal'), return that literal. Else None."""
    if not isinstance(node, ast.Call):
        return None
    if _callable_name(node.func) not in ("Path", "pathlib.Path"):
        return None
    if not node.args:
        return None
    return _literal_str(node.args[0])
