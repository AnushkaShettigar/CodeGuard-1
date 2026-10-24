"""Static Python AST analysis.

Scope and honesty:
* This is **syntactic** analysis. It inspects call nodes, resolved simple import
  aliases, literal string arguments on those calls, and ``while`` loops. It does
  not perform data-flow or taint analysis, and it never executes the snippet.
* Simple import aliases are resolved (``import os as o``, ``from os import
  system as s``). Dynamic/indirect calls (``getattr``, variables holding
  functions, ``*args`` unpacking) are not resolved.
* Attribute calls are matched on the resolved module + final attribute name so
  that an unrelated ``something.system()`` is not treated as ``os.system()``.
* String literals and comments that merely *look* dangerous are ignored; only
  string arguments passed to a recognised call are inspected.
"""

from __future__ import annotations

import ast

# Function names that are dangerous regardless of the object they are called on.
DANGEROUS_NAMES = {"eval", "exec"}
# (module, attr) pairs accepted for each check. A ``None`` module means the
# receiver could not be resolved statically, in which case we stay conservative
# and still flag the call.
SYSTEM_MODULES = {None, "os", "subprocess"}
SETUID_MODULES = {None, "os"}


class PyVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[dict] = []
        self.aliases: dict[str, str] = {}

    # -- helpers ----------------------------------------------------------
    def _hit(self, node, cat, weight, why):
        self.hits.append(
            {
                "id": f"AST_{cat.upper()}",
                "category": cat,
                "weight": weight,
                "line": getattr(node, "lineno", 1),
                "reason": why,
            }
        )

    def _resolve(self, name: str) -> str:
        return self.aliases.get(name, name)

    def _call_target(self, func) -> tuple[str | None, str]:
        """Return ``(module, final_name)`` for a call target, or ``(None, "")``."""
        if isinstance(func, ast.Name):
            return None, self._resolve(func.id)
        if isinstance(func, ast.Attribute):
            module = None
            if isinstance(func.value, ast.Name):
                module = self._resolve(func.value.id)
            return module, func.attr
        return None, ""

    @staticmethod
    def _literal_args(node) -> str:
        parts = []
        for a in node.args:
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                parts.append(a.value)
        return "".join(parts)

    # -- imports ----------------------------------------------------------
    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.aliases[local] = alias.name.split(".")[-1] if alias.asname else alias.name.split(".")[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            self.aliases[local] = alias.name
        self.generic_visit(node)

    # -- calls ------------------------------------------------------------
    def visit_Call(self, node):
        module, name = self._call_target(node.func)
        args = self._literal_args(node)

        if name in DANGEROUS_NAMES:
            self._hit(node, "obfuscated_execution", 0.85, f"{name}() call")
        if name == "system" and "rm -rf" in args and module in SYSTEM_MODULES:
            self._hit(node, "destructive_command", 0.95, "os.system rm -rf")
        if name == "setuid" and module in SETUID_MODULES:
            self._hit(node, "persistence_or_privesc", 0.9, "setuid call")
        self.generic_visit(node)

    # -- loops ------------------------------------------------------------
    def _has_own_break(self, node) -> bool:
        """True when ``node`` contains a ``break`` that belongs to *this* loop.

        Nested loops and nested function/lambda scopes are not descended into, so
        an inner loop's ``break`` does not terminate the outer loop.
        """
        nested_scopes = (
            ast.While,
            ast.For,
            ast.AsyncFor,
            ast.FunctionDef,
            ast.AsyncFunctionDef,
            ast.Lambda,
        )
        for child in ast.iter_child_nodes(node):
            if isinstance(child, nested_scopes):
                continue
            if isinstance(child, ast.Break):
                return True
            if self._has_own_break(child):
                return True
        return False

    def visit_While(self, node):
        is_forever = isinstance(node.test, ast.Constant) and node.test.value is True
        if is_forever and not self._has_own_break(node):
            self._hit(node, "resource_exhaustion", 0.85, "while True without break")
        self.generic_visit(node)


def scan(code: str) -> list[dict]:
    """Return AST findings for ``code``; ``[]`` for anything that is not Python."""
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, MemoryError):
        return []
    visitor = PyVisitor()
    visitor.visit(tree)
    for hit in visitor.hits:
        hit["source"] = "ast"
    return visitor.hits
