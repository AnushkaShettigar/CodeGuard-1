import ast

class PyVisitor(ast.NodeVisitor):
    def __init__(self):
        self.hits = []
    def _hit(self, node, cat, w, why):
        self.hits.append({"id": f"AST_{cat.upper()}", "category": cat,
                          "weight": w, "line": getattr(node, "lineno", 1),
                          "reason": why})
    def visit_Call(self, node):
        f = node.func
        name = ""
        if isinstance(f, ast.Name): name = f.id
        elif isinstance(f, ast.Attribute): name = f.attr
        args = ""
        for a in node.args:
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                args += a.value
        if name in ("eval", "exec"):
            self._hit(node, "obfuscated_execution", 0.85, f"{name}() call")
        if name == "system" and "rm -rf" in args:
            self._hit(node, "destructive_command", 0.95, "os.system rm -rf")
        if name == "setuid":
            self._hit(node, "persistence_or_privesc", 0.9, "setuid call")
        self.generic_visit(node)
    def visit_While(self, node):
        if isinstance(node.test, ast.Constant) and node.test.value is True:
            has_break = any(isinstance(n, ast.Break) for n in ast.walk(node))
            if not has_break:
                self._hit(node, "resource_exhaustion", 0.85, "while True without break")
        self.generic_visit(node)

def scan(code: str):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    v = PyVisitor()
    v.visit(tree)
    return v.hits
