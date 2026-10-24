import ast, re

PY_KEYWORDS = re.compile(
    r"^\s*(def |class |import |from \w+ import |async def |print\(|"
    r"if __name__ ==|while |for \w+ in |with \w+|try:|except |raise |"
    r"return |yield |lambda |eval\(|exec\()",
    re.M,
)

def detect_language(code: str) -> str:
    s = code.strip()
    if s.startswith("#!"):
        first = s.splitlines()[0]
        if "python" in first: return "python"
        if "bash" in first or "/sh" in first: return "bash"
        if "node" in first: return "javascript"
    if PY_KEYWORDS.search(code):
        try:
            ast.parse(code)
            return "python"
        except SyntaxError:
            pass
    try:
        ast.parse(code)
        if re.search(r"\b\w+\s*\(.*\)|\w+\s*=\s*", code):
            return "python"
    except SyntaxError:
        pass
    if re.search(r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE\s+TABLE|ALTER)\b", code, re.I):
        return "sql"
    if re.search(r"^\s*[\w.-]+\s*:\s", code, re.M) and not re.search(r"[{};]", code):
        return "yaml"
    if re.search(r"\b(const|let|var|function|=>|require\(|import\s+.+\s+from)\b", code):
        return "javascript"
    if re.search(r"^\s*(sudo |curl |wget |rm |chmod |chown |apt |pip |npm |echo |cat )", code, re.M):
        return "bash"
    if re.search(r"^(#{1,6}\s|```|\- |\* )", code, re.M) or "<!--" in code:
        return "markdown"
    return "unknown"