from textcodeguard.detect.language import detect_language
from textcodeguard.detect.rules import scan as rule_scan
from textcodeguard.detect.ast_python import scan as py_ast_scan
from textcodeguard.schema import CheckResponse

def analyze(code: str) -> CheckResponse:
    lang = detect_language(code)
    hits = rule_scan(code, lang)
    if lang == "python":
        hits += py_ast_scan(code)
    if not hits:
        return CheckResponse(verdict="allow", risk_score=0.0, categories=[],
                             code_language=lang, reason="no rules fired",
                             vulnerable_lines=[])
    p_safe = 1.0
    for h in hits: p_safe *= (1 - h["weight"])
    risk = round(1 - p_safe, 2)
    cats = sorted({h["category"] for h in hits})
    lines = sorted({h["line"] for h in hits})
    reason = "; ".join(h["reason"] for h in hits[:3])
    blocked = any(h["weight"] >= 0.8 for h in hits) or risk >= 0.6
    return CheckResponse(
        verdict="block" if blocked else "allow",
        risk_score=risk, categories=cats, code_language=lang,
        reason=reason, vulnerable_lines=lines,
    )
