"""Decision cascade: language -> rules -> Python AST -> classical ML.

The deterministic layers (rules + AST) are unchanged in behaviour: every finding
they produce is preserved. The ML layer is additive and can only *escalate* a
verdict, never cancel a deterministic finding.

Decision policy (explicit and testable):

1. ``det_high`` - any deterministic finding with weight >= 0.80. Always blocks.
2. ``det_risk`` - noisy-OR of all deterministic weights: ``1 - prod(1 - w)``.
   ``det_risk >= 0.60`` always blocks. Note this means a **single** finding of
   weight >= 0.60 also blocks (e.g. ``PY_SSRF_ARBITRARY_001`` at 0.75), which is a
   deliberate fail-closed choice; it is the documented source of the known
   false positive on benign code that fetches a caller-supplied URL.
3. Otherwise the ML layer may escalate to ``block`` when **all** hold:
   * ML is available,
   * the model has a conservative escalation threshold (precision floor met on
     out-of-fold training data),
   * ``ml_score >= escalate_threshold``.

   ``ml_escalate_mode`` controls the extra corroboration condition:

   * ``"any"`` (default) - no extra condition. ML may escalate any snippet above
     the conservative threshold. This is the shipped default: ML escalation is
     the only mechanism that closes the deterministic recall gap, and blocking is
     the fail-safe direction for a pre-execution gate.
   * ``"corroborated"`` - require at least one deterministic finding too. Note
     this mode is effectively inert with the current rule weights (the smallest
     weight is 0.70, which already crosses the 0.60 block threshold), and is kept
     only so the policy can be compared and tested.
   * ``"off"`` - ML never changes the verdict.

``risk_score`` is the **deterministic** noisy-OR score and keeps its original
meaning. The ML score is reported separately in ``ml_score`` and never changes
``risk_score``; it influences only the verdict (via ``ml_used``). A block whose
``risk_score`` is 0.0 therefore always has ``ml_used == True``.
"""

from __future__ import annotations

from textcodeguard.detect.ast_python import scan as py_ast_scan
from textcodeguard.detect.language import detect_language
from textcodeguard.detect.rules import scan as rule_scan
from textcodeguard.detect import ml
from textcodeguard.schema import CheckResponse

DET_BLOCK_WEIGHT = 0.80
DET_BLOCK_RISK = 0.60
DEFAULT_ML_MODE = "any"

ML_MODES = ("off", "corroborated", "any")


def _dedupe(hits: list[dict]) -> list[dict]:
    """Drop repeated findings with the same rule id at the same line."""
    seen = set()
    out = []
    for h in sorted(hits, key=lambda x: (x.get("line", 0), x.get("id", ""))):
        key = (h.get("id"), h.get("line"))
        if key in seen:
            continue
        seen.add(key)
        out.append(h)
    return out


def _noisy_or(hits: list[dict]) -> float:
    p_safe = 1.0
    for h in hits:
        p_safe *= 1.0 - float(h["weight"])
    return round(1.0 - p_safe, 2)


def collect_hits(code: str, lang: str | None = None, use_ast: bool = True) -> tuple[list[dict], str]:
    """Return de-duplicated deterministic findings and the detected language."""
    language = lang or detect_language(code)
    hits = list(rule_scan(code, language))
    if use_ast and language == "python":
        hits += py_ast_scan(code)
    return _dedupe(hits), language


def analyze(
    code: str,
    use_ast: bool = True,
    use_ml: bool = True,
    ml_escalate_mode: str = DEFAULT_ML_MODE,
) -> CheckResponse:
    """Run the full cascade and return the public response object."""
    return analyze_explained(
        code, use_ast=use_ast, use_ml=use_ml, ml_escalate_mode=ml_escalate_mode
    )["response"]


def analyze_explained(
    code: str,
    use_ast: bool = True,
    use_ml: bool = True,
    ml_escalate_mode: str = DEFAULT_ML_MODE,
) -> dict:
    """Extended result used by evaluation: response plus internal detail.

    Returns a dict with keys ``response`` (CheckResponse), ``findings`` (list of
    rule/AST hits), ``det_risk``, ``det_high``, ``ml_score``, ``ml_available``,
    ``ml_used`` and ``language``.
    """
    if ml_escalate_mode not in ML_MODES:
        raise ValueError(f"ml_escalate_mode must be one of {ML_MODES}, got {ml_escalate_mode!r}")

    hits, lang = collect_hits(code, use_ast=use_ast)
    det_risk = _noisy_or(hits) if hits else 0.0
    det_high = any(float(h["weight"]) >= DET_BLOCK_WEIGHT for h in hits)
    det_block = det_high or det_risk >= DET_BLOCK_RISK

    ml_available = False
    ml_score = None
    if use_ml:
        ml_score = ml.score(code)
        ml_available = ml_score is not None
    _, escalate_threshold = ml.thresholds() if use_ml else (None, None)

    ml_used = False
    if (
        use_ml
        and ml_escalate_mode != "off"
        and not det_block
        and ml_available
        and escalate_threshold is not None
        and ml_score >= escalate_threshold
        and (ml_escalate_mode == "any" or bool(hits))
    ):
        ml_used = True

    blocked = det_block or ml_used

    cats = sorted({h["category"] for h in hits})
    lines = sorted({int(h["line"]) for h in hits})
    reasons = [h["reason"] for h in hits[:3]]
    if ml_used:
        reasons.append(f"ml_escalation(score={ml_score:.3f} >= {escalate_threshold})")
    reason = "; ".join(reasons) if reasons else "no rules fired"

    response = CheckResponse(
        verdict="block" if blocked else "allow",
        risk_score=det_risk,
        categories=cats,
        code_language=lang,
        reason=reason,
        vulnerable_lines=lines,
        ml_score=round(ml_score, 4) if ml_score is not None else None,
        ml_available=ml_available,
        ml_used=ml_used,
    )

    return {
        "response": response,
        "findings": hits,
        "det_risk": det_risk,
        "det_high": det_high,
        "det_block": det_block,
        "ml_score": ml_score,
        "ml_available": ml_available,
        "ml_used": ml_used,
        "language": lang,
    }
