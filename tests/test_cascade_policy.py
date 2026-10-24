"""Decision-policy tests: explicit, conservative and testable.

ML is stubbed here so the assertions do not depend on the trained model's exact
scores.
"""

from __future__ import annotations

import pytest

from textcodeguard.detect import cascade
from textcodeguard.detect import ml

HIGH_CONFIDENCE_RISKY = 'import os\nos.system("rm -rf /")\n'
CLEAN = "print('hello world')\n"


@pytest.fixture
def stub_ml(monkeypatch):
    """Install a deterministic ML stub; returns a setter."""

    def _set(score, decision=0.5, escalate=0.5):
        monkeypatch.setattr(cascade.ml, "score", lambda code: score)
        monkeypatch.setattr(cascade.ml, "thresholds", lambda: (decision, escalate))

    return _set


def test_high_confidence_rule_blocks_regardless_of_low_ml(stub_ml):
    stub_ml(score=0.0)
    explained = cascade.analyze_explained(HIGH_CONFIDENCE_RISKY)
    assert explained["response"].verdict == "block"
    assert explained["ml_used"] is False
    assert explained["response"].risk_score >= 0.8


def test_low_ml_cannot_cancel_a_deterministic_block(stub_ml):
    """The core safety property: ML never downgrades a deterministic block."""
    for score in (0.0, 0.1, 0.49):
        stub_ml(score=score)
        assert cascade.analyze_explained(HIGH_CONFIDENCE_RISKY)["response"].verdict == "block"


def test_ml_escalates_clean_code_by_default(stub_ml):
    stub_ml(score=0.99, escalate=0.58)
    explained = cascade.analyze_explained(CLEAN)
    assert explained["response"].verdict == "block"
    assert explained["ml_used"] is True
    assert "ml_escalation" in explained["response"].reason
    # deterministic score is untouched by ML
    assert explained["response"].risk_score == 0.0


def test_ml_below_escalate_threshold_does_not_block(stub_ml):
    stub_ml(score=0.57, escalate=0.58)
    explained = cascade.analyze_explained(CLEAN)
    assert explained["response"].verdict == "allow"
    assert explained["ml_used"] is False
    assert explained["response"].ml_score == pytest.approx(0.57)


def test_escalate_threshold_exactly_met_blocks(stub_ml):
    stub_ml(score=0.58, escalate=0.58)
    assert cascade.analyze_explained(CLEAN)["response"].verdict == "block"


def test_off_mode_never_escalates(stub_ml):
    stub_ml(score=1.0)
    explained = cascade.analyze_explained(CLEAN, ml_escalate_mode="off")
    assert explained["response"].verdict == "allow"
    assert explained["ml_used"] is False


def test_corroborated_mode_requires_a_deterministic_finding(stub_ml):
    stub_ml(score=1.0)
    assert cascade.analyze_explained(CLEAN, ml_escalate_mode="corroborated")["response"].verdict == "allow"
    assert (
        cascade.analyze_explained(HIGH_CONFIDENCE_RISKY, ml_escalate_mode="corroborated")[
            "response"
        ].verdict
        == "block"
    )


def test_invalid_mode_raises():
    with pytest.raises(ValueError):
        cascade.analyze_explained(CLEAN, ml_escalate_mode="sometimes")


def test_missing_model_is_transparent(monkeypatch, tmp_path):
    monkeypatch.setenv("CODEGUARD_MODEL_PATH", str(tmp_path / "does_not_exist.joblib"))
    ml.reset_cache()
    try:
        explained = cascade.analyze_explained(CLEAN)
        assert explained["response"].ml_available is False
        assert explained["response"].ml_score is None
        assert explained["response"].verdict == "allow"
        # deterministic detection still works
        assert cascade.analyze_explained(HIGH_CONFIDENCE_RISKY)["response"].verdict == "block"
    finally:
        ml.reset_cache()


def test_ml_disabled_flag():
    explained = cascade.analyze_explained(CLEAN, use_ml=False)
    assert explained["response"].ml_available is False
    assert explained["response"].ml_score is None


def test_risk_score_threshold_blocks():
    """Two corroborating weak-ish findings cross the 0.60 noisy-OR threshold."""
    code = 'import requests\nrequests.get(url, timeout=5).text[:500]\n'
    explained = cascade.analyze_explained(code, use_ml=False)
    assert explained["det_risk"] >= 0.6
    assert explained["response"].verdict == "block"


def test_duplicate_findings_are_not_double_counted():
    code = 'import os\nos.system("rm -rf /")\nos.system("rm -rf /")\n'
    explained = cascade.analyze_explained(code, use_ml=False)
    # one rule hit + the AST hit, deduplicated by (id, line)
    keys = [(h["id"], h["line"]) for h in explained["findings"]]
    assert len(keys) == len(set(keys))
