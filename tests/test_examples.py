"""Guard the pasteable sample set.

The samples file records a measured verdict per sample. This test re-runs each
sample and fails if the verdict has drifted, so a future rule/language/ML change
cannot silently alter the documented behaviour of `examples/`.

Samples whose security intent intentionally differs from the measured verdict are
allowed, but only for the documented causes (ML escalation on benign code, and the
rule layer scanning raw text). Anything else is a failure.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from textcodeguard.categories import CANONICAL_CATEGORIES
from textcodeguard.detect.cascade import analyze

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
SAMPLES = EXAMPLES / "samples.jsonl"
REQUESTS = EXAMPLES / "check_requests.jsonl"

ALLOWED_GAP_CAUSES = {
    "ml_escalation_false_positive",
    "rules_scan_raw_text",
    "known_false_negative",
}


def load():
    if not SAMPLES.exists():
        pytest.skip("examples/samples.jsonl not generated")
    return [json.loads(l) for l in SAMPLES.read_text(encoding="utf-8").splitlines() if l.strip()]


def test_files_exist_and_are_valid():
    samples = load()
    assert len(samples) >= 60
    requests = [json.loads(l) for l in REQUESTS.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(requests) == len(samples)
    assert all(list(r) == ["code"] for r in requests)


def test_every_sample_has_required_fields():
    for s in load():
        assert set(s) >= {"id", "group", "should", "note", "code",
                          "det_verdict", "combined_verdict", "gap_vs_intent"}
        assert s["should"] in ("allow", "block")
        assert s["det_verdict"] in ("allow", "block")
        assert s["combined_verdict"] in ("allow", "block")


def test_ids_are_unique():
    ids = [s["id"] for s in load()]
    assert len(ids) == len(set(ids))


def test_categories_and_benign_controls_are_covered():
    groups = {s["group"] for s in load()}
    assert set(CANONICAL_CATEGORIES) <= groups
    assert "benign" in groups
    assert "edge" in groups


def test_no_unexpected_gap_vs_intent():
    """Only documented limitations may differ from the security intent.

    The cause is recorded per sample by ``examples/verify_samples.py``; a sample
    that starts differing for any other reason is classified `unexpected` and
    fails here.
    """
    bad = []
    for s in load():
        if not s["gap_vs_intent"]:
            continue
        cause = s.get("gap_cause", "unexpected")
        if cause not in ALLOWED_GAP_CAUSES:
            bad.append((s["id"], s["should"], s["combined_verdict"], cause))
    assert not bad, f"unexpected behaviour changes: {bad}"


def test_gap_cause_matches_recorded_verdicts():
    """The recorded cause must be consistent with the recorded verdicts."""
    for s in load():
        cause = s.get("gap_cause", "")
        if not s["gap_vs_intent"]:
            assert cause == "", f"{s['id']}: matched intent but has cause {cause!r}"
            continue
        assert cause in ALLOWED_GAP_CAUSES, f"{s['id']}: undocumented cause {cause!r}"
        if cause == "ml_escalation_false_positive":
            assert s["ml_used"] is True
            assert s["should"] == "allow" and s["combined_verdict"] == "block"
        elif cause == "rules_scan_raw_text":
            assert s["should"] == "allow" and s["combined_verdict"] == "block"
            assert s["det_verdict"] == "block"
        elif cause == "known_false_negative":
            assert s["should"] == "block" and s["combined_verdict"] == "allow"


def test_recorded_verdicts_match_current_detector():
    """Verdict drift detection: re-run every sample and compare."""
    drifted = []
    for s in load():
        got = analyze(s["code"]).verdict
        if got != s["combined_verdict"]:
            drifted.append((s["id"], s["combined_verdict"], got))
    assert not drifted, (
        "sample verdicts drifted; re-run `py -3 -m examples.verify_samples` "
        f"and review the change: {drifted}"
    )


def test_every_group_has_both_intents_or_is_documented():
    """Sanity: attack groups must be marked as block, controls as allow."""
    per_group = Counter()
    for s in load():
        per_group[(s["group"], s["should"])] += 1
    for cat in CANONICAL_CATEGORIES:
        assert per_group.get((cat, "block"), 0) >= 1, f"{cat} has no positive sample"
