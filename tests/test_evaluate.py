"""Evaluation-utility tests with hand-computed expectations."""

from __future__ import annotations

import json
from pathlib import Path

from textcodeguard.evaluate import (
    confusion,
    load_eval,
    per_category,
    redact,
)


def test_confusion_hand_computed():
    y_true = [True, True, False, False, True]
    y_pred = [True, False, True, False, True]
    m = confusion(y_true, y_pred)
    # tp=2, fn=1, fp=1, tn=1
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (2, 1, 1, 1)
    assert m["accuracy"] == round(3 / 5, 4)
    assert m["precision_risky"] == round(2 / 3, 4)
    assert m["recall_risky"] == round(2 / 3, 4)
    assert m["f1_risky"] == round(2 / 3, 4)
    assert m["precision_safe"] == round(1 / 2, 4)
    assert m["recall_safe"] == round(1 / 2, 4)
    assert m["false_positive_rate"] == round(1 / 2, 4)
    assert m["false_negative_rate"] == round(1 / 3, 4)
    assert m["n"] == 5


def test_confusion_all_correct():
    m = confusion([True, False], [True, False])
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (1, 0, 0, 1)
    assert m["accuracy"] == 1.0
    assert m["f1_risky"] == 1.0


def test_confusion_empty_is_safe():
    m = confusion([], [])
    assert m["n"] == 0
    assert m["accuracy"] == 0.0


def test_per_category_hand_computed():
    rows = [
        {"categories": {"secret_access"}},
        {"categories": set()},
        {"categories": {"secret_access"}},
    ]
    preds = [
        {"categories": ["secret_access"]},
        {"categories": ["secret_access"]},
        {"categories": []},
    ]
    out = per_category(rows, preds)
    assert out["secret_access"]["tp"] == 1
    assert out["secret_access"]["fp"] == 1
    assert out["secret_access"]["fn"] == 1
    assert out["secret_access"]["precision"] == 0.5
    assert out["secret_access"]["recall"] == 0.5


def test_load_eval_labelled_schema(tmp_path):
    path = tmp_path / "l.jsonl"
    path.write_text(
        json.dumps({"code": "x=1", "label": 1, "category": "secret_access", "language": "python"})
        + "\n"
        + json.dumps({"code": "y=1", "label": 0, "category": "benign", "language": "python"})
        + "\n",
        encoding="utf-8",
    )
    rows = load_eval(path)
    assert len(rows) == 2
    assert rows[0]["risky"] is True
    assert rows[0]["categories"] == {"secret_access"}
    assert rows[1]["risky"] is False
    assert rows[1]["categories"] == set()  # 'benign' is not a risk category


def test_load_eval_verdict_schema(tmp_path):
    path = tmp_path / "v.jsonl"
    path.write_text(
        json.dumps({"code": "x=1", "verdict": "block", "categories": ["ssrf_network_exfil"]})
        + "\n"
        + json.dumps({"code": "y=1", "verdict": "allow", "categories": []})
        + "\n",
        encoding="utf-8",
    )
    rows = load_eval(path)
    assert rows[0]["risky"] is True
    assert rows[0]["categories"] == {"ssrf_network_exfil"}
    assert rows[1]["risky"] is False


def test_load_eval_rejects_unknown_schema(tmp_path):
    path = tmp_path / "x.jsonl"
    path.write_text(json.dumps({"code": "x=1"}) + "\n", encoding="utf-8")
    try:
        load_eval(path)
    except SystemExit:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected SystemExit for a file with no label or verdict")


def test_redact_masks_likely_secrets():
    text = "KEY = 'AKIAABCDEFGHIJKLMNOP'\naws_secret_access_key='abcdefghij'"
    out = redact(text)
    assert "AKIAABCDEFGHIJKLMNOP" not in out
    assert "[REDACTED]" in out


def test_redact_truncates_and_flattens():
    out = redact("a\n" * 500)
    assert "\n" not in out
    assert len(out) <= 143


def test_redact_keeps_ordinary_code_readable():
    out = redact("import os\nos.system('rm -rf /')\n")
    assert "os.system" in out
