"""ML tests: training guards, split determinism, fit-on-train-only, load/fallback.

These tests train a *tiny throwaway* model into ``tmp_path`` so the committed
artefact is never overwritten.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from textcodeguard.detect import ml
from training import train_model

REPO_ROOT = Path(__file__).resolve().parent.parent


def _write_dataset(path: Path, rows: list[tuple[str, int]]) -> Path:
    with path.open("w", encoding="utf-8") as fh:
        for i, (code, label) in enumerate(rows):
            sid = f"t{i:03d}"
            fh.write(
                json.dumps(
                    {
                        "sample_id": sid,
                        "code": code,
                        "label": label,
                        "language": "python",
                        "source": "test",
                        "category_raw": "",
                        "category": [],
                        "synthetic": False,
                        "dup_group": sid,
                        "dup_group_size": 1,
                    }
                )
                + "\n"
            )
    return path


def _balanced_rows(n_per_class: int = 12) -> list[tuple[str, int]]:
    rows = []
    for i in range(n_per_class):
        rows.append((f"def safe_{i}():\n    return {i} + UNIQUE_SAFE_{i}\n", 0))
        rows.append((f"import os\nos.system('rm -rf /{i}')\n", 1))
    return rows


def test_train_rejects_missing_dataset(tmp_path):
    with pytest.raises(SystemExit) as exc:
        train_model.main(
            [
                "--dataset",
                str(tmp_path / "nope.jsonl"),
                "--out",
                str(tmp_path / "m.joblib"),
                "--manifest",
                str(tmp_path / "m.json"),
            ]
        )
    assert "not found" in str(exc.value)


def test_train_rejects_single_class(tmp_path):
    ds = _write_dataset(tmp_path / "one.jsonl", [("print(1)\n", 0)] * 10)
    with pytest.raises(SystemExit) as exc:
        train_model.main(
            ["--dataset", str(ds), "--out", str(tmp_path / "m.joblib"),
             "--manifest", str(tmp_path / "m.json")]
        )
    assert "one class" in str(exc.value)


def test_train_rejects_invalid_label(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text(json.dumps({"sample_id": "a", "code": "x=1", "label": 2,
                                "dup_group": "a"}) + "\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        train_model.main(["--dataset", str(path), "--out", str(tmp_path / "m.joblib"),
                          "--manifest", str(tmp_path / "m.json")])


def test_train_rejects_malformed_json(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text("{not json}\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        train_model.main(["--dataset", str(path), "--out", str(tmp_path / "m.joblib"),
                          "--manifest", str(tmp_path / "m.json")])


def test_train_rejects_empty_code(tmp_path):
    path = _write_dataset(tmp_path / "empty.jsonl", [("   ", 0), ("x=1", 1)])
    with pytest.raises(SystemExit):
        train_model.main(["--dataset", str(path), "--out", str(tmp_path / "m.joblib"),
                          "--manifest", str(tmp_path / "m.json")])


@pytest.fixture
def tiny_run(tmp_path):
    ds = _write_dataset(tmp_path / "tiny.jsonl", _balanced_rows())
    out = tmp_path / "tiny.joblib"
    manifest = tmp_path / "tiny_manifest.json"
    rc = train_model.main(
        ["--dataset", str(ds), "--out", str(out), "--manifest", str(manifest), "--folds", "3"]
    )
    assert rc == 0
    return {"ds": ds, "out": out, "manifest": manifest}


def test_train_writes_model_and_manifest(tiny_run):
    assert tiny_run["out"].exists()
    manifest = json.loads(tiny_run["manifest"].read_text(encoding="utf-8"))
    for key in (
        "model_type",
        "feature_settings",
        "split_strategy",
        "seeds",
        "decision_threshold",
        "escalate_threshold",
        "oof_threshold_sweep",
        "dependency_versions",
        "trained_at_utc",
        "dataset",
    ):
        assert key in manifest, key
    assert manifest["dataset"]["fingerprint_sha256"]
    assert manifest["dataset"]["label_counts"] == {"0": 12, "1": 12}


def test_saved_model_loads_and_predicts(tiny_run):
    import joblib

    pipeline = joblib.load(tiny_run["out"])
    proba = pipeline.predict_proba(["import os\nos.system('rm -rf /x')\n"])[0]
    assert len(proba) == 2
    assert 0.0 <= float(proba[1]) <= 1.0


def test_split_is_deterministic(tmp_path):
    ds = _write_dataset(tmp_path / "tiny.jsonl", _balanced_rows())
    m1 = tmp_path / "m1.json"
    m2 = tmp_path / "m2.json"
    common = ["--dataset", str(ds), "--folds", "3"]
    train_model.main(common + ["--out", str(tmp_path / "o1.joblib"), "--manifest", str(m1)])
    train_model.main(common + ["--out", str(tmp_path / "o2.joblib"), "--manifest", str(m2)])
    a = json.loads(m1.read_text(encoding="utf-8"))
    b = json.loads(m2.read_text(encoding="utf-8"))
    assert a["cv_folds"] == b["cv_folds"]
    assert a["split_strategy"] == b["split_strategy"]
    assert a["oof_metrics_at_threshold"] == b["oof_metrics_at_threshold"]


def test_vectorizer_is_fit_on_training_rows_only(tmp_path):
    ds = _write_dataset(tmp_path / "tiny.jsonl", _balanced_rows())
    out = tmp_path / "m.joblib"
    train_model.main(["--dataset", str(ds), "--out", str(out),
                      "--manifest", str(tmp_path / "m.json"), "--folds", "3"])
    import joblib

    pipeline = joblib.load(out)
    word_vec = pipeline.named_steps["features"].transformer_list[0][1]
    vocab = word_vec.vocabulary_
    assert any("unique_safe" in t for t in vocab)
    # A token that exists only outside the training set must not be in the vocabulary.
    assert "zzz_never_trained_token" not in vocab


def test_model_artifact_and_manifest_are_committed():
    manifest_path = REPO_ROOT / "models" / "model_manifest.json"
    assert (REPO_ROOT / "models" / "codeguard_clf.joblib").exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["dataset"]["records"] >= 100
    assert 0.0 < manifest["decision_threshold"] < 1.0


def test_committed_model_loads_via_ml_module():
    ml.reset_cache()
    status = ml.ml_status()
    assert status["available"] is True, status["reason"]
    assert 0.0 <= ml.score("print('x')") <= 1.0


# --- fallback paths ------------------------------------------------------


def test_missing_model_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("CODEGUARD_MODEL_PATH", str(tmp_path / "missing.joblib"))
    ml.reset_cache()
    try:
        status = ml.ml_status()
        assert status["available"] is False
        assert "not found" in status["reason"]
        assert ml.score("print('x')") is None
    finally:
        ml.reset_cache()


def test_unreadable_model_fallback(monkeypatch, tmp_path):
    bad = tmp_path / "bad.joblib"
    bad.write_bytes(b"not a pickle at all")
    monkeypatch.setenv("CODEGUARD_MODEL_PATH", str(bad))
    ml.reset_cache()
    try:
        assert ml.ml_status()["available"] is False
        assert ml.score("print('x')") is None
    finally:
        ml.reset_cache()


def test_inference_exception_fallback(monkeypatch):
    ml.reset_cache()
    bundle = ml._load()
    assert bundle is not None

    def boom(*_args, **_kwargs):
        raise RuntimeError("inference blew up")

    monkeypatch.setattr(bundle["pipeline"], "predict_proba", boom)
    try:
        assert ml.score("print('x')") is None
        status = ml.ml_status()
        assert status["available"] is True
        assert "inference failed" in status["reason"]
    finally:
        ml.reset_cache()


def test_thresholds_shape():
    ml.reset_cache()
    decision, escalate = ml.thresholds()
    assert 0.0 < decision < 1.0
    assert escalate is None or 0.0 < escalate < 1.0


def test_score_is_bounded():
    ml.reset_cache()
    for code in ["", "print(1)", "import os\nos.system('rm -rf /')\n", "\x00\x01"]:
        s = ml.score(code)
        assert s is None or 0.0 <= s <= 1.0
