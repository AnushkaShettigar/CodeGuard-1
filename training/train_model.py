"""Train the CodeGuard classical-ML classifier.

Model: a scikit-learn ``Pipeline`` of a TF-IDF ``FeatureUnion`` (word + character
n-grams) feeding a class-weighted ``LogisticRegression``. CPU only, deterministic,
no network, no LLM/SLM.

Data: ``training/merged_dataset.jsonl`` produced by ``training.build_dataset``.

Split strategy (see manifest for the recorded values):

* Model/threshold selection uses **grouped stratified cross-validation** on the
  training pool only. ``dup_group`` keeps near-duplicates in the same fold so a
  near-duplicate pair cannot appear in both the fit and the validation part.
* The decision threshold is chosen on out-of-fold predictions only.
* The evaluation files (``dev.jsonl``, ``unseen.jsonl``, ``hard_eval.jsonl``) are
  never read here, so no test example influences the vectorizer vocabulary, the
  coefficients, or the threshold.

Run::

    py -3 -m training.train_model
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_DATASET = REPO_ROOT / "training" / "merged_dataset.jsonl"
MODEL_DIR = REPO_ROOT / "models"
MODEL_PATH = MODEL_DIR / "codeguard_clf.joblib"
MANIFEST_PATH = MODEL_DIR / "model_manifest.json"

SEED = 42


def _relative(path: Path) -> str:
    """Repo-relative path when possible, else the absolute path (for temp outputs)."""
    try:
        return str(path.relative_to(REPO_ROOT)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def _require_sklearn():
    try:
        import joblib
        import numpy as np
        import sklearn
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict
        from sklearn.pipeline import FeatureUnion, Pipeline
    except ImportError as exc:  # pragma: no cover - environment guard
        raise SystemExit(
            "ERROR: scikit-learn, joblib and numpy are required to train the model. "
            "Install them with: py -3 -m pip install -r requirements.txt"
        ) from exc
    return dict(
        joblib=joblib,
        np=np,
        sklearn=sklearn,
        TfidfVectorizer=TfidfVectorizer,
        LogisticRegression=LogisticRegression,
        StratifiedGroupKFold=StratifiedGroupKFold,
        cross_val_predict=cross_val_predict,
        FeatureUnion=FeatureUnion,
        Pipeline=Pipeline,
    )


def load_dataset(path: Path) -> tuple[list[str], list[int], list[str], list[dict], str]:
    if not path.exists():
        raise SystemExit(
            f"ERROR: training dataset not found at {path}. "
            "Run `py -3 -m training.build_dataset` first."
        )
    records: list[dict] = []
    with path.open(encoding="utf-8-sig") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"ERROR: malformed JSON on line {lineno} of {path}: {exc}") from exc
            for field in ("code", "label", "sample_id", "dup_group"):
                if field not in rec:
                    raise SystemExit(f"ERROR: line {lineno} of {path} is missing '{field}'.")
            if rec["label"] not in (0, 1):
                raise SystemExit(f"ERROR: line {lineno} has invalid label {rec['label']!r}.")
            if not isinstance(rec["code"], str) or not rec["code"].strip():
                raise SystemExit(f"ERROR: line {lineno} has an empty code field.")
            records.append(rec)

    if not records:
        raise SystemExit(f"ERROR: training dataset {path} is empty.")

    labels = [r["label"] for r in records]
    if len(set(labels)) < 2:
        raise SystemExit(
            "ERROR: training dataset has only one class "
            f"({sorted(set(labels))}); a binary classifier cannot be trained."
        )

    texts = [r["code"] for r in records]
    groups = [r["dup_group"] for r in records]
    fingerprint = hashlib.sha256(path.read_bytes()).hexdigest()
    return texts, labels, groups, records, fingerprint


def build_pipeline(sk):
    word = sk["TfidfVectorizer"](
        analyzer="word",
        ngram_range=(1, 2),
        token_pattern=r"[A-Za-z_][A-Za-z0-9_]*",
        lowercase=True,
        sublinear_tf=True,
        min_df=1,
    )
    char = sk["TfidfVectorizer"](
        analyzer="char_wb",
        ngram_range=(3, 5),
        lowercase=True,
        sublinear_tf=True,
        min_df=1,
    )
    features = sk["FeatureUnion"]([("word", word), ("char", char)])
    clf = sk["LogisticRegression"](
        C=1.0,
        class_weight="balanced",
        solver="liblinear",
        max_iter=2000,
        random_state=SEED,
    )
    return sk["Pipeline"]([("features", features), ("clf", clf)])


ESCALATE_PRECISION_FLOOR = 0.90


def sweep_thresholds(y_true, scores) -> list[dict]:
    """Compute precision/recall/F1 for every threshold in 0.05..0.95 on OOF scores."""
    sweep = []
    for step in range(5, 96):
        t = step / 100.0
        tp = fp = fn = tn = 0
        for y, s in zip(y_true, scores):
            pred = 1 if s >= t else 0
            if y == 1 and pred == 1:
                tp += 1
            elif y == 0 and pred == 1:
                fp += 1
            elif y == 1 and pred == 0:
                fn += 1
            else:
                tn += 1
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        row = {
            "threshold": round(t, 2),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }
        sweep.append(row)
    return sweep


def _pick_f1(sweep: list[dict]) -> dict:
    """F1-maximising threshold; ties broken by recall, then closeness to 0.5."""
    return max(sweep, key=lambda r: (r["f1"], r["recall"], -abs(r["threshold"] - 0.5)))


def _pick_precision_floor(sweep: list[dict], floor: float) -> dict | None:
    """Highest-recall threshold subject to precision >= floor, or None if unreachable.

    This is the conservative operating point used for cascade escalation: the ML
    layer may only block on its own when its precision on out-of-fold data is at
    least ``floor``.
    """
    eligible = [r for r in sweep if r["precision"] >= floor and r["recall"] > 0]
    if not eligible:
        return None
    return max(eligible, key=lambda r: (r["recall"], r["f1"], -abs(r["threshold"] - 0.5)))


def choose_threshold(y_true, scores) -> dict:
    """Select the model's decision point and the conservative escalation point."""
    sweep = sweep_thresholds(y_true, scores)
    return {
        "best": _pick_f1(sweep),
        "escalate": _pick_precision_floor(sweep, ESCALATE_PRECISION_FLOOR),
        "sweep": sweep,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the CodeGuard classical ML classifier.")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--out", type=Path, default=MODEL_PATH)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args(argv)

    sk = _require_sklearn()
    np = sk["np"]

    texts, labels, groups, records, fingerprint = load_dataset(args.dataset)
    y = np.asarray(labels)

    n_groups = len(set(groups))
    n_splits = args.folds
    if n_groups < n_splits or min(np.bincount(y)) < n_splits:
        n_splits = max(2, min(n_groups, int(min(np.bincount(y)))))
        print(f"note: reduced CV folds to {n_splits} because of limited grouped data")

    cv = sk["StratifiedGroupKFold"](n_splits=n_splits, shuffle=True, random_state=args.seed)
    pipeline = build_pipeline(sk)

    # Out-of-fold scores from a copy fit only on each fold's training rows.
    oof = sk["cross_val_predict"](
        pipeline, texts, y, groups=groups, cv=cv, method="predict_proba", n_jobs=1
    )[:, 1]

    threshold_info = choose_threshold(labels, oof)
    threshold = threshold_info["best"]["threshold"]
    escalate = threshold_info["escalate"]
    escalate_threshold = escalate["threshold"] if escalate else None

    def _metrics(y_true, scores, t):
        tp = fp = fn = tn = 0
        for yy, s in zip(y_true, scores):
            pred = 1 if s >= t else 0
            if yy == 1 and pred == 1:
                tp += 1
            elif yy == 0 and pred == 1:
                fp += 1
            elif yy == 1 and pred == 0:
                fn += 1
            else:
                tn += 1
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        accuracy = (tp + tn) / max(1, tp + tn + fp + fn)
        return {
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
            "accuracy": round(accuracy, 4),
            "precision_risky": round(precision, 4),
            "recall_risky": round(recall, 4),
            "f1_risky": round(f1, 4),
            "fpr": round(fp / (fp + tn), 4) if fp + tn else 0.0,
            "fnr": round(fn / (fn + tp), 4) if fn + tp else 0.0,
        }

    fold_metrics = []
    fold_sizes = []
    for fold, (tr, va) in enumerate(cv.split(texts, y, groups), 1):
        fold_pipe = build_pipeline(sk)
        fold_pipe.fit([texts[i] for i in tr], y[tr])
        scores = fold_pipe.predict_proba([texts[i] for i in va])[:, 1]
        fold_metrics.append(_metrics(y[va], scores, threshold))
        fold_sizes.append(
            {
                "fold": fold,
                "train": len(tr),
                "validation": len(va),
                "label_validation": dict(
                    sorted((str(k), int(v)) for k, v in zip(*np.unique(y[va], return_counts=True)))
                ),
            }
        )

    final_pipeline = build_pipeline(sk)
    final_pipeline.fit(texts, y)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    sk["joblib"].dump(final_pipeline, args.out)

    try:
        import scipy

        scipy_version = scipy.__version__
    except ImportError:  # pragma: no cover
        scipy_version = "absent"

    try:
        import joblib as _joblib

        joblib_version = _joblib.__version__
    except ImportError:  # pragma: no cover
        joblib_version = "absent"

    manifest = {
        "artifact": _relative(args.out),
        "artifact_bytes": args.out.stat().st_size,
        "model_type": "sklearn Pipeline(FeatureUnion(TfidfVectorizer word(1,2), "
        "TfidfVectorizer char_wb(3,5)) -> LogisticRegression(balanced, liblinear))",
        "feature_settings": {
            "word": {"ngram_range": [1, 2], "sublinear_tf": True, "min_df": 1, "lowercase": True},
            "char": {
                "ngram_range": [3, 5],
                "analyzer": "char_wb",
                "sublinear_tf": True,
                "min_df": 1,
                "lowercase": True,
            },
        },
        "classifier_settings": {
            "C": 1.0,
            "class_weight": "balanced",
            "solver": "liblinear",
            "max_iter": 2000,
        },
        "decision_threshold": threshold,
        "escalate_threshold": escalate_threshold,
        "escalate_precision_floor": ESCALATE_PRECISION_FLOOR,
        "threshold_selection": {
            "decision_threshold": "F1-maximising on out-of-fold grouped CV scores (tie-break: recall)",
            "escalate_threshold": (
                f"highest-recall out-of-fold threshold with precision >= {ESCALATE_PRECISION_FLOOR}; "
                "used by the cascade so ML can only block on its own when it is precise"
            ),
        },
        "split_strategy": f"StratifiedGroupKFold(n_splits={n_splits}, shuffle=True), grouped by dup_group",
        "seeds": {"split_and_model": args.seed},
        "cv_folds": fold_sizes,
        "cv_fold_metrics_at_threshold": fold_metrics,
        "oof_metrics_at_threshold": _metrics(labels, oof, threshold),
        "oof_metrics_at_escalate": (
            _metrics(labels, oof, escalate_threshold) if escalate_threshold is not None else None
        ),
        "oof_threshold_sweep": threshold_info["sweep"],
        "oof_threshold_sweep_best": threshold_info["best"],
        "dataset": {
            "path": _relative(args.dataset),
            "fingerprint_sha256": fingerprint,
            "records": len(records),
            "label_counts": {
                str(k): int(v) for k, v in zip(*np.unique(y, return_counts=True))
            },
            "source_counts": {
                k: sum(1 for r in records if r["source"] == k) for k in sorted({r["source"] for r in records})
            },
            "groups": len(set(groups)),
        },
        "dependency_versions": {
            "python": platform.python_version(),
            "scikit-learn": sk["sklearn"].__version__,
            "numpy": np.__version__,
            "scipy": scipy_version,
            "joblib": joblib_version,
        },
        "trained_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "train_command": "py -3 -m training.train_model",
        "notes": [
            "Probabilities are the logistic-regression output; they are NOT calibrated "
            "and must not be presented as real-world probabilities.",
            "The evaluation files dev.jsonl, unseen.jsonl and hard_eval.jsonl were never "
            "read by this script.",
        ],
    }
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    m = manifest["oof_metrics_at_threshold"]
    print(f"dataset           : {args.dataset} ({len(records)} rows, groups={manifest['dataset']['groups']})")
    print(f"fingerprint       : {fingerprint[:16]}...")
    print(f"cv folds          : {n_splits} ({[f['validation'] for f in fold_sizes]} val rows)")
    print(f"threshold         : decision={threshold} escalate={escalate_threshold}")
    print(f"oof @ threshold   : acc={m['accuracy']} P={m['precision_risky']} "
          f"R={m['recall_risky']} F1={m['f1_risky']} (tn={m['tn']} fp={m['fp']} fn={m['fn']} tp={m['tp']})")
    print(f"model             : {args.out} ({manifest['artifact_bytes']} bytes)")
    print(f"manifest          : {args.manifest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
