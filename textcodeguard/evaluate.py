"""Honest, leakage-aware evaluation for CodeGuard.

Reports, for the same examples, four detection configurations plus one policy
variant:

1. ``rules_only``      - regex rules, no AST, no ML
2. ``rules_ast``       - regex rules + Python AST, no ML
3. ``ml_only``         - classical ML score vs its decision threshold
4. ``combined``        - rules + AST + ML (ML escalation only on weak deterministic signal)
5. ``combined_any``    - rules + AST + ML (ML may also escalate with no deterministic finding)

Every configuration reports a confusion matrix, accuracy, precision/recall/F1 for
both classes, false-positive and false-negative rates. Per-category precision and
recall are reported for the combined configuration where canonical category labels
exist. Every false positive and false negative is listed with a redacted preview.

The script never uses the evaluation labels to fit or tune anything: model fitting
and threshold selection happen in ``training/train_model.py``.

Run::

    py -3 -m textcodeguard.evaluate dev.jsonl
    py -3 -m textcodeguard.evaluate hard_eval.jsonl --json results/hard_eval.json
    py -3 -m textcodeguard.evaluate training/merged_dataset.jsonl
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

from textcodeguard.categories import CANONICAL_SET, CANONICAL_CATEGORIES
from textcodeguard.detect import ml
from textcodeguard.detect.cascade import analyze_explained

WARMUP_CALLS = 5

CONFIGS = (
    ("rules_only", {"use_ast": False, "use_ml": False}),
    ("rules_ast", {"use_ast": True, "use_ml": False}),
    ("ml_only", {"ml_only": "decision"}),
    ("ml_only_conservative", {"ml_only": "escalate"}),
    ("combined", {"use_ast": True, "use_ml": True, "ml_escalate_mode": "any"}),
    ("combined_corroborated", {"use_ast": True, "use_ml": True, "ml_escalate_mode": "corroborated"}),
)

_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*\S+"),
    re.compile(r"[A-Fa-f0-9]{40,}"),
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
]


def redact(code: str, width: int = 140) -> str:
    """Return a short single-line preview with likely secrets masked."""
    text = re.sub(r"\s+", " ", code).strip()
    for pat in _SECRET_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text[:width] + ("..." if len(text) > width else "")


def load_eval(path: Path) -> list[dict]:
    """Load an evaluation file in either supported schema.

    * labelled schema: ``label`` (0/1) + ``category`` (canonical or benign/free-form)
    * verdict schema: ``verdict`` ('allow'/'block') + ``categories`` (list)
    """
    if not path.exists():
        raise SystemExit(f"ERROR: evaluation file not found: {path}")
    rows: list[dict] = []
    with path.open(encoding="utf-8-sig") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"ERROR: malformed JSON on line {lineno}: {exc}") from exc
            code = rec.get("code", "")
            if not isinstance(code, str) or not code.strip():
                raise SystemExit(f"ERROR: line {lineno} has an empty or non-string code field.")

            if "label" in rec:
                risky = rec["label"] == 1
                raw = rec.get("category") or ""
                cats = {c.strip() for c in str(raw).split(",") if c.strip() in CANONICAL_SET}
            elif "verdict" in rec:
                risky = rec["verdict"] == "block"
                cats = {c for c in (rec.get("categories") or []) if c in CANONICAL_SET}
            else:
                raise SystemExit(f"ERROR: line {lineno} has neither 'label' nor 'verdict'.")

            rows.append(
                {
                    "sample_id": rec.get("id")
                    or rec.get("sample_id")
                    or f"line{lineno}",
                    "code": code,
                    "risky": bool(risky),
                    "categories": cats,
                    "language": rec.get("language") or "unknown",
                    "source": rec.get("source") or ("synthetic" if rec.get("synthetic") else "unknown"),
                }
            )
    return rows


def confusion(y_true: list[bool], y_pred: list[bool]) -> dict:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
    fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)
    tn = sum(1 for t, p in zip(y_true, y_pred) if not t and not p)
    n = len(y_true)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    sp = tn / (tn + fn) if tn + fn else 0.0
    sr = tn / (tn + fp) if tn + fp else 0.0
    sf1 = 2 * sp * sr / (sp + sr) if sp + sr else 0.0
    return {
        "n": n,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
        "accuracy": round((tp + tn) / n, 4) if n else 0.0,
        "precision_risky": round(precision, 4),
        "recall_risky": round(recall, 4),
        "f1_risky": round(f1, 4),
        "precision_safe": round(sp, 4),
        "recall_safe": round(sr, 4),
        "f1_safe": round(sf1, 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
        "false_negative_rate": round(fn / (fn + tp), 4) if fn + tp else 0.0,
    }


def per_category(rows: list[dict], preds: list[dict]) -> dict:
    counts: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for rec, pred in zip(rows, preds):
        gt = rec["categories"]
        pc = set(pred["categories"])
        for c in gt | pc:
            if c in gt and c in pc:
                counts[c]["tp"] += 1
            elif c not in gt and c in pc:
                counts[c]["fp"] += 1
            elif c in gt and c not in pc:
                counts[c]["fn"] += 1
    out = {}
    for c in CANONICAL_CATEGORIES:
        m = counts.get(c)
        if not m:
            continue
        tp, fp, fn = m["tp"], m["fp"], m["fn"]
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        out[c] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": tp + fn,
        }
    return out


def run_config(
    rows: list[dict], name: str, params: dict, decision_threshold: float, escalate_threshold: float | None
) -> tuple[list[dict], list[bool]]:
    """Evaluate one configuration. Returns per-row detail and predicted-risk flags."""
    detail: list[dict] = []
    preds: list[bool] = []

    if "ml_only" in params:
        # ML-only: verdict from the model score alone at the chosen threshold.
        threshold = decision_threshold if params["ml_only"] == "decision" else escalate_threshold
        for rec in rows:
            s = ml.score(rec["code"])
            pred_block = s is not None and threshold is not None and s >= threshold
            detail.append(
                {
                    "verdict": "block" if pred_block else "allow",
                    "categories": [],
                    "rule_ids": [],
                    "ml_score": s,
                    "ml_used": bool(pred_block),
                    "risk_score": 0.0,
                }
            )
            preds.append(bool(pred_block))
        return detail, preds

    for rec in rows:
        explained = analyze_explained(rec["code"], **params)
        resp = explained["response"]
        detail.append(
            {
                "verdict": resp.verdict,
                "categories": list(resp.categories),
                "rule_ids": sorted({h["id"] for h in explained["findings"]}),
                "ml_score": explained["ml_score"],
                "ml_used": explained["ml_used"],
                "risk_score": resp.risk_score,
            }
        )
        preds.append(resp.verdict == "block")
    return detail, preds


def warm_latency(rows: list[dict], sample: int = 60) -> dict:
    """Warm-latency sample for the combined pipeline, after warm-up calls."""
    codes = [r["code"] for r in rows][:sample] or ["print('x')"]
    for c in codes[:WARMUP_CALLS]:
        analyze_explained(c)
    timings = []
    samples = codes * max(1, 200 // max(1, len(codes)))
    for c in samples:
        t0 = time.perf_counter()
        analyze_explained(c)
        timings.append((time.perf_counter() - t0) * 1000.0)
    timings.sort()

    def q(p):
        return round(timings[min(len(timings) - 1, int(p * len(timings)))], 3)

    return {"samples": len(timings), "p50_ms": q(0.5), "p95_ms": q(0.95), "max_ms": round(timings[-1], 3)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate CodeGuard on a JSONL dataset.")
    parser.add_argument("dataset", nargs="?", default="dev.jsonl")
    parser.add_argument("--json", type=Path, default=None, help="write full results as JSON")
    parser.add_argument("--no-latency", action="store_true", help="skip the warm-latency sample")
    args = parser.parse_args(argv)

    path = Path(args.dataset)
    rows = load_eval(path)
    y_true = [r["risky"] for r in rows]
    n_pos = sum(y_true)
    n_neg = len(rows) - n_pos
    status = ml.ml_status()
    decision_threshold, escalate_threshold = ml.thresholds()

    print(f"dataset        : {path}")
    print(f"records        : {len(rows)}  risky={n_pos}  safe={n_neg}")
    if path.name == "merged_dataset.jsonl":
        print("WARNING        : this is the TRAINING pool. ML numbers here are "
              "training-set-fitted and are NOT a generalization result.")
    print(f"ML status      : {'available' if status['available'] else 'UNAVAILABLE'} "
          f"({status['reason']})")
    print(f"ML thresholds  : decision={decision_threshold} escalate={escalate_threshold}")
    print()
    print(f"{'config':<24}{'TN':>5}{'FP':>5}{'FN':>5}{'TP':>5}{'acc':>8}{'P':>7}{'R':>7}"
          f"{'F1':>7}{'FPR':>7}{'FNR':>7}")
    results = {"dataset": str(path), "records": len(rows), "risky": n_pos, "safe": n_neg,
               "ml_status": status, "configs": {}}
    combined_detail = None
    for name, params in CONFIGS:
        detail, preds = run_config(rows, name, params, decision_threshold, escalate_threshold)
        cm = confusion(y_true, preds)
        results["configs"][name] = {"confusion": cm}
        print(f"{name:<24}{cm['tn']:>5}{cm['fp']:>5}{cm['fn']:>5}{cm['tp']:>5}"
              f"{cm['accuracy']:>8.3f}{cm['precision_risky']:>7.3f}{cm['recall_risky']:>7.3f}"
              f"{cm['f1_risky']:>7.3f}{cm['false_positive_rate']:>7.3f}"
              f"{cm['false_negative_rate']:>7.3f}")
        if name == "combined":
            combined_detail = detail
        results["configs"][name]["safety_class_metrics"] = {
            "precision_safe": cm["precision_safe"],
            "recall_safe": cm["recall_safe"],
            "f1_safe": cm["f1_safe"],
        }

    cats = per_category(rows, combined_detail)
    results["per_category_combined"] = cats
    print()
    print("per-category (combined, where canonical labels exist):")
    print(f"  {'category':<26}{'sup':>5}{'P':>7}{'R':>7}{'F1':>7}")
    for c, m in cats.items():
        print(f"  {c:<26}{m['support']:>5}{m['precision']:>7.3f}{m['recall']:>7.3f}{m['f1']:>7.3f}")

    errors = []
    for rec, pred in zip(rows, combined_detail):
        gt = rec["risky"]
        got = pred["verdict"] == "block"
        if gt == got:
            continue
        errors.append(
            {
                "type": "false_positive" if got else "false_negative",
                "sample_id": rec["sample_id"],
                "true_label": "risky" if gt else "safe",
                "predicted_label": "risky" if got else "safe",
                "final_verdict": pred["verdict"],
                "ml_score": round(pred["ml_score"], 4) if pred["ml_score"] is not None else None,
                "ml_used": pred["ml_used"],
                "risk_score": pred["risk_score"],
                "rule_ids": pred["rule_ids"],
                "categories": pred["categories"],
                "language": rec["language"],
                "source": rec["source"],
                "preview": redact(rec["code"]),
            }
        )
    results["errors"] = errors
    print()
    print(f"combined errors: {len(errors)} "
          f"({sum(1 for e in errors if e['type']=='false_positive')} FP, "
          f"{sum(1 for e in errors if e['type']=='false_negative')} FN)")
    for e in errors:
        print(f"  [{e['type']}] {e['sample_id']} lang={e['language']} src={e['source']} "
              f"ml={e['ml_score']} rules={','.join(e['rule_ids']) or '-'}")
        print(f"      {e['preview']}")

    if not args.no_latency:
        lat = warm_latency(rows)
        results["warm_latency_ms"] = lat
        print()
        print(f"warm latency (combined, after {WARMUP_CALLS} warm-up calls): "
              f"p50={lat['p50_ms']}ms p95={lat['p95_ms']}ms max={lat['max_ms']}ms "
              f"n={lat['samples']}")

    results["environment"] = {
        "python": platform.python_version(),
        "platform": platform.platform(),
    }

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
        print(f"\nresults written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
