"""Run the pasteable samples in examples/samples.jsonl.

Two modes:

* default - call the detector in-process (no server needed)
* ``--url`` - POST each sample to a running CodeGuard service. Uses the JSON
  ``/check`` route by default, or the raw ``/check/raw`` route with ``--raw``.

Each sample carries a ``should`` field (the security intent). The runner reports
where the measured verdict differs and labels the cause, so the sample set doubles
as a smoke check.

    py -3 -m examples.run_samples
    py -3 -m examples.run_samples --url http://127.0.0.1:8000
    py -3 -m examples.run_samples --url http://127.0.0.1:8000 --raw
    py -3 -m examples.run_samples --only secret_access
    py -3 -m examples.run_samples --strict          # exit 1 on any unexpected diff
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLES = Path(__file__).resolve().parent / "samples.jsonl"

# Documented behaviours that are expected to differ from the security intent.
KNOWN_CAUSES = {
    "ml_escalation_false_positive": "ML escalated benign code (documented ML precision limit)",
    "rules_scan_raw_text": "rule layer scans comments/strings (documented rule limit)",
}


def load_samples() -> list[dict]:
    if not SAMPLES.exists():
        raise SystemExit(f"ERROR: {SAMPLES} not found. Run `py -3 -m examples.verify_samples`.")
    return [json.loads(line) for line in SAMPLES.read_text(encoding="utf-8").splitlines() if line.strip()]


def classify_gap(rec: dict, measured: str) -> str:
    if measured == rec["should"]:
        return ""
    if rec["ml_used"]:
        return "ml_escalation_false_positive"
    if measured == "block" and rec["det_verdict"] == "block" and rec["should"] == "allow":
        return "rules_scan_raw_text"
    return "unexpected"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the CodeGuard pasteable samples.")
    parser.add_argument("--url", default=None, help="POST to a running service instead of analysing in-process")
    parser.add_argument("--raw", action="store_true",
                        help="with --url, POST to /check/raw as text/plain instead of the JSON /check route")
    parser.add_argument("--only", default=None, help="only samples whose group contains this substring")
    parser.add_argument("--strict", action="store_true", help="exit non-zero on any unexpected difference")
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)

    samples = load_samples()
    if args.only:
        samples = [s for s in samples if args.only in s["group"]]
    if not samples:
        raise SystemExit("ERROR: no samples matched the filter.")

    post = None
    if args.url:
        import urllib.error
        import urllib.request

        if args.raw:
            endpoint = args.url.rstrip("/") + "/check/raw"
            content_type = "text/plain"

            def post(code: str) -> dict:
                req = urllib.request.Request(
                    endpoint, data=code.encode("utf-8"),
                    headers={"content-type": content_type}, method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=30) as resp:
                        return json.loads(resp.read().decode("utf-8"))
                except urllib.error.HTTPError as exc:  # pragma: no cover
                    return {"verdict": f"HTTP {exc.code}", "error": exc.read().decode("utf-8")[:200]}
        else:
            endpoint = args.url.rstrip("/") + "/check"

            def post(code: str) -> dict:
                body = json.dumps({"code": code}).encode("utf-8")
                req = urllib.request.Request(
                    endpoint, data=body,
                    headers={"content-type": "application/json"}, method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=30) as resp:
                        return json.loads(resp.read().decode("utf-8"))
                except urllib.error.HTTPError as exc:  # pragma: no cover
                    return {"verdict": f"HTTP {exc.code}", "error": exc.read().decode("utf-8")[:200]}

        # warm up so the first sample is not charged with the cold model load
        post("print(1)")
    else:
        from textcodeguard.detect.cascade import analyze

        def post(code: str) -> dict:
            return analyze(code).model_dump()

    results = []
    gaps = []
    print(f"{'id':<26}{'group':<26}{'should':<7}{'verdict':<7}{'ml':>7}  note")
    print("-" * 110)
    for s in samples:
        out = post(s["code"])
        measured = out.get("verdict", "?")
        cause = classify_gap(s, measured)
        ml_score = out.get("ml_score")
        results.append({**s, "measured_verdict": measured, "ml_score": ml_score,
                        "ml_used": out.get("ml_used"), "gap_cause": cause})
        if cause:
            gaps.append((s, measured, cause))
        mark = "" if not cause else ("  <-- " + KNOWN_CAUSES.get(cause, "UNEXPECTED"))
        print(f"{s['id']:<26}{s['group']:<26}{s['should']:<7}{measured:<7}"
              f"{(f'{ml_score:.3f}' if isinstance(ml_score, (int, float)) else '-'):>7}{mark}")

    print("-" * 110)
    unexpected = [g for g in gaps if g[2] == "unexpected"]
    print(f"{len(results)} samples | {len(results) - len(gaps)} matched intent | "
          f"{len(gaps)} known gaps | {len(unexpected)} unexpected")
    if gaps:
        print("\nknown gaps by cause:")
        for cause, n in sorted(Counter(g[2] for g in gaps).items()):
            print(f"  {cause:<32}{n}  ({KNOWN_CAUSES.get(cause, '')})")
    if unexpected:
        print("\nUNEXPECTED differences:")
        for s, m, _ in unexpected:
            print(f"  {s['id']}: should={s['should']} got={m}")

    by_group = Counter(s["group"] for s in results)
    print("\nsamples per group:", ", ".join(f"{g}={n}" for g, n in sorted(by_group.items())))

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
        print(f"written to: {args.json}")

    return 1 if (args.strict and unexpected) else 0


if __name__ == "__main__":
    sys.exit(main())
