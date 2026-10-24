"""Latency and size benchmark for CodeGuard.

Methodology (stated so the numbers are not over-read):

* **Cold start** is measured in a fresh subprocess and includes the Python
  interpreter start, package import, and model load. It is the worst case a
  caller can see, not a per-request cost.
* **Warm latency** is measured in-process after a warm-up, on snippets that are
  already loaded into memory. Dataset parsing and file I/O are excluded.
* Rule/AST/ML sub-layers are timed individually so the cost of the classical ML
  step is visible next to the deterministic layers.
* Numbers are machine- and load-dependent. Do not treat them as a guarantee.

Run::

    py -3 -m benchmark
    py -3 -m benchmark --dataset hard_eval.jsonl --samples 40 --repeats 3000
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

from textcodeguard.detect import ml  # noqa: E402
from textcodeguard.detect.ast_python import scan as ast_scan  # noqa: E402
from textcodeguard.detect.cascade import analyze_explained  # noqa: E402
from textcodeguard.detect.language import detect_language  # noqa: E402
from textcodeguard.detect.rules import scan as rule_scan  # noqa: E402

WARMUP_CALLS = 50

DEFAULT_SNIPPETS = [
    "print('hello world')\n",
    'import requests\nrequests.get("https://api.example.com/status")\n',
    'import os\nos.system("rm -rf /")\n',
    "def f(x):\n    return x + 1\n",
    "for i in range(10):\n    print(i)\n",
    "const x = require('fs');\n",
    "rm -rf /var/www/*\n",
    "DROP DATABASE production;\n",
]


def load_snippets(dataset: Path | None, limit: int) -> tuple[list[str], str]:
    if dataset is None:
        return DEFAULT_SNIPPETS, "built-in mix (8 snippets)"
    path = dataset if dataset.is_absolute() else REPO_ROOT / dataset
    if not path.exists():
        raise SystemExit(f"ERROR: dataset not found: {path}")
    codes = []
    with path.open(encoding="utf-8-sig") as fh:
        for line in fh:
            if line.strip():
                codes.append(json.loads(line)["code"])
            if len(codes) >= limit:
                break
    if not codes:
        raise SystemExit(f"ERROR: no snippets found in {path}")
    return codes, f"{path.name} (first {len(codes)} snippets)"


def percentiles(samples: list[float]) -> dict:
    samples = sorted(samples)

    def q(p):
        return round(samples[min(len(samples) - 1, int(p * len(samples)))], 4)

    return {
        "n": len(samples),
        "p50_ms": q(0.5),
        "p95_ms": q(0.95),
        "mean_ms": round(statistics.fmean(samples), 4),
        "min_ms": round(samples[0], 4),
        "max_ms": round(samples[-1], 4),
    }


def time_callable(fn, codes: list[str]) -> dict:
    for code in codes[: min(WARMUP_CALLS, len(codes))]:
        fn(code)
    samples = []
    for code in codes:
        start = time.perf_counter()
        fn(code)
        samples.append((time.perf_counter() - start) * 1000.0)
    return percentiles(samples)


_COLD_PROBE = (
    "import time;t=time.perf_counter();"
    "from textcodeguard.detect.cascade import analyze;"
    "analyze('print(1)');"
    "print((time.perf_counter()-t)*1000.0)"
)


def cold_start(runs: int = 3) -> dict:
    totals = []
    imports = []
    no_ml = []
    for _ in range(runs):
        proc = subprocess.run(
            [sys.executable, "-c", _COLD_PROBE],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            return {"error": proc.stderr.strip()[:400]}
        imports.append(float(proc.stdout.strip().splitlines()[-1]))
    # A second measurement isolates interpreter + import + model load only.
    probe2 = (
        "import time;t=time.perf_counter();"
        "from textcodeguard.detect import ml;ml.ml_status();"
        "print((time.perf_counter()-t)*1000.0)"
    )
    for _ in range(runs):
        proc = subprocess.run(
            [sys.executable, "-c", probe2], cwd=str(REPO_ROOT),
            capture_output=True, text=True, check=False,
        )
        if proc.returncode == 0:
            totals.append(float(proc.stdout.strip().splitlines()[-1]))
    # And a third with the model unavailable, to show the deterministic-only cost.
    env = {**os.environ, "CODEGUARD_MODEL_PATH": str(REPO_ROOT / "models" / "__absent__.joblib")}
    for _ in range(runs):
        proc = subprocess.run(
            [sys.executable, "-c", _COLD_PROBE], cwd=str(REPO_ROOT),
            capture_output=True, text=True, check=False, env=env,
        )
        if proc.returncode == 0:
            no_ml.append(float(proc.stdout.strip().splitlines()[-1]))
    return {
        "runs": runs,
        "import_and_first_analysis_ms": round(statistics.median(imports), 3),
        "import_and_model_load_ms": round(statistics.median(totals), 3) if totals else None,
        "import_and_first_analysis_without_ml_ms": round(statistics.median(no_ml), 3) if no_ml else None,
        "note": "subprocess, includes interpreter start",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark CodeGuard latency and size.")
    parser.add_argument("--dataset", type=Path, default=None)
    parser.add_argument("--samples", type=int, default=60)
    parser.add_argument("--repeats", type=int, default=1000,
                        help="target number of warm inference calls per configuration")
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)

    snippets, source = load_snippets(args.dataset, args.samples)
    # Repeat the (already in-memory) snippets so warm numbers are not dominated by
    # cache effects on a handful of strings.
    repeats = max(1, args.repeats // max(1, len(snippets)))
    codes = snippets * repeats

    status = ml.ml_status()
    decision, escalate = ml.thresholds()

    print(f"dataset        : {source}")
    print(f"warm calls     : {len(codes)} per configuration (after {WARMUP_CALLS} warm-up calls)")
    print(f"ML status      : {'available' if status['available'] else 'UNAVAILABLE'} ({status['reason']})")
    print()

    configs = {
        "language_only": lambda c: detect_language(c),
        "rules_only": lambda c: rule_scan(c, detect_language(c)),
        "ast_only": lambda c: ast_scan(c),
        "ml_only": lambda c: ml.score(c),
        "combined": lambda c: analyze_explained(c),
        "combined_corroborated": lambda c: analyze_explained(c, ml_escalate_mode="corroborated"),
    }

    results = {}
    print(f"{'configuration':<24}{'p50 ms':>10}{'p95 ms':>10}{'mean ms':>10}{'n':>8}")
    for name, fn in configs.items():
        if name.startswith("ml") and not status["available"]:
            print(f"{name:<24}{'skipped (no model)':>38}")
            continue
        stats = time_callable(fn, codes)
        results[name] = stats
        print(f"{name:<24}{stats['p50_ms']:>10.4f}{stats['p95_ms']:>10.4f}"
              f"{stats['mean_ms']:>10.4f}{stats['n']:>8}")

    cold = cold_start()
    results["cold_start"] = cold
    print()
    print(f"cold start     : import+first analysis {cold.get('import_and_first_analysis_ms')} ms, "
          f"import+model load {cold.get('import_and_model_load_ms')} ms, "
          f"deterministic-only (no model) {cold.get('import_and_first_analysis_without_ml_ms')} ms")

    model_file = REPO_ROOT / "models" / "codeguard_clf.joblib"
    manifest_file = REPO_ROOT / "models" / "model_manifest.json"
    model_size = model_file.stat().st_size if model_file.exists() else None
    results["artifact"] = {
        "model_path": str(model_file.relative_to(REPO_ROOT)).replace("\\", "/"),
        "model_bytes": model_size,
        "manifest_bytes": manifest_file.stat().st_size if manifest_file.exists() else None,
        "decision_threshold": decision,
        "escalate_threshold": escalate,
    }
    print(f"model size     : {model_size} bytes" if model_size else "model size     : (no artifact)")

    import sklearn

    versions = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "scikit-learn": sklearn.__version__,
    }
    try:
        import numpy

        versions["numpy"] = numpy.__version__
    except ImportError:  # pragma: no cover
        pass
    results["environment"] = versions
    print(f"environment    : python {versions['python']}, sklearn {versions['scikit-learn']}, "
          f"{platform.machine()}")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
        print(f"written to     : {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
