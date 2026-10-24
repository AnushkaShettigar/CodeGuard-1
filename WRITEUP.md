# CodeGuard — Architecture and Key Design Decisions

*(Supersedes the earlier rule-only write-up. Numbers here are measured; see
`docs/FINAL_REPORT.md` for commands and raw outputs.)*

## 1. Threat model and scope

**Threat.** An AI agent (or an LLM-generated patch) produces code that is about to
be executed on a developer's or CI machine. The code may read secrets, exfiltrate
data, destroy the filesystem, persist, obfuscate a payload, install a typosquatted
dependency, exhaust resources, SSRF into internal services, or try to talk the
reviewer out of blocking it.

**In scope.** Static inspection of a code **snippet** before execution, producing
a verdict, risk score, categories, and line numbers; a decorator that enforces the
verdict for calls routed through it; a small CPU-only classical ML classifier that
raises recall on shapes the hand-written rules miss.

**Out of scope (explicitly).** Executing or sandboxing the snippet; controlling
arbitrary processes; intercepting subprocesses, shell commands, or code outside a
`@guarded` function; full program analysis (no taint tracking, no inter-file
analysis); proving that allowed code is safe. CodeGuard is a gate, not a sandbox.

## 2. Components and data flow

```
api.py / guard.py / evaluate.py / benchmark.py / demo
                      │
                      ▼
            detect/cascade.py  (one decision implementation)
                    │
   detect_language ─┼─ rules.scan (rules.yaml, language-filtered)
                    ├─ ast_python.scan (Python only)
                    └─ ml.score (committed sklearn Pipeline)
                      │
                      ▼
                  CheckResponse
```

* `detect/language.py` — scored classifier over competing language signals. It
  blanks Python string/comment content before scoring other languages so prose in
  a docstring cannot vote for JavaScript. Measured 100% on the tracked datasets'
  language labels.
* `detect/rules.py` + `data/rules.yaml` — 53 regex rules, each with id, category,
  language scope, weight and reason. Rule ids are unique and stable.
* `detect/ast_python.py` — syntactic AST checks: `eval`/`exec`, `os.system` with
  `rm -rf`, `setuid`, `while True` without an owning `break`. Resolves simple
  import aliases (`import os as o`, `from os import system as s`) and matches
  attribute calls on the resolved module so an unrelated `engine.system(...)` is
  not treated as `os.system(...)`.
* `detect/ml.py` — lazily loads the committed pipeline once per process, resolves
  the path relative to the repository, and never raises on load/inference failure.
* `detect/cascade.py` — combines findings with noisy-OR, de-duplicates findings by
  `(rule id, line)`, and applies the decision policy.

**Findings combination.** `risk = 1 - ∏(1 - wᵢ)` over de-duplicated findings.
`block` if any weight ≥ 0.80 or `risk ≥ 0.60`. Because the smallest rule weight is
0.70, a single finding already blocks; this fail-closed choice is deliberate and is
the documented source of the benign-URL-fetch false positive.

## 3. Why a CPU-first classical ML model

The brief requires an explainable classical model, no SLM/LLM judge, and no GPU.
A TF-IDF + logistic regression pipeline was chosen because it:

* trains in ~1 s on the 158-row corpus and is fully reproducible from
  `training/train_model.py` plus a recorded manifest;
* adds ~0.73 ms per warm call and 571 KB on disk - small enough to sit inline
  before execution;
* is inspectable: features are n-grams, weights are coefficients;
* does not send code anywhere, which removes the exfiltration risk of an LLM judge.

The cost is a ~1.2 s one-time import of scikit-learn (cold start ≈1.30 s with ML
vs ≈162 ms deterministic-only) and a model that is deliberately binary.

**Why the ML layer exists at all.** On the broader supplied corpus the
deterministic layer's recall is 0.398 (53 of 88 risky snippets missed) while the
curated sets — which the rules were written against — score 1.000. That gap is the
justification for the ML layer, and it is why ML escalation is enabled by default:
it is the only mechanism in the system that closes it.

## 4. Safety: fail-closed interception

`@guarded` inspects the function source before the body runs:

| Condition | Behaviour |
|---|---|
| `inspect.getsource` raises `OSError`/`TypeError` | raise `GuardInspectionError`; body not run |
| source is empty or not a string | raise `GuardInspectionError`; body not run |
| detector raises | raise `GuardAnalysisError`; body not run |
| verdict is missing or not `allow`/`block` | raise `GuardAnalysisError`; body not run |
| verdict is `block` | raise `GuardBlocked`; body not run |
| verdict is `allow` | call the body |

The original implementation substituted `""` for unreadable source, analysed it as
safe, and **ran the function** — a fail-open hole. There is no fail-open option.
`tests/test_interception.py` proves the body never runs for each condition above,
including a test that monkeypatches `inspect.getsource` to raise and asserts a
marker file was not created.

**Scope honesty.** This protects only calls through the decorated function object.
It is not a sandbox and does not intercept subprocesses or arbitrary execution.

## 5. Evaluation methodology and limitations

* **Split.** Model and thresholds are fit/selected with `StratifiedGroupKFold`
  (5 folds) over the training pool, grouped by a near-duplicate cluster id so
  duplicates cannot straddle folds. Thresholds come from out-of-fold predictions
  only.
* **Threshold policy.** `decision_threshold` maximises out-of-fold F1 (0.48).
  `escalate_threshold` is the highest-recall threshold with out-of-fold precision
  ≥ 0.90 (0.64) and is the only one the cascade uses to escalate.
* **No test leakage.** `dev.jsonl`, `unseen.jsonl` and `hard_eval.jsonl` are never
  read by the training scripts; two training rows that duplicated evaluation
  snippets were excluded.
* **Reported.** Confusion matrices, accuracy, per-class precision/recall/F1, FPR,
  FNR, per-category metrics, and every FP/FN with a redacted preview.
* **Limits.** The curated sets are tiny (18/24/15) and were used while authoring
  the rules, so they are development/tuned sets, not independent validation.
  `hard.jsonl` is the labelled mirror of `hard_eval.jsonl`, so the "hard set" is
  not an independent sample. The synthetic corpus is generated, not real-world.
  Out-of-fold ML performance (precision 0.939, recall 0.352, FPR 0.029 at the
  escalation point) is the honest generalization estimate; in-pool ML figures are
  optimistic and are labelled as such. The nine-class category vocabulary cannot be
  derived from the synthetic tags, so ML remains binary.

## 6. Known failure modes and future work

**Failure modes observed**

1. ML escalation false positives on benign utility code that uses the same APIs as
   the attacks (`pip install requests`, an unrelated `engine.system(...)` call);
   scores land at 0.65–0.71, just above the 0.64 threshold. Root cause: the risky
   examples in the training corpus over-represent those APIs.
2. `PY_SQLI_001` flags an f-string that interpolates only hardcoded constant
   identifiers.
3. `PY_SSRF_ARBITRARY_001` flags code that validates a URL before fetching it.
4. Deterministic recall is low on shapes the rules were not written for
   (e.g. `sudo rm -rf "$HOME"`, `chmod -R 777 /etc`, `TRUNCATE TABLE ...`,
   `verify=False`).

**Future work**

* Rebalance the training corpus with benign network/subprocess/install examples,
  then re-select the escalation threshold.
* Add a validation step in the SSRF rule (detect a preceding `startswith`/
  allowlist check) instead of a width heuristic.
* Raise deterministic recall for destructive/permission/DB commands that are not
  covered by the literal patterns; each change must carry a positive and negative
  test and must not regress the curated sets.
* Recursive base64/hex unwrapping before rule scanning; taint analysis for
  source-to-sink exfiltration; tree-sitter parsing for JavaScript and Bash.
* Probability calibration (e.g. isotonic on out-of-fold scores) before any
  consumer treats `ml_score` as a calibrated probability.
