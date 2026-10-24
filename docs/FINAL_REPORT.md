# CodeGuard — Final Report

Date: 2026-10-24 · Working tree: `C:\cogni` · Platform: Windows, Python 3.12.10

This report follows the requested format. Every number below was produced by a
command that was actually run; raw outputs are in `results/`.

---

## 1. Initial audit

**Working before any change.** A coherent three-layer detector existed and ran:
`detect_language()` → 53 regex rules (`data/rules.yaml`) → a small Python AST pass
→ a noisy-OR cascade. A FastAPI service exposed `/check`, `/batch`, `/health`; a
`@guarded` decorator and a demo proved blocking by side effect. Verified:

| Command | Result |
|---|---|
| `py -3 -m textcodeguard.evaluate dev.jsonl` | acc 1.000 (n=18) |
| `py -3 -m textcodeguard.evaluate unseen.jsonl` | acc 1.000 (n=24) |
| `py -3 -m textcodeguard.evaluate hard_eval.jsonl` | acc 1.000, but `ssrf_network_exfil` P=0.50/F1=0.67 |
| `py -3 -m textcodeguard.demo.intercept_check` | `PASS` |

**Missing or broken.**

1. **No classical ML at all** — no features, training entry point, artefact,
   manifest, or fallback.
2. **Fail-open interception** — `inspect.getsource` failures were swallowed into
   `src = ""`, analysed as safe, and the function body still ran. Only `OSError`
   was handled.
3. **No tests** — `tests/` did not exist; every README claim was unverified.
4. **Evaluation too thin and not leakage-aware** — no confusion matrix, no
   per-class recall, no FP/FN records, no ablations, no grouping; three
   "evaluation" files had been used while authoring the rules.
5. **Supplied labelled datasets were unused by any script** — 160 labelled rows
   sat idle while evaluation used three 15–24 row verdict-only files.
6. **Language detection was badly broken** — `rm -rf /var/www/*` was detected as
   JavaScript (`\bvar\b` inside `/var/`), and `fs.rmSync('/', {recursive: true})`
   and `process.env.X = '0';` were detected as Python (they parse as Python), so
   the language-scoped rules never ran. Measured 200/232 correct (86.2%).
7. **Rule defects** — `PY_SQLI_001` flagged parameterised `... = %s` queries as
   injection; `PY_DESTRUCT_001` missed `os.system(f'rm -rf ...')`;
   `PY_EXFIL_001` treated the request kwargs `data=`/`json=` as exfiltration
   evidence; `PY_SSRF_ARBITRARY_001` ignored that the URL was a module constant.
8. **AST weaknesses** — no alias resolution; any `.system()` matched regardless of
   receiver; an inner loop's `break` was credited to the outer loop.
9. **API** — no input cap, no error handling, no ML/fallback reporting.
10. **No benchmark**, and docs overstated results (e.g. claimed all-1.000 on the
    hard set, and quoted p95 without excluding the cold call).

Full detail: `docs/AUDIT.md`.

---

## 2. Dataset audit

Six files; all inputs left byte-for-byte unchanged.

| File | Tracked | Rows | Schema | Labels |
|---|---|---|---|---|
| `codeguard_dev.jsonl` | no (supplied) | 42 | code,id,label,language,category,rationale | 12 safe / 30 risky |
| `codeguard_synthetic.jsonl` | no (supplied) | 118 | code,label,language,category,synthetic | 59 / 59 |
| `hard.jsonl` | yes | 15 | labelled | 7 / 8 |
| `hard_eval.jsonl` | yes | 15 | verdict-based | 7 allow / 8 block |
| `dev.jsonl` | yes | 18 | verdict-based | 9 / 9 |
| `unseen.jsonl` | yes | 24 | verdict-based | 12 / 12 |

* No malformed JSON, no empty code, no duplicate IDs, no exact duplicates within a
  file.
* **Two exact cross-file duplicates**: a synthetic row identical to a `dev.jsonl`
  row, and a synthetic row identical to an `unseen.jsonl` row. Both synthetic rows
  were **excluded from training** and recorded in `training/merge_report.json`.
* One near-duplicate pair inside the synthetic file; clustered.
* **`hard.jsonl` and `hard_eval.jsonl` are the same 15 snippets** (same order,
  label ⇔ verdict verified for all 15). The "hard set" is not an independent
  sample.
* **Three different category conventions** share the name `category`: the
  canonical nine; benign topic tags (`benign`, `logging`, `json_parse`); and ~30
  free-form synthetic risk tags (`command_injection`, `hardcoded_secret`, …) that
  do **not** map to the nine. One row comma-joins three categories
  (`"resource_exhaustion, ssrf_network_exfil, dependency_risk"`).
* Consequence: a nine-class classifier was not trained. The ML label is binary
  only, and no category is inferred from it.
* Provenance: only the synthetic file self-identifies (`synthetic: true`). The
  merge adds an explicit `source` field (`original` / `synthetic`); nothing is
  presented as real-world data.

**Merge result** (`training/merged_dataset.jsonl`, fingerprint
`ac8b888240c9487c…`):

| | |
|---|---|
| rows | 158 (42 original + 116 synthetic) |
| labels | 70 safe / 88 risky |
| languages | python 97, bash 22, javascript 19, sql 18, markdown 1, yaml 1 |
| duplicate groups | 157 (largest 2) |
| exclusions | 2 (both `duplicates_evaluation_snippet`) |

Near-duplicate clustering merges exact-normalised matches always, and token
Jaccard ≥ 0.85 only when the labels agree, so a real safe/risky pair is never
collapsed. Full detail: `docs/DATASET_AUDIT.md`.

**One credential-shaped literal was replaced.** Both corpora contained a
Slack-token-shaped string in a `secret_access` / `hardcoded_secret` example. GitHub
push protection rejected the repository because of it, and the trained TF-IDF
vocabulary stored the literal too. The value was replaced with the explicit
placeholder `EXAMPLE-SLACK-TOKEN-NOT-REAL` in both supplied files; the records keep
their label, category and shape, and nothing else in either file changed (bytes, BOM
and record counts verified). The dataset was then rebuilt and the model retrained,
so the artefact no longer contains the literal. This is the only deviation from the
supplied files and it is recorded here rather than done silently.

---

## 3. Changes made

| File | Change | Reason |
|---|---|---|
| `textcodeguard/detect/ml.py` | **new** — lazy singleton model loader, `ml_status()`, `score()`, `thresholds()`, `reset_cache()` | Inference integration with transparent fallback; repo-relative path |
| `textcodeguard/detect/cascade.py` | ML escalation, explicit decision policy, finding de-duplication, `analyze_explained()` | Single decision implementation; ML can only escalate |
| `textcodeguard/schema.py` | added optional `ml_score`, `ml_available`, `ml_used`; `code` capped at 100k chars | ML status without breaking the contract; bound oversized input |
| `textcodeguard/guard.py` | **fail-closed** rewrite; `GuardError` base, `GuardInspectionError`, `GuardAnalysisError` | Fix the fail-open hole (§5) |
| `textcodeguard/detect/language.py` | scored classifier; Python string/comment blanking; expanded shell/JS/SQL signals | 86.2% → 99.6% language accuracy; fixes silently-skipped rules |
| `textcodeguard/detect/ast_python.py` | alias resolution, module-aware attribute matching, `break` scoped to the owning loop, `source` tag | Reduce false positives, fix nested-loop `break` bug |
| `textcodeguard/data/rules.yaml` | 5 targeted fixes: `PY_SQLI_001`, `PY_DESTRUCT_001`, `SH_OBF_002`, `PY_EXFIL_001`, `PY_SSRF_ARBITRARY_001` | Reproducible rule defects (§4) |
| `textcodeguard/api.py` | added `POST /check/raw` and `POST /batch/raw` (NUL-separated), batch limits, helpful 400 on a JSON/raw mix-up, realistic OpenAPI examples | Raw-text submission needs no JSON escaping; JSON routes kept |
| `textcodeguard/evaluate.py` | rewritten: 6 configurations, confusion matrices, per-class metrics, per-category metrics, FP/FN records with redaction, warm latency, JSON output | Honest, leakage-aware evaluation |
| `textcodeguard/categories.py` | **new** — canonical nine categories in one place | Remove duplicated category lists |
| `training/build_dataset.py` | **new** — deterministic merge, provenance, dup_group clustering, leakage exclusions, report | Reproducible dataset with provenance |
| `training/train_model.py` | **new** — pipeline, grouped stratified CV, two thresholds, manifest | Reproducible training with validation-only selection |
| `benchmark.py` | **new** — cold/warm, per-layer, model size, versions | Latency methodology |
| `tests/` | **new** — 193 tests across 10 files | Verify every guarantee |
| `examples/` | **new** — 73 verified samples, runner, drift test, batch file | Pasteable, regression-checked test data |
| `LICENSE` | **new** — MIT | Required for publication |
| `requirements.txt` | added scikit-learn, joblib, numpy | Training/inference dependencies |
| `README.md` | rewritten | Accurate claims, training instructions, fallback, limitations |
| `WRITEUP.md` | rewritten | Architecture write-up + honest methodology and failure modes |
| `docs/AUDIT.md`, `docs/DATASET_AUDIT.md` | **new** | Audits |
| `models/codeguard_clf.joblib`, `models/model_manifest.json` | **new** | Committed artefact so a fresh clone runs |
| `results/*.json`, `results/README.md` | **new** | Raw evidence plus the command that produced each file |
| `codeguard_dev.jsonl`, `codeguard_synthetic.jsonl` | one Slack-token-shaped literal replaced with an explicit placeholder | GitHub push protection; see §2 |

Preserved: all existing rules, findings, API fields, the `/check` and `/batch`
shapes, the demo, and every input dataset (apart from the one documented literal
substitution in §2).

---

## 4. ML design

* **Model.** `Pipeline(FeatureUnion(TF-IDF word 1–2-gram, TF-IDF char_wb
  3–5-gram) → LogisticRegression(C=1.0, class_weight="balanced",
  solver="liblinear", max_iter=2000, random_state=42))`, persisted with `joblib`.
* **Features fit on training rows only** — verified by a test asserting a token
  absent from training is absent from the vocabulary.
* **Split.** `StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)`
  grouped by `dup_group`, so near-duplicates cannot straddle folds. Validation
  folds: 32/32/31/31/32 rows.
* **Two thresholds, both from out-of-fold predictions only.**
  * `decision_threshold = 0.48` — F1-maximising (out-of-fold P=0.789, R=0.932,
    F1=0.854, FPR=0.314). Reported for the `ml_only` configuration.
  * `escalate_threshold = 0.64` — highest recall subject to out-of-fold precision
    ≥ 0.90 (out-of-fold P=0.939, R=0.352, F1=0.512, FPR=0.029). **Only this one is
    used by the cascade**, so ML can block on its own only where it was precise in
    cross-validation.
* **Policy.** Rules/AST block as before. ML can only escalate an `allow` to
  `block`; a low `ml_score` never cancels a deterministic finding. `risk_score`
  remains the deterministic score; ML is reported in `ml_score`/`ml_used`. Modes
  `off` and `corroborated` exist for comparison (`corroborated` is inert with the
  current rule weights — the smallest weight, 0.70, already blocks).
* **Fallback.** Missing artefact, unreadable artefact, or an inference exception →
  `ml_available=false`, `ml_score=null`, rules+AST still work, and
  `ml_status()["reason"]` says why. No code content is logged.
* **Reproducibility.** `py -3 -m training.build_dataset` then
  `py -3 -m training.train_model` regenerates byte-comparable behaviour; a rerun in
  a fresh venv reproduced `decision=0.48 escalate=0.64` and the same out-of-fold
  metrics. The manifest records dataset fingerprint, counts, fold sizes,
  thresholds, the F1 sweep, dependency versions and timestamp.
* **Calibration.** None. `ml_score` is explicitly documented as an uncalibrated
  score, not a probability.

---

## 5. Security fixes

**Fail-open → fail-closed** in `textcodeguard/guard.py`:

| Condition | Before | After |
|---|---|---|
| `inspect.getsource` raises `OSError` | source replaced with `""`, `allow`, **body ran** | `GuardInspectionError`, body not run |
| `inspect.getsource` raises `TypeError` | uncaught | `GuardInspectionError`, body not run |
| empty/unavailable source | `allow`, body ran | `GuardInspectionError`, body not run |
| detector raises | could propagate past the gate | `GuardAnalysisError`, body not run |
| verdict missing/malformed | would `return fn(...)` | `GuardAnalysisError`, body not run |
| verdict `block` | `GuardBlocked` | unchanged |

Regression tests monkeypatch `inspect.getsource` to raise `OSError`/`TypeError`,
return `""`, make the detector raise, and return malformed/verdict-less objects —
and each asserts a marker file was **not** created (i.e. the body did not run).
There is no fail-open option. Exception messages never include arguments, secrets
or source. `GuardError` is the common base. Documented scope: decorator-only, not
a sandbox.

---

## 6. Tests run

| Command | Outcome |
|---|---|
| `py -3 -m pytest -q` | **193 passed**, 1 third-party deprecation warning, ~6 s |
| `py -3 -m textcodeguard.demo.intercept_check` | `PASS` (exit 0); `marker_unsafe.txt` never created |
| `py -3 -m textcodeguard.evaluate dev.jsonl` | ran; see §7 |
| `py -3 -m textcodeguard.evaluate unseen.jsonl` | ran; see §7 |
| `py -3 -m textcodeguard.evaluate hard_eval.jsonl` | ran; see §7 |
| `py -3 -m textcodeguard.evaluate training/merged_dataset.jsonl` | ran (training-pool diagnostic) |
| `py -3 -m training.build_dataset` | 158 rows, 2 exclusions, report written |
| `py -3 -m training.train_model` | model + manifest written; thresholds reproduced |
| `py -3 -m benchmark` | ran; see §8 |
| `py -3 -m examples.run_samples --url ...` | 73 samples, 68 match intent, 5 documented gaps, 0 unexpected |
| **fresh venv**: `python -m venv`, `pip install -r requirements.txt`, then `pytest -q`, demo, evaluate, retrain | **all passed**; deps resolve cleanly |

Test coverage: schema/API incl. both raw routes (`test_schema_api.py`), nine
categories positive+negative (`test_rules_categories.py`), AST
aliases/scoping/strings (`test_ast.py`), language detection regressions
(`test_language.py`), decision policy and fallback (`test_cascade_policy.py`),
training guards/split/fit/load/fallback (`test_ml.py`), interception fail-closed
(`test_interception.py`), no-execution proofs (`test_no_execution.py`),
hand-computed evaluation metrics (`test_evaluate.py`), and sample-set drift
(`test_examples.py`).

---

## 7. Evaluation results

All configurations use the same examples. Ablations available: `rules_only`,
`rules_ast`, `ml_only`, `ml_only_conservative`, `combined` (shipped default),
`combined_corroborated`. **These three sets are small and were used while the
rules were authored — they are development/tuned sets, not untouched independent
tests.**

**`dev.jsonl` (n=18: 9 risky / 9 safe)**

| config | TN | FP | FN | TP | acc | P | R | F1 | FPR | FNR |
|---|---|---|---|---|---|---|---|---|---|---|
| rules_only | 9 | 0 | 0 | 9 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| rules_ast | 9 | 0 | 0 | 9 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| ml_only | 2 | 7 | 0 | 9 | 0.611 | 0.563 | 1.000 | 0.720 | 0.778 | 0.000 |
| ml_only_conservative | 7 | 2 | 6 | 3 | 0.556 | 0.600 | 0.333 | 0.429 | 0.222 | 0.667 |
| **combined** | 7 | 2 | 0 | 9 | 0.889 | 0.818 | 1.000 | 0.900 | 0.222 | 0.000 |
| combined_corroborated | 9 | 0 | 0 | 9 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |

**`unseen.jsonl` (n=24: 12 / 12)**

| config | TN | FP | FN | TP | acc | P | R | F1 | FPR | FNR |
|---|---|---|---|---|---|---|---|---|---|---|
| rules_only | 12 | 0 | 0 | 12 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| rules_ast | 12 | 0 | 0 | 12 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| ml_only | 5 | 7 | 0 | 12 | 0.708 | 0.632 | 1.000 | 0.774 | 0.583 | 0.000 |
| ml_only_conservative | 12 | 0 | 9 | 3 | 0.625 | 1.000 | 0.250 | 0.400 | 0.000 | 0.750 |
| **combined** | 12 | 0 | 0 | 12 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| combined_corroborated | 12 | 0 | 0 | 12 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |

**`hard_eval.jsonl` (n=15: 8 / 7)**

| config | TN | FP | FN | TP | acc | P | R | F1 | FPR | FNR |
|---|---|---|---|---|---|---|---|---|---|---|
| rules_only | 7 | 0 | 0 | 8 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| rules_ast | 7 | 0 | 0 | 8 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| ml_only | 2 | 5 | 0 | 8 | 0.667 | 0.615 | 1.000 | 0.762 | 0.714 | 0.000 |
| ml_only_conservative | 7 | 0 | 7 | 1 | 0.533 | 1.000 | 0.125 | 0.222 | 0.000 | 0.875 |
| **combined** | 7 | 0 | 0 | 8 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| combined_corroborated | 7 | 0 | 0 | 8 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |

**Pooled over the three curated sets (n=57: 29 risky / 28 safe)**

| config | acc | P | R | F1 | FPR | FNR | MCC |
|---|---|---|---|---|---|---|---|
| rules_only | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 1.000 |
| rules_ast | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 1.000 |
| ml_only (0.48) | 0.667 | 0.604 | 1.000 | 0.753 | 0.679 | 0.000 | 0.441 |
| ml_only_conservative (0.64) | 0.579 | 0.778 | 0.241 | 0.368 | 0.071 | 0.759 | 0.233 |
| **combined** | 0.965 | 0.936 | 1.000 | 0.967 | 0.071 | 0.000 | 0.932 |
| combined_corroborated | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 1.000 |

**Per-category (combined).** On all three sets every category with labelled
support scores P=R=F1=1.000. There are no category-level errors after the retrain.

**Broader supplied corpus (`training/merged_dataset.jsonl`, 158 rows).** This is
the ML training pool, so its ML numbers are optimistic and are **not** a
generalization result; it is shown to quantify the deterministic recall gap.

| config | TN | FP | FN | TP | acc | P | R | F1 |
|---|---|---|---|---|---|---|---|---|
| rules_only | 68 | 2 | 57 | 31 | 0.627 | 0.939 | 0.352 | 0.512 |
| rules_ast | 68 | 2 | 53 | 35 | 0.652 | 0.946 | 0.398 | 0.560 |
| combined | 68 | 2 | 7 | 81 | 0.943 | 0.976 | 0.921 | 0.947 |

**Error analysis.** There are now 2 FP/FN records across the three curated sets,
both false positives on `dev.jsonl`, both from ML escalation on benign code that
uses the same APIs as the attacks:

| snippet | ML score | threshold |
|---|---|---|
| `pip install requests` | 0.6476 | 0.64 |
| `requests.get('https://example.com')` | 0.6541 | 0.64 |

Both sit just above the escalation threshold. Root cause: the risky examples in the
training corpus over-represent network/install APIs, so the model over-flags benign
uses. Recorded in `results/*.eval.json` with redacted previews, rule IDs, language
and provenance. No rule was changed on the basis of a single error.

The 73-sample suite has 5 documented gaps: the 2 above (`safe_pip`,
`edge_unrelated_attr`), 2 rule-layer false positives on a dangerous-looking string
and comment (`edge_string_only`, `edge_comment_in_python`), and 1 false negative
where neither layer fires (`edge_systemd_unit`). Every gap carries a recorded
`gap_cause` and `tests/test_examples.py` fails if a sample starts differing for any
other reason.

**Honest generalization estimate.** The out-of-fold numbers are the ones to trust:
ML alone reaches precision 0.939, recall 0.352 and FPR 0.029 at the escalation
threshold. The curated 1.000 figures reflect a small, rule-informed dataset.

---

## 8. Latency and model size

Method: cold start in a fresh subprocess (includes interpreter start and imports);
warm latency in-process after 50 warm-up calls, 1000 calls per configuration, with
snippets already in memory (no dataset I/O, no network). Machine: AMD64, Windows,
Python 3.12.10, scikit-learn 1.9.1.

| configuration | p50 ms | p95 ms | mean ms | n |
|---|---|---|---|---|
| language_only | 0.043 | 0.055 | 0.043 | 1000 |
| rules_only | 0.057 | 0.078 | 0.060 | 1000 |
| ast_only | 0.017 | 0.026 | 0.018 | 1000 |
| ml_only | 0.729 | 1.024 | 0.770 | 1000 |
| **combined** | **1.030** | **2.087** | **1.303** | 1000 |
| combined_corroborated | 1.876 | 3.195 | 2.111 | 1000 |

Cold start: **≈1.30 s** with ML loaded (≈1.20 s is importing scikit-learn) versus
**≈162 ms** deterministic-only. Model artefact **570,928 bytes**; manifest 20,890
bytes. Raw: `results/benchmark.json`.

These figures are from one run on the machine above; they move with CPU load and
are not a guarantee. Re-run `py -3 -m benchmark` to reproduce on your hardware.

**Trade-off.** ML escalation costs ~0.73 ms/call, ~1.2 s of cold start and the
false positives above; it raises recall from 0.398 to 0.921 on the supplied corpus
(and lifts ML-only recall to 1.000 on the curated sets at its decision threshold).
Running without the model is ~8× faster to start and removes the ML-driven FPs.
These figures are machine-dependent and are not a guarantee.

---

## 9. Known limitations

* Language coverage: Python gets a real AST pass; bash/SQL/JavaScript/YAML/Markdown
  are regex-only. Detection is heuristic: 72/72 (100%) on tracked language labels,
  231/232 (99.6%) including the supplied corpora.
* AST analysis is syntactic — no taint or data flow. Read-then-send
  `data_exfiltration` findings are heuristic correlations, not proven flow.
* `dependency_risk` has 4 labelled examples and 3 typosquat patterns; it is not a
  general dependency-risk detector.
* SSRF matching covers private IPv4 and the metadata IP only — no IPv6, no URL
  parsing.
* Obfuscation handling is single-level (no recursive base64/hex unwrap).
* Deterministic recall is low on shapes the rules were not written for:
  `sudo rm -rf "$HOME"`, `chmod -R 777 /etc`, `rm -rf /var/www/*` (now covered after
  the language fix), `TRUNCATE TABLE`, `verify=False`, `POSTGRES_URL` hardcodes.
* `PY_SQLI_001` false-positives on an f-string interpolating only constant
  identifiers; `PY_SSRF_ARBITRARY_001` false-positives on code that validates the
  URL before fetching; and the rule layer scans raw text including comments and
  string literals, so a quoted string or comment that merely looks like a
  dangerous call can block (the AST layer correctly ignores both).
* ML escalation still false-positives on benign code that installs packages or
  calls an unrelated `.system()` (`pip install requests` scored 0.648 against the
  0.64 threshold).
* Interception is decorator-only; it is not a sandbox.
* The curated evaluation sets are small and were used while authoring the rules;
  `hard.jsonl` mirrors `hard_eval.jsonl`; the synthetic corpus is generated. No
  claim of real-world security coverage is made.
* `ml_score` is uncalibrated.
* ML is binary; no nine-class model was trained (the data does not support one).

---

## 10. How I run it

From a clean environment (verified in a fresh venv on 2026-10-24):

    py -3 -m venv .venv
    .venv\Scripts\python -m pip install -r requirements.txt           # Windows
    # source .venv/bin/activate && pip install -r requirements.txt     # POSIX

    .venv\Scripts\python -m pytest -q                                   # 193 passed
    .venv\Scripts\python -m textcodeguard.demo.intercept_check           # PASS
    .venv\Scripts\python -m textcodeguard.evaluate dev.jsonl            # metrics
    .venv\Scripts\python -m textcodeguard.evaluate unseen.jsonl
    .venv\Scripts\python -m textcodeguard.evaluate hard_eval.jsonl
    .venv\Scripts\python -m benchmark                                   # latency/size
    .venv\Scripts\python -m examples.run_samples                        # 73 verified samples
    .venv\Scripts\python -m training.build_dataset                      # rebuild merged data
    .venv\Scripts\python -m training.train_model                        # retrain + manifest
    .venv\Scripts\python -m uvicorn textcodeguard.api:app --port 8000    # serve

Service smoke test:

    curl -s -X POST localhost:8000/check -H 'content-type: application/json' -d "{\"code\":\"import os\nos.system('rm -rf /')\"}"
    curl -s -X POST localhost:8000/check/raw --data-binary @generated.py
    curl -s -X POST localhost:8000/batch --data-binary @examples/batch_test.json -H 'content-type: application/json'

---

## 11. Remaining work

1. **ML escalation false positives** (8 on the curated sets) — rebalance the
   training corpus with benign network/subprocess/install/JSON examples and
   re-select the escalation threshold on out-of-fold data. Measure before/after.
2. **Deterministic recall gap** — add rules for the uncovered destructive,
   permission, DB and TLS shapes listed in §9. Each needs a positive and negative
   test and must not regress the curated sets.
3. **SSRF rule precision** — detect a preceding allowlist/`startswith` validation
   instead of relying on a constant-vs-variable width heuristic.
4. **`PY_SQLI_001` precision** — distinguish constant-only interpolation from
   user-input interpolation; today it cannot.
5. **AST depth** — resolve `getattr`/indirect calls and add intra-function data
   flow to turn read-then-send correlations into real flow statements.
6. **Calibration** — isotonic/Platt on out-of-fold scores before `ml_score` is
   presented as anything more than a score.
7. **Larger independent evaluation** — a held-out corpus authored *without*
   knowledge of the rules, plus per-category support (several categories have ≤4
   labelled examples).
8. **Interception breadth** — optionally a subprocess/file-write wrapper, clearly
   scoped and tested; the current decorator remains narrow by design.
