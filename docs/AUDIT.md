# CodeGuard — Repository Audit

Date: 2026-10-24
Scope: the `CodeGuard-1` working tree at `C:\cogni`.
Method: read-only inspection of every source file plus runtime verification of the
existing evaluation and interception demo. No project file was modified to produce
this audit.

## 1. What is present

| Area | Path | State |
|---|---|---|
| Language detection | `textcodeguard/detect/language.py` | working, heuristic |
| Regex rules | `textcodeguard/detect/rules.py` + `data/rules.yaml` | 53 rules, unique IDs |
| Python AST | `textcodeguard/detect/ast_python.py` | working, small |
| Decision cascade | `textcodeguard/detect/cascade.py` | working, noisy-OR |
| Response schema | `textcodeguard/schema.py` | Pydantic v2, 6 fields |
| Guard / decorator | `textcodeguard/guard.py` | working, contains a fail-open bug |
| Service | `textcodeguard/api.py` | `/check`, `/batch`, `/health` |
| Evaluation | `textcodeguard/evaluate.py` | working, metrics are thin |
| Interception demo | `textcodeguard/demo/intercept_check.py` | passes today |
| Tests | `tests/` | **absent** |
| Classical ML | any | **absent** |
| Benchmark script | any | **absent** |

Tracked datasets: `dev.jsonl` (18), `unseen.jsonl` (24), `hard.jsonl` (15),
`hard_eval.jsonl` (15). Untracked supplied datasets: `codeguard_dev.jsonl` (42),
`codeguard_synthetic.jsonl` (118).

## 2. Verified behaviour (commands actually run)

| Command | Result |
|---|---|
| `py -3 -m textcodeguard.evaluate dev.jsonl` | `OVERALL acc=1.000 ... n=18` |
| `py -3 -m textcodeguard.evaluate unseen.jsonl` | `OVERALL acc=1.000 ... n=24` |
| `py -3 -m textcodeguard.evaluate hard_eval.jsonl` | `acc=1.000`, but `ssrf_network_exfil P=0.50 F1=0.67` |
| `py -3 -m textcodeguard.demo.intercept_check` | `PASS` (exit 0) |
| `py -3 -m pip list` | scikit-learn 1.9.1, joblib 1.6.0, numpy 2.5.3, fastapi, pydantic, pyyaml present; **pytest, httpx, sqlparse absent** |

The reported per-call latency in `evaluate.py` includes the cold first call, which is
why `p95` prints around 15 ms while the true warm `p50` is about 0.08 ms.

## 3. Confirmed defects and gaps

These map directly to sections of `final.md`.

1. **Fail-open interception** (`guard.py`). `inspect.getsource` failure (`OSError`) is
   swallowed and replaced with `src = ""`; `analyze("")` returns `allow`, so the
   protected function body still runs. Only `OSError` is handled — `TypeError`, an
   empty source, a detector exception, or a malformed verdict are unguarded.
   (§6)
2. **No classical ML.** There is no feature extraction, no training entry point, no
   model artefact, no manifest, and no fallback path. (§4)
3. **No test suite.** Every guarantee in the README is unverified by automated tests. (§9)
4. **Evaluation is not leakage-resistant and reports too little.** No confusion matrix,
   no per-class recall, no FP/FN records, no ablations, no grouping of near-duplicates,
   and the three "evaluation" files were used while authoring the rules. (§5)
5. **No dataset merge or provenance.** Two label conventions (int `label` vs string
   `verdict`), two category conventions, and no source field on the original corpus. (§3)
6. **Detection weaknesses.** AST matches only the final attribute name, resolves no
   import aliases, and detects loop `break` with `ast.walk` so an inner `break` in a
   nested loop is credited to the outer loop. (§7)
7. **Cascade is effectively "any hit blocks".** `blocked = any(weight >= 0.8) or risk >= 0.6`
   means the risk-threshold branch is almost never the deciding factor, and findings are
   not de-duplicated. (§7)
8. **API has no input limit and no error handling.** A detector exception surfaces as a
   500 with a traceback; there is no size cap and no ML/fallback status field. (§8)
9. **No benchmark script** and no cold/warm separation. (§10)
10. **Documentation overstates results.** README says "all 9 categories F1=1.00" for the
    hard set, but SSRF is 0.50/0.67, and quotes p95 as 1.06 ms without stating it
    excludes the cold call. (§11)

## 4. Preserved interfaces (must not break)

- `POST /check` body `{"code": "..."}` → `CheckResponse`.
- `POST /batch` body `[{"code": "..."}]` → `[CheckResponse]`.
- `GET /health` → `{"ok": true}`.
- `CheckResponse` existing fields: `verdict`, `risk_score`, `categories`,
  `code_language`, `reason`, `vulnerable_lines`.
- `guard.guard(code) -> dict`.
- `guard.guarded(fn)` decorator and `guard.GuardBlocked`.

New response fields are additive and optional so existing clients keep working.
