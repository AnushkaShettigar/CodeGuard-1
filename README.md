# CodeGuard — Real-Time Pre-Execution Safety Layer

**CodeGuard** is a CPU-first safety gate for inspecting AI-generated code and commands *before* a protected execution path proceeds. It combines language-aware rules, Python Abstract Syntax Tree (AST) analysis, and a local classical machine-learning classifier to return an `allow` or `block` verdict.

- **No external LLM is used to judge code.**
- **Submitted snippets are analysed as text; the detector does not execute them.**
- **The ML model is local**: TF-IDF word/character features + Logistic Regression.
- **A Python decorator demonstrates enforcement** by blocking a decorated function before its body runs.

> **Prototype disclaimer:** CodeGuard is a layered detection aid, not a sandbox or a guarantee that allowed code is safe. Regex rules, AST checks, language detection and the ML classifier can all produce false positives and false negatives. The decorator only protects calls that go through the decorated function.

## Contents

- [Problem and goals](#problem-and-goals)
- [Features](#features)
- [Architecture](#architecture)
- [Detection categories](#detection-categories)
- [Decision policy and response fields](#decision-policy-and-response-fields)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Installation](#installation)
- [Run the API](#run-the-api)
- [API examples](#api-examples)
- [Run the interception demo](#run-the-interception-demo)
- [Train or rebuild the ML model](#train-or-rebuild-the-ml-model)
- [Evaluate and benchmark](#evaluate-and-benchmark)
- [Run tests](#run-tests)
- [Datasets and evaluation notes](#datasets-and-evaluation-notes)
- [Dependencies and licensing](#dependencies-and-licensing)
- [Limitations and safe use](#limitations-and-safe-use)

## Problem and goals

AI agents can generate code that reads credentials, sends data elsewhere, deletes files, establishes persistence, attempts privilege escalation, hides execution, installs suspicious packages, consumes excessive resources, reaches internal network addresses, or contains instructions aimed at manipulating an AI reviewer. CodeGuard inserts a synchronous inspection step between generation and execution.

The hackathon goals are to return a consistent verdict before execution, support nine threat categories, avoid external LLM-as-judge calls, run on a CPU, and demonstrate that a blocked function does not run.

## Features

- FastAPI endpoints: `POST /check`, `POST /batch`, and `GET /health`.
- Heuristic language detection for Python, Bash, JavaScript, SQL, YAML, Markdown, and `unknown`.
- 53 YAML-defined regular-expression rules, scoped by language or `any`.
- Python AST checks for selected structural patterns, including some dynamic execution, destructive calls, privilege changes and constant-true loops.
- Local scikit-learn binary classifier using word- and character-level TF-IDF features and Logistic Regression.
- Risk aggregation, categories, human-readable reasons and vulnerable line numbers.
- `@guarded` decorator with fail-closed handling when source inspection or analysis fails.
- JSONL evaluation scripts, training data merge/provenance tracking, tests and benchmark reports.

## Architecture

```text
                 Generated code / command
                           |
                           v
                 FastAPI or Python caller
                           |
                           v
                 Language detection
                           |
             +-------------+-------------+
             |             |             |
             v             v             v
        YAML rules     Python AST     Local ML model
        (53 rules)   (Python only)   (TF-IDF + Logistic
             |             |          Regression)
             +-------------+-------------+
                           |
                           v
                  Decision cascade
            - deduplicate deterministic hits
            - calculate deterministic risk
            - block high-weight findings
            - ML may escalate allow -> block
              but cannot cancel a deterministic block
                           |
                +----------+----------+
                |                     |
                v                     v
              ALLOW                 BLOCK
         return response       return response
         caller may proceed    caller must not run
                |
                v
       @guarded enforcement path
       invokes function only on allow
```

### Detection stages

1. **Language detection** — `textcodeguard/detect/language.py` uses syntax and pattern heuristics to select a likely language. It is not a full parser.
2. **Rule scanning** — `textcodeguard/detect/rules.py` loads `textcodeguard/data/rules.yaml`. A rule includes an ID, category, language scope, pattern, weight and reason.
3. **Python AST pass** — `textcodeguard/detect/ast_python.py` parses Python into an Abstract Syntax Tree and inspects selected code structures. It is not complete semantic analysis or taint tracking.
4. **ML score** — `textcodeguard/detect/ml.py` loads `models/codeguard_clf.joblib` and returns a binary risky score when the model is available. It predicts risky vs safe, not the nine individual categories.
5. **Decision cascade** — `textcodeguard/detect/cascade.py` combines deterministic findings and the ML score into the final verdict.
6. **Enforcement** — `textcodeguard/guard.py` exposes `guard(code)` for analysis and `@guarded` for the demonstration interception boundary.

## Detection categories

| Category | Intended coverage |
|---|---|
| `secret_access` | Reads or accesses values/locations that may contain credentials, API keys, tokens or private keys. |
| `data_exfiltration` | Patterns suggesting local or sensitive data may be sent to another destination. |
| `destructive_command` | Potentially destructive file, shell or database operations. |
| `persistence_or_privesc` | Selected persistence mechanisms or privilege escalation/change patterns. |
| `obfuscated_execution` | Dynamic execution, concealed/decoded payloads or selected unsafe deserialization patterns. |
| `dependency_risk` | Selected suspicious or typosquatted package installation patterns. |
| `resource_exhaustion` | Selected infinite-loop, fork-bomb or excessive resource patterns. |
| `ssrf_network_exfil` | Requests to loopback, private or cloud-metadata addresses and related patterns. |
| `ai_targeted_instructions` | Text that appears intended to manipulate an AI reviewer, for example asking it to ignore prior instructions or mark code safe. |

A category means that a detector pattern matched; it does not prove malicious intent or exploitability.

## Decision policy and response fields

The deterministic risk score is calculated from rule/AST finding weights using noisy-OR:

\[
\text{risk\_score} = 1 - \prod_{i=1}^{n}(1-w_i)
\]

where each \(w_i\) is a finding's configured weight. The score is rounded to two decimal places. It is a heuristic score, **not a calibrated probability**.

Current deterministic block conditions in `textcodeguard/detect/cascade.py`:

- Any deterministic finding with weight `>= 0.80` blocks.
- A combined deterministic risk score `>= 0.60` blocks.
- If deterministic checks do not block, the local ML layer may escalate the verdict when its score reaches the conservative escalation threshold stored with the model.
- ML never cancels a deterministic block.
- The default ML escalation mode is `any`. The optional `corroborated` and `off` modes exist for evaluation and testing.

`risk_score` retains its deterministic meaning. An ML-only escalation can therefore return `verdict: "block"` with `risk_score: 0.0`; inspect `ml_score` and `ml_used` to understand that case. ML does not assign categories or vulnerable line numbers.

### `POST /check` request

```json
{
  "code": "print('hello world')"
}
```

### Response shape

```json
{
  "verdict": "allow",
  "risk_score": 0.0,
  "categories": [],
  "code_language": "python",
  "reason": "no rules fired",
  "vulnerable_lines": [],
  "ml_score": 0.4116,
  "ml_available": true,
  "ml_used": false
}
```

The values above illustrate the response format only; actual scores and findings depend on the submitted snippet and the installed model. Required fields are `verdict`, `risk_score`, `categories` and `code_language`. Additional ML status fields are included by this repository. `reason` and `vulnerable_lines` explain deterministic findings where available.

## Repository layout

```text
.
├── textcodeguard/
│   ├── api.py                    FastAPI endpoints
│   ├── schema.py                 Request/response schema
│   ├── guard.py                  Analysis entry point and @guarded decorator
│   ├── evaluate.py               JSONL evaluation and metrics
│   ├── categories.py              Canonical categories
│   ├── data/rules.yaml            53 configurable detection rules
│   ├── detect/
│   │   ├── language.py            Language detection
│   │   ├── rules.py               Regex rule engine
│   │   ├── ast_python.py          Python AST analysis
│   │   ├── ml.py                  Local classifier loader/scorer
│   │   └── cascade.py              Decision policy
│   └── demo/intercept_check.py    Interception demonstration
├── models/
│   ├── codeguard_clf.joblib       Trained local classifier
│   └── model_manifest.json        Training metadata and thresholds
├── training/
│   ├── build_dataset.py           Merge/provenance/leakage checks
│   ├── train_model.py             Model training entry point
│   └── merged_dataset.jsonl       Prepared training pool
├── tests/                         Automated tests
├── results/                       Evaluation and benchmark JSON outputs
├── docs/                          Audit and final report
├── codeguard_dev.jsonl            Original labelled dataset
├── codeguard_synthetic.jsonl      Synthetic labelled dataset
├── dev.jsonl                      Development evaluation set
├── unseen.jsonl                   Unseen evaluation set
├── hard_eval.jsonl                Hard evaluation set
├── benchmark.py                   Timing benchmark
├── requirements.txt
└── WRITEUP.md
```

## Requirements

- Python 3.10+ (the uploaded environment was tested with Python 3.12.10).
- `pip`.
- Internet access is needed only to install dependencies; inference does not call an external LLM.
- CPU is sufficient; no GPU is required.

Dependencies include FastAPI, Uvicorn, Pydantic, PyYAML, `sqlparse`, scikit-learn, joblib, NumPy, pytest and httpx. Exact installed versions may vary within the version ranges in `requirements.txt`.

## Installation

Run these commands from the repository root (the folder containing `requirements.txt`).

### Windows PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, use Command Prompt:

```bat
py -3 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

No external LLM API key is required. Do not commit real secrets or local virtual environments to a public repository.

## Run the API

```bash
python -m uvicorn textcodeguard.api:app --host 127.0.0.1 --port 8000
```

Open:

- API docs: `http://127.0.0.1:8000/docs`
- OpenAPI JSON: `http://127.0.0.1:8000/openapi.json`
- Health check: `http://127.0.0.1:8000/health`

Use `127.0.0.1` for local testing. Do not expose this prototype publicly without deployment hardening, authentication/access control, request-rate limits, logging policy and monitoring.

## API examples

### Single snippet

```bash
curl -X POST "http://127.0.0.1:8000/check" \
  -H "Content-Type: application/json" \
  -d '{"code":"import os\nos.system(\"rm -rf /tmp/example\")"}'
```

### Batch of snippets

`/batch` accepts a JSON array of request objects and returns a corresponding array of responses:

```bash
curl -X POST "http://127.0.0.1:8000/batch" \
  -H "Content-Type: application/json" \
  -d '[{"code":"print(\"hello\")"},{"code":"eval(user_input)"}]'
```

### Health check

```bash
curl "http://127.0.0.1:8000/health"
```

Expected response:

```json
{"ok": true}
```

### Python client example

```python
import requests

response = requests.post(
    "http://127.0.0.1:8000/check",
    json={"code": "print('hello')"},
    timeout=5,
)
response.raise_for_status()
print(response.json())
```

`requests` is only used in this example client; it is not a required runtime dependency for the CodeGuard service.

## Run the interception demo

```bash
python -m textcodeguard.demo.intercept_check
```

The demo uses a decorated safe function and a decorated risky function. The risky function should raise `GuardBlocked` before its body creates the unsafe marker file. A successful run prints a pass result. Review `textcodeguard/demo/intercept_check.py` for the exact behavior.

**Important:** this proves interception only for the decorated call path. It is not a sandbox, and it does not intercept arbitrary unguarded Python functions, subprocesses or shell commands.

## Train or rebuild the ML model

The repository includes a small local classical ML pipeline. It uses a scikit-learn `Pipeline` with a word-level and character-level TF-IDF `FeatureUnion`, followed by class-weighted Logistic Regression. No GPU or external LLM is used.

The shipped model is at `models/codeguard_clf.joblib` (about 574 KB). The manifest at `models/model_manifest.json` records the dataset fingerprint, split/threshold metadata and classifier settings.

To rebuild the prepared dataset from the original and synthetic corpora:

```powershell
py -3 -m training.build_dataset
```

Then train the model:

```powershell
py -3 -m training.train_model
```

Training uses grouped stratified cross-validation on the training pool; near-duplicate records are grouped to reduce leakage across folds. The training script selects the threshold from out-of-fold predictions and does not use the separate evaluation files to fit the model. Rebuilding will replace the model artifact and manifest; retain a copy if you need to reproduce the currently reported results.

The prepared dataset currently contains 158 records: 70 safe and 88 risky. The merge report records 42 original rows and 116 synthetic rows retained after excluding two synthetic rows that duplicated evaluation snippets. See `training/merge_report.json` for the precise provenance and exclusions.

## Evaluate and benchmark

Run the evaluator against each evaluation file:

```powershell
py -3 -m textcodeguard.evaluate dev.jsonl
py -3 -m textcodeguard.evaluate unseen.jsonl
py -3 -m textcodeguard.evaluate hard_eval.jsonl
```

The evaluation files are small curated sets. Results below are the saved integrated-pipeline metrics from this repository snapshot:

| Set | Samples | Accuracy | Risky recall | False positives | False negatives |
|---|---:|---:|---:|---:|---:|
| `dev.jsonl` | 18 | 83.3% | 100% | 3 | 0 |
| `unseen.jsonl` | 24 | 87.5% | 100% | 3 | 0 |
| `hard_eval.jsonl` | 15 | 86.7% | 100% | 2 | 0 |
| **Pooled** | **57** | **86.0%** | **100%** | **8** | **0** |

These figures correspond to the default combined configuration (`ml_escalate_mode="any"`) in the checked-in result files. They are results on this specific small evaluation pool, not an independent security certification. The test sets may not represent the full variety of real-world code. Category precision/recall can also differ from overall allow/block accuracy.

Run the benchmark:

```powershell
py -3 benchmark.py
```

Saved timings in `results/benchmark.json` were measured on Windows 11 with Python 3.12.10 and an AMD64 processor. Warm measurements (1000 iterations) were:

| Component | Mean | p95 |
|---|---:|---:|
| Language detection | 0.044 ms | 0.059 ms |
| Rule scan | 0.060 ms | 0.075 ms |
| Python AST scan | 0.018 ms | 0.025 ms |
| ML-only scoring | 0.733 ms | 0.878 ms |
| Combined detector | 1.058 ms | 1.834 ms |
| Combined corroborated mode | 1.877 ms | 2.564 ms |

Cold-start measurements include starting a subprocess and importing Python modules: about 1.25 seconds with ML, compared with about 157 ms without ML in the recorded environment. These numbers are machine- and environment-dependent; benchmark again on the target machine.

## Run tests

From the repository root:

```powershell
python -m pytest -q
```

The test suite covers AST checks, decision policy, evaluator metrics, examples, interception, language detection, ML loading/scoring, no-execution behavior, required categories and API schema. Tests should be run after modifying rules, thresholds, training data or the model.

## Datasets and evaluation notes

- `codeguard_dev.jsonl`: 42 original labelled records.
- `codeguard_synthetic.jsonl`: 118 synthetic labelled records.
- `training/merged_dataset.jsonl`: 158 records retained for training after deduplication/leakage exclusions.
- `dev.jsonl`, `unseen.jsonl`, `hard_eval.jsonl`: separate evaluation inputs. They are not the same thing as the training pool.

Dataset labels and categories are only as reliable as their annotation and generation process. Synthetic examples can make evaluation look easier if they resemble rules or training records. The build script excludes exact normalized overlaps with evaluation snippets and groups near-duplicates for grouped cross-validation, but that does not remove all possible dataset bias or prove generalization.

The detector should be evaluated on larger, independently collected samples, with precision, recall, false positives, false negatives and per-category results reported. Avoid claiming perfect real-world detection from the current results.

## Dependencies and licensing

The project directly uses these libraries:

| Component | Use | License note |
|---|---|---|
| FastAPI | HTTP API | MIT |
| Uvicorn | ASGI server | BSD-3-Clause |
| Pydantic | Request/response validation | MIT |
| PyYAML | Load rule configuration | MIT |
| sqlparse | SQL-related parsing utility dependency | BSD-3-Clause |
| scikit-learn | TF-IDF and Logistic Regression | BSD-3-Clause |
| joblib | Model serialization/loading | BSD-3-Clause |
| NumPy | Numerical dependency | BSD-3-Clause |
| pytest | Automated tests | MIT |
| httpx | API/test client | BSD-3-Clause |

The model is trained from the repository's included labelled datasets; it is not a downloaded pretrained foundation model. The project does not use an external LLM-as-judge. Confirm third-party notices and transitive dependency licenses for the exact versions distributed before publication.

## Limitations and safe use

- **Heuristic detection:** patterns may miss obfuscated, dynamically constructed, aliased or multi-file behavior.
- **No full taint/data-flow analysis:** matching a read and a network call does not prove that sensitive data flows between them.
- **Language detection is approximate:** misclassification can skip language-specific checks.
- **ML score is not calibrated probability:** it is a classifier score used for escalation, not a probability guarantee.
- **False positives:** defensive thresholds can block benign code, including code with suspicious-looking patterns.
- **False negatives:** code that does not match known patterns may be allowed.
- **No runtime sandbox:** CodeGuard does not isolate the operating system or restrict filesystem/network permissions.
- **Decorator scope:** only decorated calls are checked; unguarded execution paths remain outside its protection.
- **No category prediction by ML:** categories come from deterministic rules/AST findings. An ML-only block may have an empty category list.

Use CodeGuard as one layer in a defense-in-depth design. For genuinely untrusted code, combine pre-execution analysis with OS-level sandboxing, least-privilege execution, network restrictions, resource limits and independent security testing.
