# CodeGuard — Dataset Audit

Date: 2026-10-24
Method: static parse of each JSONL file only. No dataset snippet was executed.
Snippets are treated as data throughout.

## 1. Files and record counts

| File | Tracked | Records | Blank lines | Malformed JSON |
|---|---|---|---|---|
| `codeguard_dev.jsonl` | no (supplied) | 42 | 0 | 0 |
| `codeguard_synthetic.jsonl` | no (supplied) | 118 | 0 | 0 |
| `hard.jsonl` | yes | 15 | 0 | 0 |
| `hard_eval.jsonl` | yes | 15 | 0 | 0 |
| `dev.jsonl` | yes | 18 | 0 | 0 |
| `unseen.jsonl` | yes | 24 | 0 | 0 |

## 2. Schemas

Two distinct schema families exist.

**Labelled family** — `codeguard_dev.jsonl`, `hard.jsonl`
fields: `code:str`, `id:str`, `label:int`, `language:str`, `category:str`, `rationale:str`

**Partially-labelled family** — `codeguard_synthetic.jsonl`
fields: `code:str`, `label:int`, `language:str`, `category:str`, `synthetic:bool`
(no `id`, no `rationale`)

**Verdict family** — `dev.jsonl`, `unseen.jsonl`, `hard_eval.jsonl`
fields: `code:str`, `verdict:str ("allow"|"block")`, `categories:list[str]`, `language:str`
(no explicit `label`; the risky label is derived from `verdict == "block"`)

## 3. Labels

| File | label 0 | label 1 | block | allow |
|---|---|---|---|---|
| `codeguard_dev.jsonl` | 12 | 30 | — | — |
| `codeguard_synthetic.jsonl` | 59 | 59 | — | — |
| `hard.jsonl` | 7 | 8 | — | — |
| `hard_eval.jsonl` | — | — | 8 | 7 |
| `dev.jsonl` | — | — | 9 | 9 |
| `unseen.jsonl` | — | — | 12 | 12 |

`label` is always an `int` where present. `0 = safe`, `1 = risky` is consistent with the
`verdict`-family files: every `hard.jsonl` row's label maps to the matching
`hard_eval.jsonl` verdict (`label==1 ⇔ verdict=="block"`, verified for all 15 rows).
No malformed labels, no duplicate IDs, no empty `code` fields, no duplicate codes within
any single file.

## 4. Category conventions — three different things share the name "category"

1. **Canonical nine** (used by `dev.jsonl`, `unseen.jsonl`, `hard_eval.jsonl`, and by
   risky rows of `codeguard_dev.jsonl` / `hard.jsonl`):
   `secret_access`, `data_exfiltration`, `destructive_command`, `persistence_or_privesc`,
   `obfuscated_execution`, `dependency_risk`, `resource_exhaustion`,
   `ssrf_network_exfil`, `ai_targeted_instructions`.
2. **Benign topic tags** — `codeguard_dev.jsonl` safe rows use `benign`;
   `codeguard_synthetic.jsonl` safe rows use free-form topics such as `logging`,
   `json_parse`, `parameterized_sql`, `safe_subprocess`. These are *not* risk categories.
3. **Free-form risk tags** — `codeguard_synthetic.jsonl` risky rows use ~30 labels that do
   **not** match the canonical nine, e.g. `command_injection`, `hardcoded_secret`,
   `destructive_sql`, `dynamic_execution`, `tls_disabled`, `remote_shell`,
   `unsafe_deserialization`. Only `obfuscated_execution` and `data_exfiltration` coincide.

Consequences:
- A nine-class classifier cannot be trained from this data; the synthetic category
  vocabulary would have to be manually mapped, and that mapping is not given.
- Only `codeguard_dev.jsonl` + `hard.jsonl` risky rows carry canonical category labels.
- One `codeguard_dev.jsonl` row (`cg_multi_0001`) comma-joins three categories in one
  string: `"resource_exhaustion, ssrf_network_exfil, dependency_risk"`.

The merge therefore emits both `category_raw` (verbatim) and `category` (canonical or
empty). Binary label and category label are kept strictly separate.

## 5. Provenance

- Only `codeguard_synthetic.jsonl` marks itself, via `synthetic: true`.
- `codeguard_dev.jsonl` and `hard.jsonl` carry no `source` field; IDs are prefixed
  `cg_*` and correlate with the category (e.g. `cg_data_exfiltration_0011`).
- `dev.jsonl`, `unseen.jsonl`, `hard_eval.jsonl` carry no provenance field.

No file claims to be real-world production data, and none is described here as such.
The merge adds an explicit `source` field (`original` vs `synthetic`) rather than
inventing a claim.

## 6. Duplicates and overlap

- No exact duplicate code within any single file.
- **Exact cross-file duplicates (2):**
  - `codeguard_synthetic.jsonl` risky row (`category=destructive_shell`) is identical to a
    `dev.jsonl` `block` row (`destructive_command`).
  - `codeguard_synthetic.jsonl` safe row (`category=select`) is identical to an
    `unseen.jsonl` `allow` row.
- **Near-duplicate pair (1)** inside `codeguard_synthetic.jsonl` (token Jaccard ≥ 0.8).
- `hard.jsonl` and `hard_eval.jsonl` are the **same 15 snippets** in the same order, one
  labelled and one carrying a verdict. The "third-party hard set" is therefore not an
  independent sample from `hard.jsonl`.

Leakage handling:
- The two synthetic rows that duplicate evaluation snippets are **excluded from training**
  by `training/build_dataset.py` (recorded in the merge report), so no training example is
  byte-identical to an evaluation example.
- Near-duplicates inside the training pool are clustered into a shared `dup_group` and
  never split across train/validation.
- `dev.jsonl` and `unseen.jsonl` were used while authoring the rules, so they are reported
  as **development/tuned** sets, not as untouched test sets.

## 7. Category coverage across all risky records

| Category | Count |
|---|---|
| secret_access | 8 |
| data_exfiltration | 11 |
| destructive_command | 11 |
| persistence_or_privesc | 6 |
| obfuscated_execution | 10 |
| dependency_risk | 4 |
| resource_exhaustion | 6 |
| ssrf_network_exfil | 6 |
| ai_targeted_instructions | 8 |

`dependency_risk` is the thinnest category (4 examples), so per-category results for it
are small-sample and are reported with that caveat.

## 8. Quality observations (nothing silently dropped)

- No contradictory or mislabelled rows were found in the labelled corpus.
- Safe rows in `codeguard_synthetic.jsonl` are short and template-like (e.g. `logging`,
  `index`, `select`); they are low-diversity, which is expected for synthetic data and is
  reported rather than hidden.
- Several risky synthetic rows are deliberately similar in shape across languages
  (e.g. command injection in Python/JS/SQL/bash), forming small template families. The
  `dup_group` clustering keeps such families together during splitting.
- No row is removed for being "trivial"; only the two evaluation-duplicating rows are
  excluded, and the reason is recorded.

## 9. Files preserved

All six input datasets are left byte-for-byte unchanged, with **one documented
exception**: a Slack-token-shaped literal in a `secret_access` /
`hardcoded_secret` example was replaced with the explicit placeholder
`EXAMPLE-SLACK-TOKEN-NOT-REAL` in `codeguard_dev.jsonl` and
`codeguard_synthetic.jsonl`. GitHub push protection rejected the repository because
of it, and the trained TF-IDF vocabulary had stored the literal. Labels, categories,
record counts and all other bytes are unchanged; the model was rebuilt and retrained
afterwards so the artefact no longer contains it. See `docs/FINAL_REPORT.md` §2.

Merge output is written to new files under `training/`.
