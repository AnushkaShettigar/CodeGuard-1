"""Build a deterministic, provenance-tracked training dataset from the labelled
CodeGuard corpora.

Sources (all treated as data, never executed):

* ``codeguard_dev.jsonl``  - original labelled corpus (42 rows)
* ``codeguard_synthetic.jsonl`` - generated labelled corpus (118 rows)

Evaluation files (``dev.jsonl``, ``unseen.jsonl``, ``hard_eval.jsonl``) are read
only to detect leakage: any training row whose normalised code is byte-identical
to an evaluation snippet is excluded from the training pool and recorded in the
merge report. Evaluation files themselves are never modified.

Outputs:

* ``training/merged_dataset.jsonl`` - one record per training example with a
  stable ``sample_id``, ``source`` provenance, canonical ``category``, and a
  ``dup_group`` used to keep near-duplicates in the same split.
* ``training/merge_report.json`` - counts, exclusions and the dataset fingerprint.

Run::

    py -3 -m training.build_dataset
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

from textcodeguard.categories import CANONICAL_CATEGORIES

REPO_ROOT = Path(__file__).resolve().parent.parent

ORIGINAL_FILE = REPO_ROOT / "codeguard_dev.jsonl"
SYNTHETIC_FILE = REPO_ROOT / "codeguard_synthetic.jsonl"
EVAL_FILES = ["dev.jsonl", "unseen.jsonl", "hard_eval.jsonl"]

OUT_DATASET = REPO_ROOT / "training" / "merged_dataset.jsonl"
OUT_REPORT = REPO_ROOT / "training" / "merge_report.json"

# Near-duplicate threshold on the token Jaccard similarity.
NEAR_DUP_THRESHOLD = 0.85
_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")


def _read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def normalise(code: str) -> str:
    """Whitespace-insensitive form used for duplicate detection."""
    return re.sub(r"\s+", " ", code or "").strip()


def tokens(code: str) -> frozenset[str]:
    return frozenset(t.lower() for t in _TOKEN_RE.findall(code or ""))


def canonical_category(raw: str) -> list[str]:
    """Map a verbatim category string to the canonical nine, or [] if it is not one."""
    if not raw:
        return []
    found = []
    for part in str(raw).split(","):
        part = part.strip()
        if part in CANONICAL_CATEGORIES and part not in found:
            found.append(part)
    return sorted(found)


def stable_id(source: str, code: str, existing: str | None) -> str:
    """Deterministic id: reuse the original id, otherwise hash the source + code."""
    if existing:
        return f"{source[:3]}_{existing}"
    digest = hashlib.sha1(f"{source}\x00{normalise(code)}".encode("utf-8")).hexdigest()
    return f"{source[:3]}_{digest[:16]}"


class UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def assign_dup_groups(records: list[dict]) -> None:
    """Cluster exact-normalised and near-duplicate rows into a shared dup_group.

    Exact matches are always merged. Near-duplicates (token Jaccard >= threshold)
    are merged only when their labels agree, so a genuine safe/risky contrast is
    never collapsed into one group.
    """
    n = len(records)
    uf = UnionFind(n)
    norms = [normalise(r["code"]) for r in records]
    exact: dict[str, int] = {}
    for i, key in enumerate(norms):
        if key in exact:
            uf.union(exact[key], i)
        else:
            exact[key] = i

    toks = [tokens(r["code"]) for r in records]
    # Bucket by a shared token to avoid a full O(n^2) scan while staying deterministic.
    buckets: dict[str, list[int]] = {}
    for i, ts in enumerate(toks):
        for t in sorted(ts):
            buckets.setdefault(t, []).append(i)
    seen_pairs: set[tuple[int, int]] = set()
    for members in buckets.values():
        if len(members) < 2 or len(members) > 60:
            continue
        for a in range(len(members)):
            for b in range(a + 1, len(members)):
                i, j = members[a], members[b]
                if (i, j) in seen_pairs:
                    continue
                seen_pairs.add((i, j))
                if records[i]["label"] != records[j]["label"]:
                    continue
                ta, tb = toks[i], toks[j]
                if not ta or not tb:
                    continue
                jac = len(ta & tb) / len(ta | tb)
                if jac >= NEAR_DUP_THRESHOLD:
                    uf.union(i, j)

    # Group id = the smallest sample_id in the cluster (stable and readable).
    members: dict[int, list[int]] = {}
    for i in range(n):
        members.setdefault(uf.find(i), []).append(i)
    for root, idxs in members.items():
        # Re-key by lexicographically smallest sample_id for determinism.
        group_id = min(records[i]["sample_id"] for i in idxs)
        for i in idxs:
            records[i]["dup_group"] = group_id
            records[i]["dup_group_size"] = len(idxs)


def build() -> dict:
    missing = [p.name for p in (ORIGINAL_FILE, SYNTHETIC_FILE) if not p.exists()]
    if missing:
        raise SystemExit(
            f"ERROR: missing labelled dataset(s): {', '.join(missing)}. "
            "Place codeguard_dev.jsonl and codeguard_synthetic.jsonl next to this repo."
        )

    raw = []
    for rec in _read_jsonl(ORIGINAL_FILE):
        raw.append({**rec, "_source": "original"})
    for rec in _read_jsonl(SYNTHETIC_FILE):
        raw.append({**rec, "_source": "synthetic"})

    # Evaluation snippets, used only for leakage detection.
    eval_norm: dict[str, list[str]] = {}
    for name in EVAL_FILES:
        path = REPO_ROOT / name
        if not path.exists():
            continue
        for rec in _read_jsonl(path):
            eval_norm.setdefault(normalise(rec.get("code", "")), []).append(name)

    records: list[dict] = []
    excluded: list[dict] = []
    seen_norm: dict[str, str] = {}

    for rec in raw:
        code = rec.get("code", "")
        if not isinstance(code, str) or not code.strip():
            raise SystemExit("ERROR: dataset contains an empty or non-string code field.")
        label = rec.get("label")
        if label not in (0, 1):
            raise SystemExit(f"ERROR: invalid label {label!r} in source record {rec.get('id')}.")
        norm = normalise(code)

        if norm in eval_norm:
            excluded.append(
                {
                    "reason": "duplicates_evaluation_snippet",
                    "source": rec["_source"],
                    "original_id": rec.get("id"),
                    "evaluation_files": sorted(set(eval_norm[norm])),
                }
            )
            continue
        if norm in seen_norm:
            excluded.append(
                {
                    "reason": "exact_duplicate_of_training_row",
                    "source": rec["_source"],
                    "original_id": rec.get("id"),
                    "duplicate_of": seen_norm[norm],
                }
            )
            continue
        sid = stable_id(rec["_source"], code, rec.get("id"))
        seen_norm[norm] = sid
        records.append(
            {
                "sample_id": sid,
                "code": code,
                "label": int(label),
                "language": rec.get("language") or "unknown",
                "source": rec["_source"],
                "category_raw": rec.get("category") or "",
                "category": canonical_category(rec.get("category")),
                "synthetic": bool(rec.get("synthetic", rec["_source"] == "synthetic")),
                "dup_group": sid,
                "dup_group_size": 1,
            }
        )

    records.sort(key=lambda r: r["sample_id"])
    assign_dup_groups(records)

    OUT_DATASET.parent.mkdir(parents=True, exist_ok=True)
    with OUT_DATASET.open("w", encoding="utf-8", newline="\n") as fh:
        for rec in records:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")

    payload = OUT_DATASET.read_bytes()
    fingerprint = hashlib.sha256(payload).hexdigest()

    label_counts = Counter(r["label"] for r in records)
    if len(label_counts) < 2:
        raise SystemExit(
            "ERROR: merged dataset has only one class "
            f"({dict(label_counts)}); cannot train a binary classifier."
        )

    groups = {r["dup_group"] for r in records}
    report = {
        "dataset_fingerprint_sha256": fingerprint,
        "records": len(records),
        "label_counts": {str(k): v for k, v in sorted(label_counts.items())},
        "source_counts": dict(sorted(Counter(r["source"] for r in records).items())),
        "language_counts": dict(sorted(Counter(r["language"] for r in records).items())),
        "category_counts_risky": dict(
            sorted(
                Counter(c for r in records if r["label"] == 1 for c in r["category"]).items()
            )
        ),
        "dup_groups": len(groups),
        "largest_dup_group": max((r["dup_group_size"] for r in records), default=1),
        "input_counts": {
            "original": len(_read_jsonl(ORIGINAL_FILE)),
            "synthetic": len(_read_jsonl(SYNTHETIC_FILE)),
        },
        "exclusions": excluded,
        "near_dup_threshold": NEAR_DUP_THRESHOLD,
    }
    OUT_REPORT.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report


def main() -> int:
    report = build()
    print(f"merged dataset : {OUT_DATASET}")
    print(f"records        : {report['records']}")
    print(f"label counts   : {report['label_counts']}")
    print(f"source counts  : {report['source_counts']}")
    print(f"dup groups     : {report['dup_groups']} (largest {report['largest_dup_group']})")
    print(f"exclusions     : {len(report['exclusions'])}")
    for ex in report["exclusions"]:
        print(f"  - {ex['reason']}: {ex.get('original_id') or ex['source']}")
    print(f"fingerprint    : {report['dataset_fingerprint_sha256'][:16]}...")
    print(f"report         : {OUT_REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
