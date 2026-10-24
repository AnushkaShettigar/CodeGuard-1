import re, yaml
from pathlib import Path
from functools import lru_cache

@lru_cache(maxsize=1)
def load_rules():
    p = Path(__file__).parent.parent / "data" / "rules.yaml"
    data = yaml.safe_load(p.read_text(encoding="utf-8-sig"))
    compiled = []
    for r in data["rules"]:
        try:
            rx = re.compile(r["pattern"])
        except re.error as e:
            print(f"BAD REGEX in {r['id']}: {e}")
            continue
        compiled.append({**r, "rx": rx})
    return compiled

def scan(code: str, language: str):
    hits = []
    for r in load_rules():
        if r["language"] not in (language, "any"):
            continue
        for m in r["rx"].finditer(code):
            line = code.count("\n", 0, m.start()) + 1
            hits.append({"id": r["id"], "category": r["category"],
                         "weight": r["weight"], "line": line,
                         "reason": f"{r['id']}: {r['reason']}"})
    return hits
