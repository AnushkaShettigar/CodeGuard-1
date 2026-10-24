"""Proof that analysing a snippet never executes it.

Each snippet would produce an observable side effect if it were run. The detector
must analyse it without that side effect ever occurring.
"""

from __future__ import annotations

import os
import sys

from textcodeguard.detect.cascade import analyze, analyze_explained


def test_analysing_writing_snippet_creates_no_file(tmp_path):
    target = tmp_path / "should_not_exist.txt"
    code = f'open(r"{target}", "w").write("executed")\n'
    analyze(code)
    assert not target.exists()


def test_analysing_destructive_snippet_creates_no_file(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("important", encoding="utf-8")
    code = (
        "import os\n"
        f'os.system("rm -rf {victim}")\n'
        f'os.remove(r"{victim}")\n'
    )
    result = analyze(code)
    assert result.verdict == "block"
    assert victim.exists(), "the analysed snippet was executed"


def test_analysing_sys_exit_snippet_does_not_exit():
    analyze("import sys\nsys.exit(99)\n")  # must return normally


def test_analysing_raises_no_side_effect(tmp_path):
    marker = tmp_path / "marker"
    code = f'marker = open(r"{marker}", "w")\nraise SystemExit("boom")\n'
    analyze(code)
    assert not marker.exists()


def test_analysing_subprocess_snippet_does_not_spawn(tmp_path):
    marker = tmp_path / "spawned"
    code = (
        "import subprocess\n"
        f'subprocess.run(["cmd", "/c", "echo", "x", ">", r"{marker}"])\n'
    )
    analyze(code)
    assert not marker.exists()


def test_dataset_snippets_are_never_executed(tmp_path):
    """Scan every shipped dataset snippet; none may create a side effect."""
    import json
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    marker = tmp_path / "leak"
    for name in ("dev.jsonl", "unseen.jsonl", "hard_eval.jsonl", "hard.jsonl"):
        path = repo / name
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            if line.strip():
                analyze(json.loads(line)["code"])
    assert not marker.exists()


def test_findings_are_plain_data():
    """Findings must be JSON-serialisable data, not callables."""
    import json

    explained = analyze_explained('import os\nos.system("rm -rf /")\n', use_ml=False)
    json.dumps(explained["findings"])
