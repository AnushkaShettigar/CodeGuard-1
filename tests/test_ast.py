"""Python AST analyser tests: aliases, scoping, strings vs calls, robustness."""

from __future__ import annotations

import pytest

from textcodeguard.detect.ast_python import scan


def ids(code: str) -> list[str]:
    return [h["id"] for h in scan(code)]


def test_plain_os_system_rm_rf():
    assert "AST_DESTRUCTIVE_COMMAND" in ids('import os\nos.system("rm -rf /")')


def test_import_alias_resolved():
    assert "AST_DESTRUCTIVE_COMMAND" in ids('import os as o\no.system("rm -rf /")')


def test_from_import_resolved():
    assert "AST_DESTRUCTIVE_COMMAND" in ids('from os import system\nsystem("rm -rf /")')


def test_from_import_alias_resolved():
    assert "AST_DESTRUCTIVE_COMMAND" in ids('from os import system as s\ns("rm -rf /")')


def test_eval_alias_resolved():
    assert "AST_OBFUSCATED_EXECUTION" in ids("from builtins import eval as e\ne(code)")


def test_unrelated_attribute_not_flagged():
    """Reduced false positives: only a known module's `.system` counts."""
    assert ids('engine.system("rm -rf whatever")') == []


def test_dangerous_looking_string_is_not_a_call():
    assert ids("msg = \"os.system('rm -rf /')\"") == []


def test_dangerous_looking_comment_is_ignored():
    assert ids('# os.system("rm -rf /")\nprint(1)') == []


def test_setuid_detected():
    assert "AST_PERSISTENCE_OR_PRIVESC" in ids("import os\nos.setuid(0)")


def test_dynamic_setattr_receiver_still_flagged():
    """Unknown receivers stay conservative for setuid."""
    assert "AST_PERSISTENCE_OR_PRIVESC" in ids("setuid(0)")


def test_while_true_without_break():
    assert "AST_RESOURCE_EXHAUSTION" in ids("while True:\n    pass")


def test_while_true_with_own_break_is_safe():
    assert ids("while True:\n    if x:\n        break") == []


def test_while_true_with_only_inner_break_is_infinite():
    """Regression: an inner loop's break does not terminate the outer loop."""
    assert "AST_RESOURCE_EXHAUSTION" in ids("while True:\n    for x in y:\n        break")


def test_while_true_break_inside_nested_function_is_not_outer():
    code = "while True:\n    def stop():\n        break\n    stop()\n"
    # A break inside a nested function cannot break the while loop.
    hits = ids(code)
    assert "AST_RESOURCE_EXHAUSTION" in hits


@pytest.mark.parametrize(
    "code",
    [
        "def broken(:\n    pass",
        "const x = 1;",
        'rm -rf /',
        "SELECT * FROM t WHERE x = 1",
        "",
        "   ",
    ],
)
def test_non_python_is_ignored_without_crashing(code):
    assert scan(code) == []


def test_line_numbers_refer_to_input():
    code = "x = 1\ny = 2\nimport os\nos.system('rm -rf /')\n"
    hits = [h for h in scan(code) if h["id"] == "AST_DESTRUCTIVE_COMMAND"]
    assert hits and hits[0]["line"] == 4


def test_hits_have_expected_schema():
    for hit in scan('import os\nos.system("rm -rf /")'):
        assert set(hit) >= {"id", "category", "weight", "line", "reason"}
        assert 0.0 <= hit["weight"] <= 1.0
