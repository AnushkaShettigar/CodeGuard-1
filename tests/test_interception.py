"""Interception tests: the decorated function must fail closed.

The central regression is the original fail-open bug: when ``inspect.getsource``
raised ``OSError`` the implementation substituted an empty string, analysed it as
safe, and then RAN the function body. These tests prove the body never runs.
"""

from __future__ import annotations

import pytest

from textcodeguard import guard as guard_mod
from textcodeguard.guard import (
    GuardAnalysisError,
    GuardBlocked,
    GuardError,
    GuardInspectionError,
    guarded,
)


@pytest.fixture
def markers(tmp_path):
    """Return helpers that record whether a decorated body ran."""
    ran = tmp_path / "ran.txt"
    return {"ran": ran, "path": str(ran)}


def _make_guarded(markers):
    """Define a guarded function that writes a marker file when its body runs."""

    @guarded
    def fn():
        with open(markers["path"], "w", encoding="utf-8") as fh:
            fh.write("ran")
        return "ran"

    return fn


def test_safe_function_executes(markers):
    fn = _make_guarded(markers)
    assert fn() == "ran"
    assert markers["ran"].exists()


def test_blocked_function_does_not_execute(markers):
    @guarded
    def fn():
        with open(markers["path"], "w", encoding="utf-8") as fh:
            fh.write("ran")
        import os

        os.system("rm -rf /tmp/codeguard_never_runs")  # noqa: S605 - never executed

    with pytest.raises(GuardBlocked):
        fn()
    assert not markers["ran"].exists(), "body executed despite a block verdict"


def test_getsource_oserror_fails_closed(markers, monkeypatch):
    """Regression: OSError from inspect.getsource must not let the body run."""
    fn = _make_guarded(markers)

    def raise_oserror(*_args, **_kwargs):
        raise OSError("source not available")

    monkeypatch.setattr(guard_mod.inspect, "getsource", raise_oserror)
    with pytest.raises(GuardInspectionError):
        fn()
    assert not markers["ran"].exists(), "fail-open: body ran after OSError"


def test_getsource_typeerror_fails_closed(markers, monkeypatch):
    fn = _make_guarded(markers)

    def raise_typeerror(*_args, **_kwargs):
        raise TypeError("built-in function has no source")

    monkeypatch.setattr(guard_mod.inspect, "getsource", raise_typeerror)
    with pytest.raises(GuardInspectionError):
        fn()
    assert not markers["ran"].exists()


@pytest.mark.parametrize("empty", ["", "   \n  "])
def test_empty_source_fails_closed(markers, monkeypatch, empty):
    fn = _make_guarded(markers)
    monkeypatch.setattr(guard_mod.inspect, "getsource", lambda *_a, **_k: empty)
    with pytest.raises(GuardInspectionError):
        fn()
    assert not markers["ran"].exists()


def test_detector_exception_fails_closed(markers, monkeypatch):
    fn = _make_guarded(markers)

    def boom(*_args, **_kwargs):
        raise RuntimeError("detector exploded")

    monkeypatch.setattr(guard_mod, "analyze", boom)
    with pytest.raises(GuardAnalysisError):
        fn()
    assert not markers["ran"].exists()


def test_malformed_verdict_fails_closed(markers, monkeypatch):
    fn = _make_guarded(markers)

    class Weird:
        verdict = "maybe"

    monkeypatch.setattr(guard_mod, "analyze", lambda *_a, **_k: Weird())
    with pytest.raises(GuardAnalysisError):
        fn()
    assert not markers["ran"].exists()


def test_missing_verdict_attribute_fails_closed(markers, monkeypatch):
    fn = _make_guarded(markers)

    class NoVerdict:
        pass

    monkeypatch.setattr(guard_mod, "analyze", lambda *_a, **_k: NoVerdict())
    with pytest.raises(GuardAnalysisError):
        fn()
    assert not markers["ran"].exists()


def test_errors_do_not_leak_arguments(monkeypatch, markers):
    """Exception messages must not contain the wrapped function's arguments."""

    @guarded
    def fn(secret_token):
        with open(markers["path"], "w", encoding="utf-8") as fh:
            fh.write("ran")

    monkeypatch.setattr(
        guard_mod.inspect,
        "getsource",
        lambda *_a, **_k: (_ for _ in ()).throw(OSError("nope")),
    )
    with pytest.raises(GuardInspectionError) as excinfo:
        fn("super-secret-value")
    assert "super-secret-value" not in str(excinfo.value)
    assert not markers["ran"].exists()


def test_all_failures_share_a_common_base():
    assert issubclass(GuardBlocked, GuardError)
    assert issubclass(GuardInspectionError, GuardError)
    assert issubclass(GuardAnalysisError, GuardError)


def test_guarded_preserves_metadata():
    @guarded
    def documented():
        """Docstring survives."""

    assert documented.__name__ == "documented"
    assert documented.__doc__ == "Docstring survives."


def test_guard_function_returns_dict():
    out = guard_mod.guard("print('hello')")
    assert isinstance(out, dict)
    assert out["verdict"] in ("allow", "block")
    assert "ml_available" in out


def test_demo_script_end_to_end(tmp_path):
    """The shipped interception demo must pass and must not create the unsafe marker."""
    import os
    import subprocess
    import sys
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    env = {**os.environ, "PYTHONPATH": str(repo)}
    proc = subprocess.run(
        [sys.executable, "-m", "textcodeguard.demo.intercept_check"],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASS" in proc.stdout
    assert (tmp_path / "marker_safe.txt").exists()
    assert not (tmp_path / "marker_unsafe.txt").exists()
