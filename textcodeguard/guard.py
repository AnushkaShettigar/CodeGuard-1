"""CodeGuard guard: the API entry point and the interception decorator.

Security model
--------------

* ``guard(code)`` analyses a snippet and returns the response dict. Analysed code
  is never executed.
* ``@guarded`` wraps a function so that its source is inspected **before** the body
  runs. If the verdict is ``block`` the body never executes.

The decorator **fails closed**: if the source cannot be inspected, or the detector
raises, or the verdict is malformed, the wrapped function is *not* run and a
``GuardError`` subclass is raised. There is deliberately no fail-open option; a
fail-open path would let unanalysable code execute, which defeats the gate.

Scope limitation: ``@guarded`` only protects calls that go through the decorated
function object. It does not intercept arbitrary Python execution, direct calls to
an undecorated inner function, subprocesses, shell commands, or other processes.
"""

from __future__ import annotations

import functools
import inspect

from textcodeguard.detect.cascade import analyze


class GuardError(Exception):
    """Base class for every CodeGuard interception failure.

    Catch this to observe any block-or-refusal. All subclasses mean the wrapped
    function body did **not** run.
    """


class GuardBlocked(GuardError):
    """Raised when the detector returns a ``block`` verdict."""

    def __init__(self, verdict):
        self.verdict = verdict
        super().__init__(f"CodeGuard blocked: {verdict.categories}")


class GuardInspectionError(GuardError):
    """Raised when the function source cannot be inspected.

    Raised for ``OSError``, ``TypeError`` (e.g. built-ins / C functions) and for an
    empty source string. The protected function must not be called in this case.
    """

    def __init__(self, reason: str):
        super().__init__(
            f"CodeGuard could not inspect the function source ({reason}); "
            "refusing to execute it (fail-closed)"
        )
        self.reason = reason


class GuardAnalysisError(GuardError):
    """Raised when the detector fails or returns a malformed verdict.

    The protected function must not be called in this case.
    """

    def __init__(self, reason: str):
        super().__init__(
            f"CodeGuard could not analyse the function source ({reason}); "
            "refusing to execute it (fail-closed)"
        )
        self.reason = reason


_VALID_VERDICTS = ("allow", "block")


def guard(code: str) -> dict:
    """Analyse ``code`` and return the response as a plain dict."""
    return analyze(code).model_dump()


def guarded(fn):
    """Decorate ``fn`` so it only runs when the detector returns ``allow``.

    Raises:
        GuardInspectionError: source could not be read (fail-closed).
        GuardAnalysisError: the detector raised or returned a malformed verdict.
        GuardBlocked: the detector returned ``block``.
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            src = inspect.getsource(fn)
        except (OSError, TypeError) as exc:
            # Fail closed: we cannot analyse what we cannot read.
            raise GuardInspectionError(type(exc).__name__) from exc

        if not isinstance(src, str) or not src.strip():
            raise GuardInspectionError("empty source")

        try:
            verdict = analyze(src)
        except Exception as exc:  # noqa: BLE001 - any detector failure must fail closed
            # Do not include snippet content or arguments in the message.
            raise GuardAnalysisError(f"detector raised {type(exc).__name__}") from exc

        value = getattr(verdict, "verdict", None)
        if value not in _VALID_VERDICTS:
            raise GuardAnalysisError("malformed verdict")

        if value == "block":
            raise GuardBlocked(verdict)

        return fn(*args, **kwargs)

    return wrapper
