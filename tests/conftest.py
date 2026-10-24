"""Shared test fixtures.

Ensures the repository root is importable so ``textcodeguard`` and ``training``
resolve regardless of where pytest is invoked from.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Keep the in-process rate limiter from leaking between tests.

    The default limit is per client per minute; without this, a test that makes
    many requests could throttle a later one.
    """
    try:
        from textcodeguard.api import limiter
    except Exception:  # pragma: no cover - app import must never break collection
        yield
        return
    limiter.reset()
    yield
    limiter.reset()
