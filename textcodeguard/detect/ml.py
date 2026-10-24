"""Classical-ML inference for CodeGuard.

Loads the trained scikit-learn pipeline once (lazily) and exposes a single
``score`` function returning ``P(risky)`` in ``[0, 1]``.

Safety properties:

* The model path is resolved relative to the repository, not the caller's
  working directory, so a service started from elsewhere still finds it.
* A missing or unreadable model is reported transparently (``ml_status()``) and
  ``score`` returns ``None``. The deterministic rule/AST detector keeps working.
* ``joblib``/pickle loading is only ever done from the in-repo path (or an
  explicit ``CODEGUARD_MODEL_PATH`` override). Never load a model from an
  untrusted source.
* No analysed source code is written to logs or exception messages.

The cached model is process-wide; call :func:`reset_cache` in tests.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_MODEL_PATH = REPO_ROOT / "models" / "codeguard_clf.joblib"
DEFAULT_MANIFEST_PATH = REPO_ROOT / "models" / "model_manifest.json"

# Fallback decision point when a model exists but its manifest does not.
FALLBACK_DECISION_THRESHOLD = 0.5

_lock = threading.Lock()
_cache: dict | None = None
_cache_error: str | None = None
_inference_error: str | None = None


def model_path() -> Path:
    override = os.environ.get("CODEGUARD_MODEL_PATH")
    return Path(override) if override else DEFAULT_MODEL_PATH


def manifest_path() -> Path:
    override = os.environ.get("CODEGUARD_MANIFEST_PATH")
    return Path(override) if override else DEFAULT_MANIFEST_PATH


def reset_cache() -> None:
    """Drop the cached model so the next call reloads from disk (used by tests)."""
    global _cache, _cache_error, _inference_error
    with _lock:
        _cache = None
        _cache_error = None
        _inference_error = None


def _load() -> dict | None:
    """Load and cache the model bundle, or return None with a recorded reason."""
    global _cache, _cache_error
    if _cache is not None or _cache_error is not None:
        return _cache

    with _lock:
        if _cache is not None or _cache_error is not None:
            return _cache
        path = model_path()
        if not path.exists():
            _cache_error = f"model artifact not found at {path}"
            return None
        try:
            import joblib  # local import: keep the dependency optional
        except ImportError:
            _cache_error = "joblib is not installed"
            return None
        try:
            pipeline = joblib.load(path)
        except Exception as exc:  # noqa: BLE001 - report any load failure transparently
            # Never include the exception's repr of data; only the type name.
            _cache_error = f"failed to load model ({type(exc).__name__})"
            return None

        decision = FALLBACK_DECISION_THRESHOLD
        escalate = None
        manifest_loaded = False
        mpath = manifest_path()
        if mpath.exists():
            try:
                import json

                manifest = json.loads(mpath.read_text(encoding="utf-8"))
                if isinstance(manifest.get("decision_threshold"), (int, float)):
                    decision = float(manifest["decision_threshold"])
                esc = manifest.get("escalate_threshold")
                if isinstance(esc, (int, float)):
                    escalate = float(esc)
                manifest_loaded = True
            except Exception:  # noqa: BLE001 - a bad manifest must not disable the model
                manifest_loaded = False

        _cache = {
            "pipeline": pipeline,
            "path": str(path),
            "decision_threshold": decision,
            "escalate_threshold": escalate,
            "manifest_loaded": manifest_loaded,
        }
        return _cache


def ml_status() -> dict:
    """Report whether ML inference is available, with the reason when it is not."""
    bundle = _load()
    if bundle is None:
        return {
            "available": False,
            "reason": _cache_error or "model unavailable",
            "artifact": str(model_path()),
            "decision_threshold": None,
            "escalate_threshold": None,
        }
    return {
        "available": True,
        "reason": _inference_error or ("loaded" if bundle["manifest_loaded"] else "loaded without manifest"),
        "artifact": bundle["path"],
        "decision_threshold": bundle["decision_threshold"],
        "escalate_threshold": bundle["escalate_threshold"],
    }


def thresholds() -> tuple[float, float | None]:
    bundle = _load()
    if bundle is None:
        return FALLBACK_DECISION_THRESHOLD, None
    return bundle["decision_threshold"], bundle["escalate_threshold"]


def score(code: str) -> float | None:
    """Return ``P(risky)`` for ``code``, or ``None`` when ML is unavailable.

    Never raises: any inference error is swallowed and reported as ``None`` so the
    deterministic detector remains usable. The error type is available via
    :func:`ml_status` only in aggregate (reason string), never with snippet content.
    """
    global _inference_error
    bundle = _load()
    if bundle is None:
        return None
    try:
        proba = bundle["pipeline"].predict_proba([code])[0]
    except Exception as exc:  # noqa: BLE001 - inference must not crash the detector
        _inference_error = f"inference failed ({type(exc).__name__})"
        return None
    # Row order follows pipeline.classes_; find the risky (1) column robustly.
    classes = list(getattr(bundle["pipeline"], "classes_", [0, 1]))
    try:
        idx = classes.index(1)
    except ValueError:
        idx = len(proba) - 1
    return float(proba[idx])
