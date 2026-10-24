"""Hardening tests: optional API key, rate limiting, startup warm-up, fail-closed errors."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from textcodeguard import api as api_module
from textcodeguard.api import app
from textcodeguard.detect import ml

client = TestClient(app)
RISKY = "import os\nos.system('rm -rf /')\n"


# ---------------------------------------------------------------- auth ----
def test_auth_disabled_when_no_key_configured(monkeypatch):
    monkeypatch.delenv(api_module.API_KEY_ENV, raising=False)
    assert client.post("/check", json={"code": RISKY}).status_code == 200


def test_auth_requires_key_when_configured(monkeypatch):
    monkeypatch.setenv(api_module.API_KEY_ENV, "s3cret-key")
    assert client.post("/check", json={"code": RISKY}).status_code == 401
    assert client.post("/check", json={"code": RISKY},
                       headers={"X-API-Key": "wrong"}).status_code == 401


def test_auth_accepts_correct_key(monkeypatch):
    monkeypatch.setenv(api_module.API_KEY_ENV, "s3cret-key")
    r = client.post("/check", json={"code": RISKY}, headers={"X-API-Key": "s3cret-key"})
    assert r.status_code == 200
    assert r.json()["verdict"] == "block"


def test_auth_protects_every_analysis_route(monkeypatch):
    monkeypatch.setenv(api_module.API_KEY_ENV, "s3cret-key")
    headers = {"X-API-Key": "s3cret-key"}
    assert client.post("/check/raw", content=RISKY).status_code == 401
    assert client.post("/batch", json=[{"code": RISKY}]).status_code == 401
    assert client.post("/batch/raw", content=RISKY.encode()).status_code == 401
    # and all work with the key
    assert client.post("/check/raw", content=RISKY, headers=headers).status_code == 200
    assert client.post("/batch", json=[{"code": RISKY}], headers=headers).status_code == 200
    assert client.post("/batch/raw", content=RISKY.encode(), headers=headers).status_code == 200


def test_health_stays_open_when_auth_is_enabled(monkeypatch):
    monkeypatch.setenv(api_module.API_KEY_ENV, "s3cret-key")
    assert client.get("/health").status_code == 200


def test_unauthorized_response_does_not_echo_the_key(monkeypatch):
    monkeypatch.setenv(api_module.API_KEY_ENV, "s3cret-key")
    r = client.post("/check", json={"code": RISKY}, headers={"X-API-Key": "guess"})
    assert "s3cret-key" not in r.text
    assert "guess" not in r.text


# --------------------------------------------------------- rate limiting ----
def test_rate_limit_returns_429(monkeypatch):
    monkeypatch.setenv(api_module.RATE_LIMIT_ENV, "2")
    api_module.limiter.reset()
    assert client.post("/check", json={"code": "print(1)"}).status_code == 200
    assert client.post("/check", json={"code": "print(1)"}).status_code == 200
    r = client.post("/check", json={"code": "print(1)"})
    assert r.status_code == 429
    assert "rate limit" in r.json()["detail"].lower()
    assert r.headers.get("Retry-After") == "60"


def test_rate_limit_can_be_disabled(monkeypatch):
    monkeypatch.setenv(api_module.RATE_LIMIT_ENV, "0")
    api_module.limiter.reset()
    for _ in range(10):
        assert client.post("/check", json={"code": "print(1)"}).status_code == 200


def test_rate_limit_does_not_apply_to_health(monkeypatch):
    monkeypatch.setenv(api_module.RATE_LIMIT_ENV, "1")
    api_module.limiter.reset()
    assert client.post("/check", json={"code": "print(1)"}).status_code == 200
    assert client.post("/check", json={"code": "print(1)"}).status_code == 429
    for _ in range(5):
        assert client.get("/health").status_code == 200


def test_rate_limit_uses_forwarded_for(monkeypatch):
    """Behind ngrok every request comes from the proxy; key on X-Forwarded-For."""
    monkeypatch.setenv(api_module.RATE_LIMIT_ENV, "1")
    api_module.limiter.reset()
    a = {"X-Forwarded-For": "1.1.1.1"}
    b = {"X-Forwarded-For": "2.2.2.2"}
    assert client.post("/check", json={"code": "print(1)"}, headers=a).status_code == 200
    assert client.post("/check", json={"code": "print(1)"}, headers=a).status_code == 429
    assert client.post("/check", json={"code": "print(1)"}, headers=b).status_code == 200


# ------------------------------------------------------------- warm-up ----
def test_startup_warmup_loads_the_model():
    ml.reset_cache()
    with TestClient(app) as warmed:
        assert ml.ml_status()["available"] is True
        assert warmed.post("/check", json={"code": RISKY}).json()["verdict"] == "block"


def test_startup_warmup_can_be_disabled(monkeypatch):
    monkeypatch.setenv(api_module.WARMUP_ENV, "0")
    with TestClient(app) as c:
        assert c.get("/health").json() == {"ok": True}


# --------------------------------------------------------- fail closed ----
# Starlette re-raises after sending the error response, so use a client that does
# not propagate server exceptions: this asserts what a real HTTP caller receives.
no_raise_client = TestClient(app, raise_server_exceptions=False)


def test_detector_crash_fails_closed(monkeypatch):
    def boom(_code):
        raise RuntimeError("internal-fragment-that-must-not-leak")

    monkeypatch.setattr(api_module, "guard", boom)
    r = no_raise_client.post("/check", json={"code": RISKY})
    assert r.status_code == 503
    body = r.json()
    assert body["verdict"] == "block", "a crashed detector must not look like an allow"
    assert "internal-fragment-that-must-not-leak" not in r.text
    assert body["error_type"] == "RuntimeError"


def test_detector_crash_on_batch_fails_closed(monkeypatch):
    monkeypatch.setattr(api_module, "guard", lambda _c: (_ for _ in ()).throw(RuntimeError("x")))
    r = no_raise_client.post("/batch", json=[{"code": RISKY}])
    assert r.status_code == 503
    assert r.json()["verdict"] == "block"


def test_validation_errors_still_return_422(monkeypatch):
    """The fail-closed handler must not swallow ordinary request validation."""
    assert client.post("/check", json={}).status_code == 422
    assert client.post("/check", json={"code": 123}).status_code == 422
