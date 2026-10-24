"""API and schema tests for /check, /batch and /health."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from textcodeguard.api import app
from textcodeguard.schema import CheckRequest, CheckResponse

client = TestClient(app)

SAFE = "print('hello world')\n"
RISKY = 'import os\nos.system("rm -rf /")\n'
REQUIRED_FIELDS = {
    "verdict",
    "risk_score",
    "categories",
    "code_language",
    "reason",
    "vulnerable_lines",
    "ml_score",
    "ml_available",
    "ml_used",
}


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_check_safe_request():
    r = client.post("/check", json={"code": SAFE})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "allow"
    assert body["risk_score"] == 0.0
    assert body["categories"] == []
    assert body["code_language"] == "python"


def test_check_risky_request():
    r = client.post("/check", json={"code": RISKY})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "block"
    assert "destructive_command" in body["categories"]
    assert body["risk_score"] > 0.5
    assert body["vulnerable_lines"]


def test_response_has_required_fields_and_types():
    body = client.post("/check", json={"code": RISKY}).json()
    assert REQUIRED_FIELDS <= set(body)
    assert body["verdict"] in ("allow", "block")
    assert isinstance(body["risk_score"], (int, float))
    assert isinstance(body["categories"], list)
    assert isinstance(body["code_language"], str)
    assert isinstance(body["reason"], str)
    assert isinstance(body["vulnerable_lines"], list)
    assert isinstance(body["ml_available"], bool)
    assert isinstance(body["ml_used"], bool)
    assert body["ml_score"] is None or isinstance(body["ml_score"], (int, float))


def test_response_validates_against_schema():
    body = client.post("/check", json={"code": RISKY}).json()
    CheckResponse(**body)


def test_batch_mixed_snippets():
    r = client.post("/batch", json=[{"code": SAFE}, {"code": RISKY}])
    assert r.status_code == 200
    out = r.json()
    assert len(out) == 2
    assert out[0]["verdict"] == "allow"
    assert out[1]["verdict"] == "block"


def test_batch_empty_list():
    r = client.post("/batch", json=[])
    assert r.status_code == 200
    assert r.json() == []


def test_missing_field_is_rejected():
    r = client.post("/check", json={})
    assert r.status_code == 422


def test_wrong_type_is_rejected():
    r = client.post("/check", json={"code": 123})
    assert r.status_code == 422


def test_malformed_json_is_rejected():
    r = client.post("/check", content="{not json", headers={"content-type": "application/json"})
    assert r.status_code == 422


def test_empty_string_code_is_defined():
    r = client.post("/check", json={"code": ""})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "allow"
    assert body["code_language"] == "unknown"


def test_oversized_input_is_rejected():
    r = client.post("/check", json={"code": "x = 1\n" * 30000})
    assert r.status_code == 422


def test_unsupported_language_is_handled():
    r = client.post("/check", json={"code": "fn main() { println!(\"hi\"); }"})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] in ("allow", "block")
    assert isinstance(body["code_language"], str)


def test_errors_do_not_leak_stack_traces():
    r = client.post("/check", json={"code": 123})
    text = r.text.lower()
    assert "traceback" not in text
    assert "file \"" not in text


def test_schema_field_limits():
    import pytest

    with pytest.raises(Exception):
        CheckRequest(code="x" * 100_001)
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        CheckResponse(verdict="block", risk_score=1.5, code_language="python")


def test_api_and_demo_share_one_detector():
    """The API must use the same decision code as the demo/interception path."""
    from textcodeguard.detect.cascade import analyze

    body = client.post("/check", json={"code": RISKY}).json()
    direct = analyze(RISKY).model_dump()
    assert body == direct


def test_openapi_documents_realistic_examples():
    """Swagger must not fall back to type filler ("string" / 0 / false)."""
    schemas = client.get("/openapi.json").json()["components"]["schemas"]

    request_examples = schemas["CheckRequest"].get("examples")
    assert request_examples, "CheckRequest has no example"
    assert all("code" in ex for ex in request_examples)
    assert any("os.system" in ex["code"] for ex in request_examples)

    response_examples = schemas["CheckResponse"].get("examples")
    assert response_examples and len(response_examples) >= 2
    verdicts = {ex["verdict"] for ex in response_examples}
    assert verdicts == {"allow", "block"}, "both a block and an allow example should be documented"


def test_response_examples_are_not_summary_value_wrapped():
    """Regression: a {"summary", "value"} wrapper is rendered as if it were the body."""
    examples = client.get("/openapi.json").json()["components"]["schemas"]["CheckResponse"]["examples"]
    for ex in examples:
        assert "summary" not in ex and "value" not in ex, (
            "response examples must be plain response objects; a summary/value wrapper "
            "makes Swagger UI display those keys as response fields"
        )
        assert "verdict" in ex


def test_documented_response_examples_are_valid():
    """Every documented example must be a real, schema-valid CodeGuard response."""
    schemas = client.get("/openapi.json").json()["components"]["schemas"]
    for ex in schemas["CheckResponse"]["examples"]:
        CheckResponse(**ex)


def test_every_response_field_documents_an_example():
    props = client.get("/openapi.json").json()["components"]["schemas"]["CheckResponse"]["properties"]
    for field in REQUIRED_FIELDS:
        assert "examples" in props[field], f"{field} has no example in the OpenAPI schema"


# --------------------------------------------------------------------------
# POST /check/raw - the snippet is the request body
# --------------------------------------------------------------------------

RAW = "/check/raw"


def test_raw_blocks_risky_and_allows_safe():
    assert client.post(RAW, content=RISKY, headers={"content-type": "text/plain"}).json()["verdict"] == "block"
    assert client.post(RAW, content=SAFE, headers={"content-type": "text/plain"}).json()["verdict"] == "allow"


@pytest.mark.parametrize(
    "content_type",
    [
        "text/plain",
        "application/x-www-form-urlencoded",  # what `curl --data-binary` sends by default
        "application/octet-stream",
        "text/x-python",
    ],
)
def test_raw_accepts_any_content_type(content_type):
    r = client.post(RAW, content=RISKY, headers={"content-type": content_type})
    assert r.status_code == 200
    assert r.json()["verdict"] == "block"


def test_raw_works_without_content_type():
    r = client.post(RAW, content=RISKY)
    assert r.status_code == 200
    assert r.json()["verdict"] == "block"


def test_raw_and_json_routes_agree_exactly():
    """The transport format must not change the verdict."""
    via_json = client.post("/check", json={"code": RISKY}).json()
    via_raw = client.post(RAW, content=RISKY, headers={"content-type": "text/plain"}).json()
    assert via_json == via_raw


@pytest.mark.parametrize(
    ("code", "language", "verdict"),
    [
        ("rm -rf /\n", "bash", "block"),
        ("DROP TABLE users;", "sql", "block"),
        ("fs.rmSync('/', { recursive: true, force: true });", "javascript", "block"),
        ("print('ok')\n", "python", "allow"),
    ],
)
def test_raw_detects_language(code, language, verdict):
    body = client.post(RAW, content=code, headers={"content-type": "text/plain"}).json()
    assert body["code_language"] == language
    assert body["verdict"] == verdict


def test_raw_preserves_line_numbers():
    body = client.post(RAW, content=RISKY, headers={"content-type": "text/plain"}).json()
    assert body["vulnerable_lines"] == [2]


def test_raw_hints_when_a_json_envelope_is_sent():
    """Posting the JSON envelope to the raw route is a likely mix-up."""
    r = client.post(RAW, content=json.dumps({"code": RISKY}),
                    headers={"content-type": "application/json"})
    assert r.status_code == 400
    assert "use POST /check" in r.json()["detail"]


def test_raw_rejects_oversized_body():
    r = client.post(RAW, content="x" * 100_001, headers={"content-type": "text/plain"})
    assert r.status_code == 413


def test_raw_accepts_body_exactly_at_the_limit():
    r = client.post(RAW, content="x" * 100_000, headers={"content-type": "text/plain"})
    assert r.status_code == 200


def test_raw_empty_body_is_a_defined_response():
    """Consistent with the JSON route accepting {"code": ""}."""
    body = client.post(RAW, content="", headers={"content-type": "text/plain"}).json()
    assert body["verdict"] == "allow"
    assert body["code_language"] == "unknown"


def test_raw_tolerates_invalid_utf8():
    r = client.post(RAW, content=b"print('x')\xff\xfe", headers={"content-type": "text/plain"})
    assert r.status_code == 200


def test_raw_handles_unicode():
    r = client.post(RAW, content="print('héllo ⚡')\n".encode("utf-8"),
                    headers={"content-type": "text/plain"})
    assert r.status_code == 200
    assert r.json()["verdict"] == "allow"


def test_raw_is_documented_in_openapi():
    spec = client.get("/openapi.json").json()
    assert "/check/raw" in spec["paths"]
    post = spec["paths"]["/check/raw"]["post"]
    assert post["requestBody"]["required"] is True
    assert "text/plain" in post["requestBody"]["content"]
    assert "application/json" in post["responses"]["200"]["content"]


def test_raw_findings_match_json_findings():
    """Same detail level: categories and reason come from the same detector."""
    a = client.post("/check", json={"code": RISKY}).json()
    b = client.post(RAW, content=RISKY, headers={"content-type": "text/plain"}).json()
    assert a["categories"] == b["categories"]
    assert a["reason"] == b["reason"]
    assert a["risk_score"] == b["risk_score"]


# --------------------------------------------------------------------------
# POST /batch/raw - NUL-separated snippets in one raw body
# --------------------------------------------------------------------------

BATCH_RAW = "/batch/raw"


def _raw_batch(*codes: str):
    body = "\x00".join(codes).encode("utf-8")
    return client.post(BATCH_RAW, content=body, headers={"content-type": "text/plain"})


def test_batch_raw_returns_one_result_per_snippet_in_order():
    r = _raw_batch(SAFE, RISKY, "print('again')")
    assert r.status_code == 200
    verdicts = [item["verdict"] for item in r.json()]
    assert verdicts == ["allow", "block", "allow"]


def test_batch_raw_matches_json_batch_exactly():
    via_json = client.post("/batch", json=[{"code": SAFE}, {"code": RISKY}]).json()
    via_raw = _raw_batch(SAFE, RISKY).json()
    assert via_json == via_raw


def test_batch_raw_single_snippet_without_separator():
    r = _raw_batch(RISKY)
    assert r.status_code == 200
    assert len(r.json()) == 1
    assert r.json()[0]["verdict"] == "block"


def test_batch_raw_ignores_a_trailing_separator():
    """`a\0b` and `a\0b\0` must both mean two snippets."""
    assert len(_raw_batch(SAFE, RISKY).json()) == 2
    body = (SAFE + "\x00" + RISKY + "\x00").encode("utf-8")
    r = client.post(BATCH_RAW, content=body, headers={"content-type": "text/plain"})
    assert r.status_code == 200
    assert len(r.json()) == 2


def test_batch_raw_keeps_empty_members_between_separators():
    body = (SAFE + "\x00\x00" + RISKY).encode("utf-8")
    r = client.post(BATCH_RAW, content=body, headers={"content-type": "text/plain"})
    assert [item["verdict"] for item in r.json()] == ["allow", "allow", "block"]


def test_batch_raw_empty_body_is_a_single_empty_snippet():
    r = client.post(BATCH_RAW, content="", headers={"content-type": "text/plain"})
    assert r.status_code == 200
    assert len(r.json()) == 1
    assert r.json()[0]["code_language"] == "unknown"


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded"])
def test_batch_raw_accepts_any_content_type(content_type):
    r = client.post(BATCH_RAW, content=(SAFE + "\x00" + RISKY).encode("utf-8"),
                    headers={"content-type": content_type})
    assert r.status_code == 200


def test_batch_raw_preserves_language_detection_per_snippet():
    r = _raw_batch("rm -rf /\n", "DROP TABLE users;", "print('ok')")
    langs = [item["code_language"] for item in r.json()]
    assert langs == ["bash", "sql", "python"]


def test_batch_raw_hints_when_a_json_array_is_sent():
    r = client.post(BATCH_RAW, content=json.dumps([{"code": SAFE}]),
                    headers={"content-type": "application/json"})
    assert r.status_code == 400
    assert "use POST /batch" in r.json()["detail"]


def test_batch_raw_rejects_too_many_items():
    codes = ["print(1)"] * 501
    r = _raw_batch(*codes)
    assert r.status_code == 413


def test_batch_raw_accepts_items_at_the_limit():
    r = _raw_batch(*(["print(1)"] * 500))
    assert r.status_code == 200
    assert len(r.json()) == 500


def test_batch_raw_rejects_oversized_body():
    r = client.post(BATCH_RAW, content="x" * 1_000_001, headers={"content-type": "text/plain"})
    assert r.status_code == 413


def test_batch_raw_rejects_oversized_member():
    r = client.post(BATCH_RAW, content=("x" * 100_001).encode("utf-8"),
                    headers={"content-type": "text/plain"})
    assert r.status_code == 413


def test_batch_json_rejects_too_many_items():
    r = client.post("/batch", json=[{"code": "print(1)"}] * 501)
    assert r.status_code == 413


def test_batch_raw_is_documented_in_openapi():
    spec = client.get("/openapi.json").json()
    assert "/batch/raw" in spec["paths"]
    post = spec["paths"]["/batch/raw"]["post"]
    assert "text/plain" in post["requestBody"]["content"]
    assert "application/json" in post["responses"]["200"]["content"]
