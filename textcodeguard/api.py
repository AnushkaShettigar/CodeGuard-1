from fastapi import FastAPI
from typing import List
from textcodeguard.schema import CheckRequest, CheckResponse
from textcodeguard.guard import guard

app = FastAPI(title="CodeGuard")

@app.post("/check", response_model=CheckResponse)
def check(req: CheckRequest) -> CheckResponse:
    return CheckResponse(**guard(req.code))

@app.post("/batch", response_model=List[CheckResponse])
def batch(reqs: List[CheckRequest]) -> List[CheckResponse]:
    return [CheckResponse(**guard(r.code)) for r in reqs]

@app.get("/health")
def health(): return {"ok": True}
