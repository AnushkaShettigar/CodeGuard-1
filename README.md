# CodeGuard — Real-Time Pre-Execution Safety Layer

Intercepts LLM-generated code **before** execution and returns an allow/block verdict. No LLM-as-judge. CPU-only. Warm p95 ≈ 1.1 ms.

## Run

```powershell
py -3 -m pip install -r requirements.txt
py -3 -m textcodeguard.demo.intercept_check     # -> PASS
py -3 -m textcodeguard.evaluate dev.jsonl       # -> all 9 categories F1=1.00
py -3 -m textcodeguard.evaluate unseen.jsonl    # -> all 9 categories F1=1.00
py -3 -m textcodeguard.evaluate hard_eval.jsonl # -> OVERALL acc=1.000
py -3 -m uvicorn textcodeguard.api:app --port 8000
```
