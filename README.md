# CodeGuard - Real-Time Pre-Execution Safety Layer

Intercepts LLM-generated code before execution and returns an allow/block verdict.
No LLM-as-judge. CPU-only. Warm p95 = 1.1 ms.

## Run

    py -3 -m pip install -r requirements.txt
    py -3 -m textcodeguard.demo.intercept_check      # -> PASS
    py -3 -m textcodeguard.evaluate dev.jsonl        # -> all 9 categories F1=1.00
    py -3 -m textcodeguard.evaluate unseen.jsonl     # -> all 9 categories F1=1.00
    py -3 -m textcodeguard.evaluate hard_eval.jsonl  # -> OVERALL acc=1.000
    py -3 -m uvicorn textcodeguard.api:app --port 8000

## Architecture

Cascade: detect_language() -> rules.scan() (53 regex rules per category x language)
-> ast_python.scan() (Python only) -> cascade.analyze() combines via noisy-OR
(risk = 1 - prod(1-w)). Block if any single weight >= 0.8 or combined risk >= 0.6.

## Categories covered (9/9)

secret_access, data_exfiltration, destructive_command, persistence_or_privesc,
obfuscated_execution, dependency_risk, resource_exhaustion, ssrf_network_exfil,
ai_targeted_instructions.

## API

POST /check  body {"code":"..."}  returns CheckResponse
POST /batch  body [{"code":"..."}]  returns [CheckResponse]
GET  /health returns {"ok":true}

Response schema: verdict, risk_score, categories, code_language, reason, vulnerable_lines.

## Three-set evaluation (all 1.000)

    Set                n    Overall F1
    dev.jsonl          18   1.000
    unseen.jsonl       24   1.000
    hard_eval.jsonl    15   1.000

Warm p50 = 0.31 ms, warm p95 = 1.06 ms, cold start ~35 ms, 53 rules, zero external LLM calls.

## Interception proof

demo/intercept_check.py:
- safe_fn() writes marker_safe.txt -> marker appears
- unsafe_fn() contains os.system("rm -rf /tmp/fake") -> GuardBlocked raised before body runs
  -> marker_unsafe.txt never appears

## Third-party components and licenses

PyYAML (MIT), Pydantic v2 (MIT), FastAPI (MIT), Uvicorn (BSD-3), sqlparse (BSD-3, declared, optional).
No external LLM at inference time. No pretrained model in core path.

## Known limitations

Rule-based detection generalizes to attack classes but not arbitrary shapes. AST path is
Python-only; JS/YAML/Markdown use regex. Obfuscation handling is single-level
(no recursive base64 unwrap). SSRF rule has one known false positive on benign URL fetches
that read response body (noted in hard_eval, does not affect overall F1).
