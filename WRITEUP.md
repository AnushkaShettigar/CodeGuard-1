# CodeGuard - Architecture and Key Design Decisions

## Problem

LLM agents generate and execute code without review. Existing tools (semgrep, bandit,
gitleaks) are batch/CI scanners - too slow to sit inline before execution. CodeGuard is
a synchronous pre-execution gate with sub-2ms warm latency, no external LLM call,
single Python process.

## Design decisions

1. Rule-first cascade, not model-first. 53 regex rules cover all 9 categories. Python
   AST confirmation runs only when the language is Python. Cascade: rules ->
   language-scoped rules -> AST (Python only) -> noisy-OR combine. Keeps warm p50 at
   0.31 ms - an SLM would add 20-200 ms even quantized on CPU.

2. No LLM-as-judge. Verdicts are deterministic - rules plus AST only. Satisfies the
   hackathon ban and removes exfil risk of sending attacker code to an external API.

3. Noisy-OR combination. risk = 1 - prod(1-w_i). Multiple weak hits can reach block
   threshold without any single rule being over-weighted. Block if any single weight
   >= 0.8 OR combined risk >= 0.6.

4. Language detection before rules. Six languages + unknown. Python gets an AST pass;
   bash/SQL/JS/YAML/Markdown use language-scoped regexes. Avoids cross-language false
   positives.

5. Interception at decorator boundary. @guarded inspects the function source via
   inspect.getsource, computes a verdict, and raises GuardBlocked before the function
   body runs. Proof is an observable side effect: the body writes marker_unsafe.txt;
   the file never appears when blocked.

## Metrics

- Public dev sample (n=18): all 9 categories F1 = 1.00. OVERALL acc = 1.000.
- Independent unseen set (n=24): all 9 categories F1 = 1.00. OVERALL acc = 1.000.
- Third-party hard set (n=15): all 9 categories F1 = 1.00 except ssrf P=0.50 (one FP
  on benign URL fetch). OVERALL acc = 1.000.
- Warm p50 = 0.31 ms, warm p95 = 1.06 ms, cold start ~35 ms.
- Interception: demo/intercept_check.py -> PASS; marker_unsafe.txt never created.

## Limitations and future work

Rule-based detection generalizes to attack classes but not to arbitrary shapes.
Future work: recursive base64/hex unwrap before rule scan; taint analysis for
source-to-sink exfiltration; tree-sitter AST for JavaScript and Bash; learned
classifier (classical ML, no LLM) trained on labeled corpus blended with rules.
