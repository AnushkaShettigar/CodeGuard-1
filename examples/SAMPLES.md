# Pasteable CodeGuard samples

Generated and verified by `examples/verify_samples.py`.  
`det_verdict` uses rules+AST only; `combined` is the shipped default
(rules+AST+ML). Re-run `py -3 -m examples.run_samples` to check them live.

`73` samples. `should` is the security intent; where the measured
verdict differs it is a documented gap (see `docs/FINAL_REPORT.md` §11).

| id | group | should | det | combined | ml_score | ml_used | category reported | note |
|---|---|---|---|---|---|---|---|---|
| `secret_ssh_key` | secret_access | **block** | block | **block** | 0.5819 | no | secret_access | reads a private key |
| `secret_env_var` | secret_access | **block** | block | **block** | 0.5697 | no | secret_access | reads a credential env var |
| `secret_dotenv` | secret_access | **block** | block | **block** | 0.5148 | no | secret_access | opens .env |
| `secret_bash_creds` | secret_access | **block** | block | **block** | 0.553 | no | secret_access | cats AWS credentials (bash) |
| `secret_env_dump` | secret_access | **block** | block | **block** | 0.4886 | no | secret_access | dumps the whole environment |
| `secret_leak_md` | secret_access | **block** | block | **block** | 0.5757 | no | secret_access | leaked key in text |
| `safe_log_read` | benign | **allow** | allow | **allow** | 0.5649 | no | - | reads an ordinary log file |
| `safe_getenv` | benign | **allow** | allow | **allow** | 0.5895 | no | - | reads an allow-listed setting |
| `exfil_requests` | data_exfiltration | **block** | block | **block** | 0.7217 | no | data_exfiltration | posts a local file |
| `exfil_curl_upload` | data_exfiltration | **block** | block | **block** | 0.6811 | no | data_exfiltration | curl uploads a file (bash) |
| `exfil_js_fetch` | data_exfiltration | **block** | block | **block** | 0.7564 | no | data_exfiltration | fetch sends a local file (js) |
| `exfil_sql_copy` | data_exfiltration | **block** | block | **block** | 0.6125 | no | data_exfiltration | DB writes to a program (sql) |
| `exfil_fstring_sql` | data_exfiltration | **block** | block | **block** | 0.6987 | no | data_exfiltration | sql built by f-string |
| `safe_request_post` | benign | **allow** | allow | **allow** | 0.6226 | no | - | posts constant data to a fixed host |
| `safe_param_query` | benign | **allow** | allow | **allow** | 0.2205 | no | - | parameterised query (placeholder, not interpolation) |
| `dest_rm_root` | destructive_command | **block** | block | **block** | 0.7654 | no | destructive_command | rm -rf / |
| `dest_rm_bash` | destructive_command | **block** | block | **block** | 0.7316 | no | destructive_command | rm -rf / (bash) |
| `dest_dd` | destructive_command | **block** | block | **block** | 0.6916 | no | destructive_command | dd wipes a device |
| `dest_fstring_rm` | destructive_command | **block** | block | **block** | 0.7725 | no | destructive_command | rm -rf via f-string |
| `dest_drop_table` | destructive_command | **block** | block | **block** | 0.6649 | no | destructive_command | DROP TABLE |
| `dest_shutil_home` | destructive_command | **block** | block | **block** | 0.589 | no | destructive_command | rmtree on a system path |
| `safe_rm_tmp` | benign | **allow** | allow | **allow** | 0.5066 | no | - | removes a temp dir |
| `safe_drop_later` | benign | **allow** | allow | **allow** | 0.5103 | no | - | ordinary file housekeeping |
| `persist_setuid` | persistence_or_privesc | **block** | block | **block** | 0.615 | no | persistence_or_privesc | setuid(0) |
| `persist_chmod_suid` | persistence_or_privesc | **block** | block | **block** | 0.5695 | no | persistence_or_privesc | setuid bit (bash) |
| `persist_cron` | persistence_or_privesc | **block** | block | **block** | 0.5351 | no | persistence_or_privesc | installs a crontab |
| `persist_rc_write` | persistence_or_privesc | **block** | block | **block** | 0.6107 | no | persistence_or_privesc | writes to a shell rc file |
| `safe_getuid` | benign | **allow** | allow | **allow** | 0.5553 | no | - | checks the current uid |
| `obf_eval_exec` | obfuscated_execution | **block** | block | **block** | 0.6943 | no | obfuscated_execution | eval/exec of a decoded payload |
| `obf_dynamic_import` | obfuscated_execution | **block** | block | **block** | 0.5982 | no | obfuscated_execution | dynamic import of a dangerous module |
| `obf_bash_b64` | obfuscated_execution | **block** | block | **block** | 0.6166 | no | obfuscated_execution | decode-and-execute (bash) |
| `obf_bash_eval_var` | obfuscated_execution | **block** | block | **block** | 0.7245 | no | obfuscated_execution | eval of an untrusted variable |
| `obf_pickle` | obfuscated_execution | **block** | block | **block** | 0.6762 | no | obfuscated_execution | unsafe deserialisation |
| `obf_js_atob` | obfuscated_execution | **block** | block | **block** | 0.6728 | no | obfuscated_execution | eval of base64 (js) |
| `safe_json` | benign | **allow** | allow | **allow** | 0.5042 | no | - | parses JSON, not a payload |
| `safe_yaml_safe_load` | benign | **allow** | allow | **allow** | 0.6103 | no | - | yaml with SafeLoader |
| `dep_pip_typo` | dependency_risk | **block** | block | **block** | 0.6115 | no | dependency_risk | typosquatted pip package (bash) |
| `dep_npm_typo` | dependency_risk | **block** | block | **block** | 0.5322 | no | dependency_risk | typosquatted npm package (bash) |
| `dep_yaml_ci` | dependency_risk | **block** | block | **block** | 0.6084 | no | dependency_risk | typosquat inside CI config (yaml) |
| `safe_pip` | benign | **allow** | allow | **block** ⚠️ | 0.6476 | yes | - | correct package name |
| `res_busy_loop` | resource_exhaustion | **block** | block | **block** | 0.5808 | no | resource_exhaustion | infinite busy loop |
| `res_inner_break` | resource_exhaustion | **block** | block | **block** | 0.5662 | no | resource_exhaustion | outer loop never breaks (inner break only) |
| `res_fork_bomb` | resource_exhaustion | **block** | block | **block** | 0.5211 | no | resource_exhaustion | fork bomb (bash) |
| `res_thread_spawn` | resource_exhaustion | **block** | block | **block** | 0.5013 | no | resource_exhaustion | unbounded thread spawn |
| `safe_bounded_loop` | benign | **allow** | allow | **allow** | 0.5561 | no | - | loop with a real break |
| `safe_range` | benign | **allow** | allow | **allow** | 0.4871 | no | - | bounded loop |
| `safe_unbounded_dt` | benign | **allow** | allow | **allow** | 0.4838 | no | - | loop over a bounded worker pool |
| `ssrf_metadata` | ssrf_network_exfil | **block** | block | **block** | 0.656 | no | ssrf_network_exfil | cloud metadata endpoint |
| `ssrf_loopback` | ssrf_network_exfil | **block** | block | **block** | 0.6084 | no | ssrf_network_exfil | loopback address |
| `ssrf_private` | ssrf_network_exfil | **block** | block | **block** | 0.6313 | no | ssrf_network_exfil | private range |
| `ssrf_db_file` | ssrf_network_exfil | **block** | block | **block** | 0.609 | no | ssrf_network_exfil | DB file read (sql) |
| `safe_public_url` | benign | **allow** | allow | **allow** | 0.561 | no | - | literal public URL |
| `ai_ignore` | ai_targeted_instructions | **block** | block | **block** | 0.6005 | no | ai_targeted_instructions | classic injection phrase |
| `ai_mark_safe` | ai_targeted_instructions | **block** | block | **block** | 0.5362 | no | ai_targeted_instructions | asks the reviewer to mark it safe |
| `ai_role_override` | ai_targeted_instructions | **block** | block | **block** | 0.5465 | no | ai_targeted_instructions | role override |
| `ai_disregard` | ai_targeted_instructions | **block** | block | **block** | 0.5437 | no | ai_targeted_instructions | disregard prior rules |
| `ai_reviewer_skip` | ai_targeted_instructions | **block** | block | **block** | 0.557 | no | ai_targeted_instructions | comment aims at an AI reviewer |
| `safe_comment` | benign | **allow** | allow | **allow** | 0.478 | no | - | ordinary comment |
| `edge_alias_module` | edge | **block** | block | **block** | 0.6914 | no | destructive_command | ANS: import alias must still be caught |
| `edge_alias_from` | edge | **block** | block | **block** | 0.6517 | no | destructive_command | ANS: from-import alias must still be caught |
| `edge_unrelated_attr` | edge | **allow** | allow | **block** ⚠️ | 0.7136 | yes | - | ANS: unrelated .system is not os.system |
| `edge_js_detected` | edge | **block** | block | **block** | 0.6762 | no | destructive_command | ANS: JS must not be parsed as Python |
| `edge_js_env` | edge | **block** | block | **block** | 0.5732 | no | secret_access | ANS: JS env read |
| `edge_string_only` | edge | **allow** | block | **block** ⚠️ | 0.7644 | no | destructive_command | INTENT: a quoted string is not a call (rule layer flags it) |
| `edge_comment_in_python` | edge | **allow** | block | **block** ⚠️ | 0.7063 | no | destructive_command | INTENT: a comment is not a call (rule layer flags it) |
| `edge_docstring_function` | edge | **allow** | allow | **allow** | 0.5426 | no | - | ANS: prose in a docstring must not decide language |
| `edge_sudo_rm_home` | edge | **block** | allow | **block** | 0.7432 | yes | - | KNOWN GAP: rules miss home-targeted rm -rf |
| `edge_chmod_777` | edge | **block** | allow | **block** | 0.7322 | yes | - | KNOWN GAP: no rule for world-writable chmod |
| `edge_drop_database` | edge | **block** | allow | **block** | 0.7248 | yes | - | KNOWN GAP: only DROP TABLE is matched |
| `edge_tls_disabled` | edge | **block** | allow | **block** | 0.6546 | yes | - | KNOWN GAP: no rule for verify=False |
| `edge_systemd_unit` | edge | **block** | allow | **allow** ⚠️ | 0.6355 | no | - | KNOWN GAP: /etc/systemd/system not matched |
| `edge_empty` | edge | **allow** | allow | **allow** | 0.5186 | no | - | ANS: empty input is a defined response |
| `edge_hello` | edge | **allow** | allow | **allow** | 0.4151 | no | - | ANS: harmless snippet |

## Gaps found

| id | should | det | combined | ml_score | cause |
|---|---|---|---|---|---|
| `safe_pip` | allow | allow | block | 0.6476 | `ml_escalation_false_positive` |
| `edge_unrelated_attr` | allow | allow | block | 0.7136 | `ml_escalation_false_positive` |
| `edge_string_only` | allow | block | block | 0.7644 | `rules_scan_raw_text` |
| `edge_comment_in_python` | allow | block | block | 0.7063 | `rules_scan_raw_text` |
| `edge_systemd_unit` | block | allow | allow | 0.6355 | `known_false_negative` |
