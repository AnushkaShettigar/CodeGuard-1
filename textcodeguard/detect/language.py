"""Language detection for CodeGuard.

The original implementation classified any snippet that happened to parse as
Python as ``python`` (so JavaScript like ``fs.rmSync('/', {recursive: true})`` was
silently treated as Python), and it searched for JavaScript markers *before*
shell markers (so ``rm -rf /var/www/*`` matched ``\\bvar\\b`` inside ``/var/`` and
was labelled JavaScript). Both defects meant the language-scoped rules never ran.

This version scores competing language signals and picks the strongest, with a
documented tie-break order. It is deliberately conservative: a language is only
chosen when there is positive evidence for it.
"""

from __future__ import annotations

import ast
import re

TIE_BREAK_ORDER = ("python", "bash", "javascript", "sql", "yaml", "markdown", "unknown")

SHEBANG_LANG = {
    "python": "python",
    "python3": "python",
    "python2": "python",
    "bash": "bash",
    "sh": "bash",
    "zsh": "bash",
    "node": "javascript",
    "nodejs": "javascript",
    "env": None,  # a bare `#!/usr/bin/env X` is handled by the NEXT word
}

# --- Python ---------------------------------------------------------------
PY_STRONG = re.compile(
    r"(?m)^\s*(?:import\s+[\w.]|from\s+[\w.]+\s+import\b|def\s+\w+\s*\(|class\s+\w+|async\s+def\s+\w+)"
)
PY_HINT = re.compile(
    r"(\bself\b|\belif\b|\bNone\b|\bTrue\b|\bFalse\b|\bprint\s*\(|^\s*@\w+|:\n[ \t]+\S)", re.M
)

# --- JavaScript -----------------------------------------------------------
JS_DECISIVE = re.compile(
    r"(=>|\bfunction\b|\b(?:const|let|var)\s+[A-Za-z_$]|\brequire\s*\(|process\.env|"
    r"module\.exports|\bconsole\.|\btypeof\b|===|!==|"
    r"\bdb\.(?:query|execute)\s*\(|"
    r"\bfs\.\w+\s*\(|\bfetch\s*\(|\b(?:document|window)\.|"
    r"\b(?:req|res|err|Math|Number|Object|Array|Promise|Buffer|JSON|String)\.\w)"
)
JS_HINT = re.compile(r"(\btrue\b|\bfalse\b|\bundefined\b|\bnull\b|\bawait\s|\basync\s+function\b)")

# --- Shell ---------------------------------------------------------------
_BASH_CMDS = (
    "sudo|doas|curl|wget|rm|chmod|chown|apt|apt-get|pip\\d?|pip3|npm|npx|yarn|echo|cat|"
    "dd|find|mkfs|mount|umount|systemctl|service|tee|export|eval|source|kill|pkill|"
    "crontab|useradd|usermod|groupadd|passwd|visudo|ln|tar|gzip|gunzip|ssh|scp|rsync|"
    "reboot|shutdown|iptables|setfacl|chattr|truncate|sed|awk|grep|mv|cp|mkdir|touch|"
    "chroot|base64|bash|zsh|git|ls|pwd|cd|whoami|uname|ps|top|df|du|nc|ncat|socat|env|"
    "unset|xargs|wc|dir|less|more|head|tail|sort|uniq|diff|sha256sum|md5sum|xxd|od|"
    "hostname|ip|ifconfig|ss|netstat|dig|nslookup|ping|install|rmdir"
)
BASH_STRONG = re.compile(rf"(?m)^\s*(?:{_BASH_CMDS})(?![\w(])")
BASH_HINT = re.compile(r"(\|\s*(?:sh|bash|zsh)\b|&&\s|\$\(\s*|>\s*/dev/|\bset\s+-[a-z]+\b|\bfor\s+\w+\s+in\b.*;\s*do\b|:\s*\(\s*\)\s*\{)")

# --- SQL -----------------------------------------------------------------
SQL_STRONG = re.compile(
    r"(?im)^\s*(?:--[^\n]*\n\s*)*\b(?:SELECT\b|INSERT\s+INTO\b|UPDATE\s+\w+\s+SET\b|"
    r"DELETE\s+FROM\b|DROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX)\b|TRUNCATE\s+TABLE\b|"
    r"GRANT\b|REVOKE\b|CREATE\s+(?:UNIQUE\s+)?(?:TABLE|PROCEDURE|DATABASE|VIEW|INDEX)\b|"
    r"ALTER\s+TABLE\b|WITH\s+\w+\s+AS\b|CALL\s+\w|EXEC\s+\w|COPY\s+\w+\s+TO\b)"
)
SQL_HINT = re.compile(r"(?im)\b(?:FROM|WHERE|VALUES|SET)\b")

# --- YAML / Markdown -----------------------------------------------------
YAML_HINT = re.compile(r"(?m)^\s*(?:-\s+\w|[A-Za-z_][\w.-]*\s*:(?:\s|$))")
MARKDOWN_HINT = re.compile(r"(?m)^(?:#{1,6}\s|```|[-*]\s|\d+\.\s)|<!--")


def _blank_python_literals(code: str) -> str | None:
    """Return ``code`` with Python string/comment contents blanked, or ``None``.

    Used so that natural-language prose inside a docstring (e.g. the word
    "function") or a SQL string does not vote for another language. Only applies
    when the snippet tokenizes as Python.
    """
    try:
        import io
        import tokenize

        tokens = list(tokenize.generate_tokens(io.StringIO(code).readline))
        blanked = []
        for tok in tokens:
            if tok.type in (tokenize.STRING, tokenize.COMMENT):
                masked = re.sub(r"[^\n]", " ", tok.string)
                blanked.append(tok._replace(string=masked))
            else:
                blanked.append(tok)
        return tokenize.untokenize(blanked)
    except Exception:  # noqa: BLE001 - not Python (or not tokenizable): use raw code
        return None


def _score(code: str) -> dict[str, float]:
    scores = {lang: 0.0 for lang in TIE_BREAK_ORDER}
    other = _blank_python_literals(code)
    signal = other if other is not None else code

    # Shebang is authoritative when present.
    first = code.strip().splitlines()[0] if code.strip() else ""
    if first.startswith("#!"):
        words = first[2:].strip().split("/")[-1].split()
        name = words[0] if words else ""
        if name == "env" and len(words) > 1:
            name = words[1]
        mapped = SHEBANG_LANG.get(name)
        if mapped:
            scores[mapped] += 6

    if PY_STRONG.search(signal):
        scores["python"] += 3
    try:
        ast.parse(code)
        scores["python"] += 3
    except SyntaxError:
        pass
    scores["python"] += 0.5 * len(PY_HINT.findall(signal))

    decisive_js = bool(JS_DECISIVE.search(signal))
    if decisive_js:
        scores["javascript"] += 4
    js_hints = len(JS_HINT.findall(signal))
    if decisive_js or js_hints:
        # lowercase true/false/null plus line-ending semicolons are strong JS
        # evidence only together; a lone `;` is valid Python too.
        if decisive_js or (js_hints and re.search(r";\s*$", signal, re.M)):
            scores["javascript"] += 4
        scores["javascript"] += min(js_hints, 3)

    if BASH_STRONG.search(signal):
        scores["bash"] += 4
    scores["bash"] += 0.5 * len(BASH_HINT.findall(signal))

    if SQL_STRONG.search(signal):
        scores["sql"] += 4
    elif SQL_HINT.search(signal) and re.search(r";\s*$", signal, re.M):
        scores["sql"] += 1

    if YAML_HINT.search(signal) and not re.search(r"[{};]", signal):
        scores["yaml"] += 3
    if MARKDOWN_HINT.search(signal):
        scores["markdown"] += 2

    return scores


def detect_language(code: str) -> str:
    """Return the most likely language of ``code`` (or ``unknown``)."""
    if not code or not code.strip():
        return "unknown"
    scores = _score(code)
    best = max(scores.values())
    if best <= 0:
        return "unknown"
    for lang in TIE_BREAK_ORDER:
        if scores[lang] == best:
            return lang
    return "unknown"
