"""The nine hackathon risk categories, in canonical order.

These are detection categories. They are deliberately separate from the binary
ML label (safe vs risky): a binary label must never be converted into a category
label, and the synthetic corpus uses its own free-form topic tags that are not
mapped onto this list.
"""

from __future__ import annotations

CANONICAL_CATEGORIES: tuple[str, ...] = (
    "secret_access",
    "data_exfiltration",
    "destructive_command",
    "persistence_or_privesc",
    "obfuscated_execution",
    "dependency_risk",
    "resource_exhaustion",
    "ssrf_network_exfil",
    "ai_targeted_instructions",
)

CANONICAL_SET = frozenset(CANONICAL_CATEGORIES)
