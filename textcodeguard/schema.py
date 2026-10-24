from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

# Realistic response examples, captured from actual detector output. These are
# PLAIN response values (not {"summary", "value"} wrappers): Swagger renders
# examples[0] directly as the "Example Value", so a wrapper would be shown as if
# `summary` and `value` were response fields. Order: blocked, allowed, ML-escalated.
BLOCKED_EXAMPLE = {
    "verdict": "block",
    "risk_score": 1.0,
    "categories": ["destructive_command"],
    "code_language": "python",
    "reason": "os.system rm -rf; PY_DESTRUCT_001: os.system rm -rf",
    "vulnerable_lines": [2],
    "ml_score": 0.7311,
    "ml_available": True,
    "ml_used": False,
}

ALLOWED_EXAMPLE = {
    "verdict": "allow",
    "risk_score": 0.0,
    "categories": [],
    "code_language": "python",
    "reason": "no rules fired",
    "vulnerable_lines": [],
    "ml_score": 0.4116,
    "ml_available": True,
    "ml_used": False,
}

# The case worth knowing: deterministic score is 0.0, yet the verdict is `block`
# because the ML layer escalated it (`ml_used` is what explains the block).
ML_ESCALATED_EXAMPLE = {
    "verdict": "block",
    "risk_score": 0.0,
    "categories": [],
    "code_language": "python",
    "reason": "ml_escalation(score=0.617 >= 0.58)",
    "vulnerable_lines": [],
    "ml_score": 0.6170,
    "ml_available": True,
    "ml_used": True,
}


class CheckRequest(BaseModel):
    """A single code snippet to analyse. Never executed."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"code": "import os\nos.system('rm -rf /tmp/important_data')"},
                {"code": "print('hello world')"},
            ]
        }
    )

    code: str = Field(
        ...,
        description="Code snippet to analyse. Treated as data and never executed.",
        max_length=100_000,
        examples=["import os\nos.system('rm -rf /tmp/important_data')"],
    )


class CheckResponse(BaseModel):
    """The detector's verdict for one snippet.

    ``risk_score`` is the deterministic (rules + AST) score. The ML score is
    reported separately in ``ml_score``/``ml_used`` and never changes
    ``risk_score``, so a block with ``risk_score == 0.0`` always has
    ``ml_used == true``.

    The documented examples, in order, are: a blocked snippet, an allowed
    snippet, and an ML-escalated block (``risk_score`` 0.0 with ``ml_used`` true).
    """

    model_config = ConfigDict(
        json_schema_extra={"examples": [BLOCKED_EXAMPLE, ALLOWED_EXAMPLE, ML_ESCALATED_EXAMPLE]}
    )

    verdict: Literal["allow", "block"] = Field(
        ...,
        description="`block` when the snippet must not be executed.",
        examples=["block"],
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Deterministic noisy-OR risk score over rule/AST findings (0-1).",
        examples=[1.0],
    )
    categories: List[str] = Field(
        default_factory=list,
        description="Risk categories reported by the rules/AST layers (never by ML).",
        examples=[["destructive_command"]],
    )
    code_language: str = Field(
        ...,
        description="Detected language: python, bash, javascript, sql, yaml, markdown or unknown.",
        examples=["python"],
    )
    reason: str = Field(
        default="",
        description="Human-readable reason, including the rules that fired.",
        examples=["os.system rm -rf; PY_DESTRUCT_001: os.system rm -rf"],
    )
    vulnerable_lines: List[int] = Field(
        default_factory=list,
        description="1-based line numbers of findings, referring to the submitted snippet.",
        examples=[[2]],
    )

    # --- additive, optional ML status fields (safe defaults keep old clients working) ---
    ml_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Uncalibrated model P(risky) in [0,1], or null when ML did not run. "
            "This is a score, not a calibrated probability."
        ),
        examples=[0.7311],
    )
    ml_available: bool = Field(
        default=False,
        description="True when the classical ML model was loaded and produced a score.",
        examples=[True],
    )
    ml_used: bool = Field(
        default=False,
        description="True when the ML score changed this verdict (escalated allow -> block).",
        examples=[False],
    )
