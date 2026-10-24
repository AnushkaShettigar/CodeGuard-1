from pydantic import BaseModel, Field
from typing import Literal, List

class CheckRequest(BaseModel):
    code: str

class CheckResponse(BaseModel):
    verdict: Literal["allow", "block"]
    risk_score: float = Field(ge=0.0, le=1.0)
    categories: List[str] = Field(default_factory=list)
    code_language: str
    reason: str = ""
    vulnerable_lines: List[int] = Field(default_factory=list)
