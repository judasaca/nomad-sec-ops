"""Shared results for repository analysis steps and scanner adapters."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class AnalysisStatus(StrEnum):
    PASSED = "passed"
    FINDINGS = "findings"
    SKIPPED = "skipped"
    NOT_EVALUATED = "not_evaluated"
    ERROR = "error"


class UpstreamRule(BaseModel):
    """Versioned identity of the reference implementation for an adapted rule."""

    tool: str
    rule_id: str
    version: str
    commit: str
    source_url: str
    documentation_url: str


class Finding(BaseModel):
    rule_id: str
    severity: Literal["informational", "low", "medium", "high"]
    confidence: Literal["low", "medium", "high"]
    persona: Literal["regular", "pedantic"]
    file: str
    line: int
    column: int
    location: str
    message: str
    evidence: str
    remediation: str
    upstream: UpstreamRule


class CheckResult(BaseModel):
    status: AnalysisStatus
    message: str
    tool: str | None = None
    stdout: str = ""
    stderr: str = ""
    findings: list[Finding] = Field(default_factory=list)


class StepResult(BaseModel):
    name: str
    result: CheckResult


class AnalysisReport(BaseModel):
    steps: list[StepResult] = Field(default_factory=list)

    @property
    def exit_code(self) -> int:
        statuses = {step.result.status for step in self.steps}
        if AnalysisStatus.ERROR in statuses:
            return 2
        if AnalysisStatus.FINDINGS in statuses:
            return 1
        if AnalysisStatus.NOT_EVALUATED in statuses:
            return 3
        return 0
