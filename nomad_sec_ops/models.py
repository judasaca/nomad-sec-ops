"""Shared results for repository analysis steps and scanner adapters."""

from enum import StrEnum

from pydantic import BaseModel, Field


class AnalysisStatus(StrEnum):
    PASSED = "passed"
    FINDINGS = "findings"
    SKIPPED = "skipped"
    NOT_EVALUATED = "not_evaluated"
    ERROR = "error"


class CheckResult(BaseModel):
    status: AnalysisStatus
    message: str
    tool: str | None = None
    stdout: str = ""
    stderr: str = ""


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
