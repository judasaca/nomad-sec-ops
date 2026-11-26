"""Shared results for repository analysis steps and scanner adapters."""

from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from nomad_sec_ops.repositories import RepositoryProvider


class AnalysisStatus(StrEnum):
    PASSED = "passed"
    FINDINGS = "findings"
    SKIPPED = "skipped"
    NOT_EVALUATED = "not_evaluated"
    ERROR = "error"


class UpstreamRule(BaseModel):
    """Upstream identity and available provenance for a finding's rule."""

    tool: str
    rule_id: str
    version: str | None
    commit: str | None
    source_url: str | None
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


class AuditedDependency(BaseModel):
    name: str
    version: str


class DependencyVulnerability(BaseModel):
    dependency: AuditedDependency
    id: str
    summary: str | None
    link: str
    fix_versions: list[str]


class DependencyProjectStatus(BaseModel):
    name: str
    status: str
    reason: str | None


class DependencyAudit(BaseModel):
    audited_packages: int = Field(ge=0, strict=True)
    vulnerabilities: list[DependencyVulnerability]
    adverse_statuses: list[DependencyProjectStatus]


class CheckResult(BaseModel):
    status: AnalysisStatus
    message: str
    tool: str | None = None
    stdout: str = ""
    stderr: str = ""
    findings: list[Finding] = Field(default_factory=list)
    dependency_audit: DependencyAudit | None = None


class StepResult(BaseModel):
    name: str
    result: CheckResult


class RepositoryInfo(BaseModel):
    """Target identity captured before any temporary checkout is removed."""

    provider: RepositoryProvider | None = None
    local_path: Path | None = None
    remote: str | None = None
    branch: str | None = None
    commit: str | None = None


class AnalysisReport(BaseModel):
    steps: list[StepResult] = Field(default_factory=list)
    repository: RepositoryInfo | None = None

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
