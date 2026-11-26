"""Run uv's lockfile audit and validate its JSON report."""

import subprocess
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, Field

from nomad_sec_ops.models import (
    AnalysisStatus,
    CheckResult,
    DependencyAudit,
    DependencyProjectStatus,
    DependencyProjectStatusFinding,
    DependencyVulnerabilityFinding,
    DependencyVulnerabilityMetadata,
    Finding,
)

type _Count = Annotated[int, Field(ge=0, strict=True)]


class _AuditSummary(BaseModel):
    audited_packages: _Count
    vulnerabilities: _Count
    adverse_statuses: _Count


class _Vulnerability(DependencyVulnerabilityMetadata):
    id: str
    summary: str | None = None


class _AuditOutput(BaseModel):
    summary: _AuditSummary
    vulnerabilities: list[_Vulnerability]
    adverse_statuses: list[DependencyProjectStatus]


def run_uv_audit(root: Path) -> CheckResult:
    result = subprocess.run(
        [
            "uv",
            "--no-config",
            "--directory",
            str(root.absolute()),
            "--project",
            str(root.absolute()),
            "audit",
            "--frozen",
            "--no-python-downloads",
            "--preview-features",
            "audit,json-output",
            "--output-format",
            "json",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    try:
        if result.returncode not in {0, 1} or not result.stdout.strip():
            raise ValueError(f"uv exited with code {result.returncode}")
        output = _AuditOutput.model_validate_json(result.stdout)
        vulnerability_count = len(output.vulnerabilities)
        adverse_count = len(output.adverse_statuses)
        if (
            output.summary.vulnerabilities != vulnerability_count
            or output.summary.adverse_statuses != adverse_count
            or result.returncode != int(vulnerability_count > 0)
        ):
            raise ValueError("report counts do not match its findings or exit code")
    except ValueError as error:
        return CheckResult(
            status=AnalysisStatus.ERROR,
            message=f"uv audit failed ({error}).",
            tool="uv",
            stderr=result.stderr,
        )

    findings: list[Finding] = []
    for vulnerability in output.vulnerabilities:
        dependency = vulnerability.dependency
        findings.append(
            DependencyVulnerabilityFinding(
                kind="dependency-vulnerability",
                message=(
                    vulnerability.summary
                    or f"Known vulnerability in {dependency.name} {dependency.version}"
                ),
                severity=None,
                advisory_id=vulnerability.id,
                metadata=DependencyVulnerabilityMetadata(
                    dependency=dependency,
                    link=vulnerability.link,
                    fix_versions=vulnerability.fix_versions,
                ),
            )
        )
    adverse_statuses = []
    for project in output.adverse_statuses:
        if project.status == "deprecated":
            findings.append(
                DependencyProjectStatusFinding(
                    kind="dependency-project-status",
                    message=f"{project.name} is deprecated",
                    severity=None,
                    metadata=project,
                )
            )
        else:
            adverse_statuses.append(project)

    return CheckResult(
        status=AnalysisStatus.FINDINGS if findings else AnalysisStatus.PASSED,
        message=(
            f"uv audit checked {output.summary.audited_packages} package(s) "
            f"(vulnerabilities: {vulnerability_count}, "
            f"adverse project statuses: {adverse_count})."
        ),
        tool="uv",
        stderr=result.stderr,
        findings=findings,
        dependency_audit=DependencyAudit(
            audited_packages=output.summary.audited_packages,
            adverse_statuses=adverse_statuses,
        ),
    )
