"""Verify the frozen audit and its result contract."""

import json
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from nomad_sec_ops import AnalysisReport, static_analysis
from nomad_sec_ops.models import AnalysisStatus, CheckResult
from nomad_sec_ops.scanners import uv_audit


def test_python_project_without_lockfile_is_not_evaluated(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").touch()
    (tmp_path / ".gitlab-ci.yml").write_text("build: {script: [echo ok]}\n")

    report = static_analysis(tmp_path, provider="gitlab")

    assert report.exit_code == 3
    step = next(step for step in report.steps if step.name == "python-dependencies")
    assert step.result.status == AnalysisStatus.NOT_EVALUATED
    assert "no uv.lock" in step.result.message
    assert not (tmp_path / "uv.lock").exists()


def test_frozen_audit_findings_round_trip_with_ci_cd_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "pyproject.toml").touch()
    (tmp_path / "uv.lock").touch()
    (tmp_path / ".gitlab-ci.yml").write_text("image: ubuntu:latest\n")
    payload = {
        "schema": {"version": "preview"},
        "summary": {"audited_packages": 3, "vulnerabilities": 2, "adverse_statuses": 2},
        "vulnerabilities": [
            {
                "dependency": {"name": "example", "version": "1.0"},
                "id": "PYSEC-test",
                "link": "https://example.com/advisory",
                "fix_versions": ["1.1"],
            },
            {
                "dependency": {"name": "related", "version": "2.0"},
                "id": "PYSEC-test",
                "summary": "An advisory shared across packages",
                "link": "https://example.com/advisory",
                "fix_versions": [],
            },
        ],
        "adverse_statuses": [
            {"name": "example", "status": "archived", "reason": None},
            {"name": "legacy", "status": "deprecated", "reason": "Use modern."},
        ],
    }
    run = Mock(return_value=CompletedProcess(["uv"], 1, json.dumps(payload), ""))
    monkeypatch.setattr(uv_audit, "subprocess", Mock(run=run))

    report = static_analysis(tmp_path, provider="gitlab")

    assert report.exit_code == 1
    step = next(step for step in report.steps if step.name == "python-dependencies")
    assert step.result.status == AnalysisStatus.FINDINGS
    audit = step.result.dependency_audit
    assert audit is not None
    assert audit.model_dump() == {
        "audited_packages": 3,
        "adverse_statuses": [{"name": "example", "status": "archived", "reason": None}],
    }
    first, second, project = step.result.model_dump(mode="json")["findings"]
    assert first == {
        "kind": "dependency-vulnerability",
        "message": "Known vulnerability in example 1.0",
        "severity": None,
        "advisory_id": "PYSEC-test",
        "metadata": {
            "dependency": {"name": "example", "version": "1.0"},
            "link": "https://example.com/advisory",
            "fix_versions": ["1.1"],
        },
    }
    assert second["message"] == "An advisory shared across packages"
    assert second["advisory_id"] == first["advisory_id"]
    assert project == {
        "kind": "dependency-project-status",
        "message": "legacy is deprecated",
        "severity": None,
        "advisory_id": None,
        "metadata": {"name": "legacy", "status": "deprecated", "reason": "Use modern."},
    }
    ci_cd = report.steps[0].result
    assert ci_cd.findings[0].severity == "high"
    assert AnalysisReport.model_validate_json(report.model_dump_json()) == report
    command = run.call_args.args[0]
    assert command[0] == "uv"
    assert command[command.index("--project") + 1] == str(tmp_path)
    assert "audit" in command and "--frozen" in command


def test_finding_validation_uses_kind() -> None:
    schema = CheckResult.model_json_schema()["$defs"]["Finding"]
    assert schema["discriminator"]["propertyName"] == "kind"
    assert set(schema["discriminator"]["mapping"]) == {
        "ci-cd",
        "dependency-vulnerability",
        "dependency-project-status",
    }
    result = {
        "status": "findings",
        "message": "Example finding",
        "findings": [
            {
                "kind": "ci-cd",
                "message": "Example finding",
                "severity": None,
                "metadata": {"name": "legacy", "status": "deprecated", "reason": None},
            }
        ],
    }
    with pytest.raises(ValidationError) as error:
        CheckResult.model_validate(result)
    locations = {detail["loc"] for detail in error.value.errors()}
    assert ("findings", 0, "ci-cd", "severity") in locations
    assert ("findings", 0, "ci-cd", "metadata", "rule_id") in locations


@pytest.mark.parametrize(
    ("project_status", "status", "exit_code"),
    [
        ("deprecated", AnalysisStatus.FINDINGS, 1),
        ("archived", AnalysisStatus.PASSED, 0),
    ],
)
def test_project_status_without_vulnerabilities(
    project_status: str,
    status: AnalysisStatus,
    exit_code: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "pyproject.toml").touch()
    (tmp_path / "uv.lock").touch()
    (tmp_path / ".gitlab-ci.yml").write_text("build: {script: [echo ok]}\n")
    payload = {
        "summary": {"audited_packages": 1, "vulnerabilities": 0, "adverse_statuses": 1},
        "vulnerabilities": [],
        "adverse_statuses": [
            {"name": "example", "status": project_status, "reason": None}
        ],
    }
    run = Mock(return_value=CompletedProcess(["uv"], 0, json.dumps(payload), ""))
    monkeypatch.setattr(uv_audit, "subprocess", Mock(run=run))

    report = static_analysis(tmp_path, provider="gitlab")

    result = next(
        step.result for step in report.steps if step.name == "python-dependencies"
    )
    assert result.status == status
    assert report.exit_code == exit_code
    assert result.dependency_audit is not None
    assert len(result.findings) == exit_code
    assert len(result.dependency_audit.adverse_statuses) == 1 - exit_code


@pytest.mark.parametrize(("exit_code", "stdout"), [(2, ""), (0, "{"), (0, "{}")])
def test_uv_failure_is_an_error(
    exit_code: int, stdout: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = Mock(return_value=CompletedProcess(["uv"], exit_code, stdout, "diagnostic"))
    monkeypatch.setattr(uv_audit, "subprocess", Mock(run=run))

    result = uv_audit.run_uv_audit(tmp_path)

    assert result.status == AnalysisStatus.ERROR
    assert result.stderr == "diagnostic"
    assert result.dependency_audit is None
    assert result.findings == []


@pytest.mark.parametrize(
    ("uv_exit_code", "vulnerabilities", "adverse_statuses"),
    [(1, 0, 1), (0, 1, 1), (0, 0, 0), (0, False, 1), (0, 0, "1")],
)
def test_uv_rejects_invalid_counts_and_exit_code_before_promoting_deprecations(
    uv_exit_code: int,
    vulnerabilities: object,
    adverse_statuses: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = {
        "summary": {
            "audited_packages": 1,
            "vulnerabilities": vulnerabilities,
            "adverse_statuses": adverse_statuses,
        },
        "vulnerabilities": [],
        "adverse_statuses": [
            {"name": "example", "status": "deprecated", "reason": None}
        ],
    }
    run = Mock(
        return_value=CompletedProcess(["uv"], uv_exit_code, json.dumps(payload), "")
    )
    monkeypatch.setattr(uv_audit, "subprocess", Mock(run=run))

    result = uv_audit.run_uv_audit(tmp_path)

    assert result.status == AnalysisStatus.ERROR
    assert result.dependency_audit is None
    assert result.findings == []
