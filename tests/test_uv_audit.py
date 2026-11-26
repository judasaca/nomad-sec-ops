"""Verify the frozen audit and its result contract."""

import json
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import Mock

import pytest

from nomad_sec_ops import static_analysis
from nomad_sec_ops.models import AnalysisStatus
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


def test_frozen_audit_returns_vulnerabilities_and_project_statuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "pyproject.toml").touch()
    (tmp_path / "uv.lock").touch()
    (tmp_path / ".gitlab-ci.yml").write_text("build: {script: [echo ok]}\n")
    payload = {
        "schema": {"version": "preview"},
        "summary": {"audited_packages": 1, "vulnerabilities": 1, "adverse_statuses": 1},
        "vulnerabilities": [
            {
                "dependency": {"name": "example", "version": "1.0"},
                "id": "PYSEC-test",
                "summary": None,
                "link": "https://example.com/advisory",
                "fix_versions": ["1.1"],
            },
        ],
        "adverse_statuses": [
            {"name": "example", "status": "archived", "reason": None},
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
    assert audit.vulnerabilities[0].fix_versions == ["1.1"]
    assert audit.adverse_statuses[0].status == "archived"
    command = run.call_args.args[0]
    assert command[0] == "uv"
    assert command[command.index("--project") + 1] == str(tmp_path)
    assert "audit" in command and "--frozen" in command


@pytest.mark.parametrize(("exit_code", "stdout"), [(2, ""), (0, "{}")])
def test_uv_failure_is_an_error(
    exit_code: int, stdout: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = Mock(return_value=CompletedProcess(["uv"], exit_code, stdout, "diagnostic"))
    monkeypatch.setattr(uv_audit, "subprocess", Mock(run=run))

    result = uv_audit.run_uv_audit(tmp_path)

    assert result.status == AnalysisStatus.ERROR
    assert result.stderr == "diagnostic"
    assert result.dependency_audit is None
