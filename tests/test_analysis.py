"""Verify repository analysis independently of CLI and individual scanners."""

from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import Mock

import pytest

from nomad_sec_ops.analysis import analyze_repository
from nomad_sec_ops.models import AnalysisStatus, CheckResult, StepResult
from nomad_sec_ops.repositories import RemoteRepository, RepositoryTarget
from nomad_sec_ops.steps.ci_cd import CICDAnalysis


@dataclass
class ExampleStep:
    name: str
    status: AnalysisStatus
    error: Exception | None = None
    calls: list[RepositoryTarget] = field(default_factory=list)

    def run(self, target: RepositoryTarget) -> CheckResult:
        self.calls.append(target)
        if self.error is not None:
            raise self.error
        return CheckResult(status=self.status, message=f"{self.name} completed")


@pytest.mark.parametrize(
    "status",
    [
        AnalysisStatus.SKIPPED,
        AnalysisStatus.NOT_EVALUATED,
        AnalysisStatus.FINDINGS,
        AnalysisStatus.ERROR,
    ],
)
def test_all_steps_run_and_retain_results(status: AnalysisStatus) -> None:
    target = RepositoryTarget(None, RemoteRepository("gitlab.com", "org/repo"))
    first = ExampleStep("first", status)
    second = ExampleStep("second", AnalysisStatus.PASSED)

    report = analyze_repository(target, steps=[first, second])

    assert first.calls == [target]
    assert second.calls == [target]
    assert [step.name for step in report.steps] == ["first", "second"]
    assert report.steps[0].result.status == status
    assert report.steps[1].result.status == AnalysisStatus.PASSED


def test_unevaluated_gitlab_ci_does_not_skip_repository_analysis() -> None:
    target = RepositoryTarget(None, RemoteRepository("gitlab.com", "org/repo"))
    next_step = ExampleStep("next-step", AnalysisStatus.FINDINGS)

    report = analyze_repository(target, steps=[CICDAnalysis(), next_step])

    assert report.steps[0].result.status == AnalysisStatus.NOT_EVALUATED
    assert next_step.calls == [target]
    assert report.exit_code == 1


def test_unknown_host_only_affects_ci_cd_step() -> None:
    target = RepositoryTarget(None, None)
    next_step = ExampleStep("next-step", AnalysisStatus.PASSED)

    report = analyze_repository(target, steps=[CICDAnalysis(), next_step])

    assert report.steps[0].result.status == AnalysisStatus.NOT_EVALUATED
    assert next_step.calls == [target]
    assert report.exit_code == 3


@pytest.mark.parametrize("broken_entry", ["syntax", "directory", "dangling symlink"])
def test_invalid_repository_settings_skip_ci_cd_and_continue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, broken_entry: str
) -> None:
    unified = tmp_path / "nomad-sec-ops.yml"
    if broken_entry == "syntax":
        unified.write_text("ci-cd: [")
    elif broken_entry == "directory":
        unified.mkdir()
    else:
        unified.symlink_to(tmp_path / "missing")
    target = RepositoryTarget(tmp_path, RemoteRepository("github.com", "org/repo"))
    github = Mock()
    monkeypatch.setattr("nomad_sec_ops.scanners.github.run_zizmor", github)
    following = ExampleStep("following", AnalysisStatus.PASSED)

    report = analyze_repository(target, steps=[CICDAnalysis(), following])

    assert report.exit_code == 3
    assert f"Warning [{unified}]" in report.steps[0].result.stderr
    assert following.calls == [target]
    github.assert_not_called()


def test_unavailable_shipped_defaults_report_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = RepositoryTarget(tmp_path, RemoteRepository("github.com", "org/repo"))
    monkeypatch.setattr(
        "nomad_sec_ops.scanners.github.load_defaults",
        Mock(side_effect=FileNotFoundError("missing defaults")),
    )
    github = Mock()
    monkeypatch.setattr("nomad_sec_ops.scanners.github.run_zizmor", github)

    report = analyze_repository(target)

    assert report.exit_code == 2
    assert (
        "Invalid shipped defaults (nomad-sec-ops.yml)" in report.steps[0].result.message
    )
    github.assert_not_called()


def test_step_execution_error_does_not_stop_following_steps() -> None:
    target = RepositoryTarget(None, None)
    first = ExampleStep("broken", AnalysisStatus.PASSED, OSError("scanner failed"))
    second = ExampleStep("second", AnalysisStatus.FINDINGS)

    report = analyze_repository(target, steps=[first, second])

    assert report.steps[0].result.status == AnalysisStatus.ERROR
    assert "scanner failed" in report.steps[0].result.message
    assert second.calls == [target]
    assert report.exit_code == 2


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([AnalysisStatus.PASSED], 0),
        ([AnalysisStatus.SKIPPED, AnalysisStatus.PASSED], 0),
        ([AnalysisStatus.NOT_EVALUATED, AnalysisStatus.PASSED], 3),
        ([AnalysisStatus.NOT_EVALUATED, AnalysisStatus.FINDINGS], 1),
        ([AnalysisStatus.ERROR, AnalysisStatus.FINDINGS], 2),
        ([AnalysisStatus.FINDINGS, AnalysisStatus.ERROR], 2),
    ],
)
def test_aggregate_exit_code(statuses: list[AnalysisStatus], expected: int) -> None:
    steps = [ExampleStep(str(index), status) for index, status in enumerate(statuses)]

    report = analyze_repository(RepositoryTarget(None, None), steps=steps)

    assert report.exit_code == expected


def test_empty_step_selection_does_not_run_defaults() -> None:
    report = analyze_repository(RepositoryTarget(None, None), steps=[])

    assert report.steps == []


def test_progress_callbacks_follow_execution_and_errors() -> None:
    events: list[str] = []
    target = RepositoryTarget(None, None)
    broken = ExampleStep("broken", AnalysisStatus.PASSED, OSError("failure"))
    following = ExampleStep("following", AnalysisStatus.PASSED)

    def completed(step: StepResult) -> None:
        events.append(f"done:{step.name}:{step.result.status.value}")

    analyze_repository(
        target,
        steps=[broken, following],
        on_step_start=lambda name: events.append(f"start:{name}"),
        on_step_complete=completed,
    )

    assert events == [
        "start:broken",
        "done:broken:error",
        "start:following",
        "done:following:passed",
    ]
