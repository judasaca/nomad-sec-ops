"""Verify repository analysis independently of CLI and individual scanners."""

from dataclasses import dataclass, field

import pytest

from nomad_sec_ops.analysis import analyze_repository
from nomad_sec_ops.models import AnalysisStatus, CheckResult
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
