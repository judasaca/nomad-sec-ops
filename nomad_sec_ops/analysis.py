"""Run independent repository analysis steps and aggregate their results."""

import subprocess
from collections.abc import Callable, Sequence
from typing import Protocol

from nomad_sec_ops.models import AnalysisReport, AnalysisStatus, CheckResult, StepResult
from nomad_sec_ops.repositories import RepositoryTarget
from nomad_sec_ops.steps.ci_cd import CICDAnalysis


class AnalysisStep(Protocol):
    @property
    def name(self) -> str: ...

    def run(self, target: RepositoryTarget) -> CheckResult: ...


def analyze_repository(
    target: RepositoryTarget,
    steps: Sequence[AnalysisStep] | None = None,
    *,
    on_step_start: Callable[[str], None] | None = None,
    on_step_complete: Callable[[StepResult], None] | None = None,
) -> AnalysisReport:
    """A skipped or failed step does not stop the remaining repository checks."""
    selected_steps: Sequence[AnalysisStep] = (
        (CICDAnalysis(),) if steps is None else steps
    )
    results: list[StepResult] = []
    for step in selected_steps:
        if on_step_start is not None:
            on_step_start(step.name)
        try:
            result = step.run(target)
        except FileNotFoundError as error:
            guidance = "Install Git." if error.filename == "git" else "Run uv sync."
            result = CheckResult(
                status=AnalysisStatus.ERROR,
                message=(
                    f"Required executable unavailable: {error.filename}. {guidance}"
                ),
            )
        except subprocess.TimeoutExpired:
            result = CheckResult(
                status=AnalysisStatus.ERROR, message="Analysis step timed out."
            )
        except (OSError, ValueError) as error:
            result = CheckResult(status=AnalysisStatus.ERROR, message=str(error))
        step_result = StepResult(name=step.name, result=result)
        results.append(step_result)
        if on_step_complete is not None:
            on_step_complete(step_result)
    return AnalysisReport(steps=results)
