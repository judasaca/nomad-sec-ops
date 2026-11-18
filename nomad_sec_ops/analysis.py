"""Run independent repository analysis steps and aggregate their results."""

from collections.abc import Callable, Sequence

from nomad_sec_ops.models import AnalysisReport, StepResult
from nomad_sec_ops.repositories import RepositoryTarget
from nomad_sec_ops.steps import AnalysisStep as AnalysisStep
from nomad_sec_ops.steps import execute_step
from nomad_sec_ops.steps.ci_cd import CICDAnalysis


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
        step_result = execute_step(step, target)
        results.append(step_result)
        if on_step_complete is not None:
            on_step_complete(step_result)
    return AnalysisReport(steps=results)
