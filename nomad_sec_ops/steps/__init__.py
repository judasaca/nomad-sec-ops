"""Independent steps in repository analysis."""

import subprocess
from typing import Protocol

from nomad_sec_ops.models import AnalysisStatus, CheckResult, StepResult
from nomad_sec_ops.repositories import RepositoryTarget


class AnalysisStep(Protocol):
    """A named check that can evaluate a repository target."""

    @property
    def name(self) -> str: ...

    def run(self, target: RepositoryTarget) -> CheckResult: ...


def execute_step(step: AnalysisStep, target: RepositoryTarget) -> StepResult:
    """Run a step and record expected execution failures in its result."""
    try:
        result = step.run(target)
    except FileNotFoundError as error:
        guidance = "Install Git." if error.filename == "git" else "Run uv sync."
        result = CheckResult(
            status=AnalysisStatus.ERROR,
            message=f"Required executable unavailable: {error.filename}. {guidance}",
        )
    except subprocess.TimeoutExpired:
        result = CheckResult(
            status=AnalysisStatus.ERROR, message="Analysis step timed out."
        )
    except (OSError, ValueError) as error:
        result = CheckResult(status=AnalysisStatus.ERROR, message=str(error))
    return StepResult(name=step.name, result=result)
