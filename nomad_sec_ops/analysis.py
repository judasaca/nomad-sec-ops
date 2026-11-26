"""Run independent repository analysis steps and aggregate their results."""

import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

from nomad_sec_ops.models import AnalysisReport, RepositoryInfo, StepResult
from nomad_sec_ops.repositories import (
    InvalidTargetError,
    RepositoryProvider,
    RepositoryTarget,
    checkout_revision,
    resolve_target,
)
from nomad_sec_ops.steps import AnalysisStep as AnalysisStep
from nomad_sec_ops.steps import execute_step
from nomad_sec_ops.steps.ci_cd import CICDAnalysis
from nomad_sec_ops.steps.python_dependencies import PythonDependencies
from nomad_sec_ops.steps.repository_settings import RepositorySettingsAnalysis


class AnalysisError(RuntimeError):
    """The analysis target could not be prepared."""


def static_analysis(
    path: str | Path | None = None,
    *,
    repo: str | None = None,
    branch: str | None = None,
    provider: RepositoryProvider | str | None = None,
) -> AnalysisReport:
    """Scan a local directory or remote Git repository and return a report.

    With neither path nor repo, scan the current working directory. Branch
    selects a remote branch. Findings and scanner failures appear in the report.
    Invalid arguments raise ValueError. Target preparation raises AnalysisError.
    """
    return _run_static_analysis(path, repo=repo, branch=branch, provider=provider)


def _run_static_analysis(
    path: str | Path | None,
    *,
    repo: str | None,
    branch: str | None,
    provider: RepositoryProvider | str | None,
    checkout_root: Path | None = None,
    on_target: Callable[[RepositoryInfo], None] | None = None,
    run_checks: Callable[[RepositoryTarget], AnalysisReport] | None = None,
) -> AnalysisReport:
    try:
        with resolve_target(
            path, repo, provider, branch=branch, checkout_root=checkout_root
        ) as target:
            checked_out_branch, commit = (
                checkout_revision(target.local_path)
                if target.local_path is not None
                else (None, None)
            )
            remote = target.remote
            repository = RepositoryInfo(
                provider=target.hosting_provider,
                local_path=target.local_path if repo is None else None,
                remote=f"{remote.host}/{remote.path}" if remote is not None else None,
                branch=checked_out_branch,
                commit=commit,
            )
            if on_target is not None:
                on_target(repository)
            report = (run_checks or analyze_repository)(target)
            report.repository = repository
            return report
    except InvalidTargetError:
        raise
    except FileNotFoundError as error:
        if error.filename == "git":
            raise AnalysisError(
                "Required executable unavailable: git. Install Git."
            ) from error
        raise AnalysisError(str(error)) from error
    except subprocess.TimeoutExpired as error:
        raise AnalysisError("Repository detection timed out.") from error
    except (OSError, ValueError) as error:
        raise AnalysisError(str(error)) from error


def analyze_repository(
    target: RepositoryTarget,
    steps: Sequence[AnalysisStep] | None = None,
    *,
    on_step_start: Callable[[str], None] | None = None,
    on_step_complete: Callable[[StepResult], None] | None = None,
) -> AnalysisReport:
    """A skipped or failed step does not stop the remaining repository checks."""
    selected_steps: Sequence[AnalysisStep] = (
        (CICDAnalysis(), PythonDependencies(), RepositorySettingsAnalysis())
        if steps is None
        else steps
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
