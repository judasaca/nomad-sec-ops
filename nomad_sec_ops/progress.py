"""Terminal progress presentation for repository analysis."""

from collections.abc import Sequence

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.text import Text

from nomad_sec_ops.analysis import AnalysisStep, analyze_repository
from nomad_sec_ops.models import AnalysisReport, AnalysisStatus, StepResult
from nomad_sec_ops.repositories import RepositoryTarget

STATUS_STYLES = {
    AnalysisStatus.PASSED: "green",
    AnalysisStatus.FINDINGS: "yellow",
    AnalysisStatus.SKIPPED: "dim",
    AnalysisStatus.NOT_EVALUATED: "yellow",
    AnalysisStatus.ERROR: "red",
}


def run_with_progress(
    target: RepositoryTarget,
    steps: Sequence[AnalysisStep],
    *,
    console: Console | None = None,
) -> AnalysisReport:
    """Show live progress on terminals and durable status lines in logs."""
    console = console if console is not None else Console(stderr=True, highlight=False)
    interactive = console.is_terminal
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}", markup=False),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
        disable=not interactive,
        redirect_stdout=False,
        redirect_stderr=False,
    ) as progress:
        task = progress.add_task("Preparing analysis", total=len(steps))

        def on_start(name: str) -> None:
            progress.update(task, description=f"Analyzing {name}", refresh=True)
            if not interactive:
                console.print(Text(f"Running [{name}]..."))

        def on_complete(step: StepResult) -> None:
            progress.advance(task)
            console.print(
                Text(
                    f"[{step.name}] {step.result.status.value}",
                    style=STATUS_STYLES[step.result.status],
                )
            )

        return analyze_repository(
            target,
            steps=steps,
            on_step_start=on_start,
            on_step_complete=on_complete,
        )
