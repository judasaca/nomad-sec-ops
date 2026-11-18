"""Command-line interface for Nomad SecOps."""

import subprocess
from pathlib import Path
from typing import Annotated

import typer

from nomad_sec_ops import __version__
from nomad_sec_ops.equivalence import build_equivalence_report
from nomad_sec_ops.models import AnalysisStatus
from nomad_sec_ops.progress import STATUS_COLORS, run_with_progress
from nomad_sec_ops.repositories import RepositoryProvider, resolve_target
from nomad_sec_ops.steps import AnalysisStep
from nomad_sec_ops.steps.ci_cd import CICDAnalysis
from nomad_sec_ops.steps.docker import DockerAnalysis
from nomad_sec_ops.steps.npm_dependencies import NpmDependencies
from nomad_sec_ops.steps.python_dependencies import PythonDependencies

app = typer.Typer(
    name="nomadsecops",
    help="Security analysis for repositories in the Nomad ecosystem.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback(invoke_without_command=True)
def main(
    version: Annotated[
        bool, typer.Option("--version", help="Show the version and exit.")
    ] = False,
) -> None:
    if version:
        typer.echo(f"nomadsecops {__version__}")


@app.command("equivalence")
def equivalence(
    details: Annotated[
        bool, typer.Option("--details", help="List implemented and missing rule IDs.")
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the full report as JSON.")
    ] = False,
) -> None:
    """Report GitLab rule coverage against offline zizmor rules."""
    report = build_equivalence_report()
    if json_output:
        typer.echo(report.model_dump_json(indent=2))
        return
    typer.echo(
        f"GitLab equivalents of zizmor {report.upstream_version} ({report.scope} rules)"
    )
    typer.echo(
        f"Rule coverage: {report.percentage:.2f}% "
        f"({report.implemented_count}/{report.total_count})"
    )
    implemented = [rule.rule_id for rule in report.rules if rule.implemented]
    typer.echo(f"Implemented: {', '.join(implemented) or 'none'}")
    if details:
        for rule in report.rules:
            status = "implemented" if rule.implemented else "missing"
            typer.echo(f"  {status}: {rule.rule_id}")
    if report.unmatched_implementations:
        typer.echo(
            "Excluded implementations with unmatched upstream metadata: "
            + ", ".join(report.unmatched_implementations)
        )
    typer.echo(report.note)


@app.command("static-analysis")
def static_analysis(
    path: Annotated[
        Path | None,
        typer.Option(
            "--path",
            "-p",
            help="Local project directory. Defaults to the current directory.",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            resolve_path=True,
        ),
    ] = None,
    repo: Annotated[
        str | None,
        typer.Option(
            "--repo",
            "-r",
            help="Remote Git repository URL (HTTPS or SSH). Exclusive with --path.",
        ),
    ] = None,
    provider: Annotated[
        RepositoryProvider | None,
        typer.Option(
            "--provider",
            help="Hosting provider override; use gitlab for self-hosted GitLab.",
        ),
    ] = None,
    demo: Annotated[
        bool,
        typer.Option(
            "--demo",
            help="Add simulated npm, Python, and Docker steps (four seconds each).",
        ),
    ] = False,
) -> None:
    """Run applicable security checks on a local or remote repository."""
    if path is not None and repo is not None:
        raise typer.BadParameter("--path and --repo cannot be used together.")

    if repo is not None:
        if not repo.strip():
            raise typer.BadParameter(
                "Repository URL cannot be empty.", param_hint="--repo"
            )
    try:
        target = resolve_target(path=path, repo=repo, provider=provider)
        if repo is not None:
            typer.echo(f"Remote repository: {repo}")
        else:
            typer.echo(f"Local path: {target.local_path}")
        steps: list[AnalysisStep] = []
        if demo:
            typer.echo("Demo mode: npm, Python, and Docker steps simulate work only.")
            steps.extend((NpmDependencies(), PythonDependencies(), DockerAnalysis()))
        steps.append(CICDAnalysis())
        report = run_with_progress(target, steps)
    except FileNotFoundError as error:
        typer.echo(
            f"Required executable unavailable: {error.filename}. Install Git.",
            err=True,
        )
        raise typer.Exit(2) from error
    except subprocess.TimeoutExpired as error:
        typer.echo("Repository detection timed out.", err=True)
        raise typer.Exit(2) from error
    except (OSError, ValueError) as error:
        typer.echo(f"Analysis error: {error}", err=True)
        raise typer.Exit(2) from error

    for step in report.steps:
        result = step.result
        step_name = typer.style(
            f"[{step.name}]",
            fg=STATUS_COLORS[result.status],
            bold=True,
        )
        typer.echo(
            f"{step_name} {result.message}",
            err=result.status == AnalysisStatus.ERROR,
        )
        if result.stdout and not (
            result.tool == "zizmor" and result.status == AnalysisStatus.PASSED
        ):
            typer.echo(result.stdout, nl=False)
        if result.stderr:
            typer.echo(result.stderr, nl=False, err=True)
    raise typer.Exit(report.exit_code)
