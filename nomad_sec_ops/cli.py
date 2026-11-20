"""Command-line interface for Nomad SecOps."""

from pathlib import Path
from typing import Annotated

import typer

from nomad_sec_ops import __version__
from nomad_sec_ops.analysis import AnalysisError, _run_static_analysis
from nomad_sec_ops.equivalence import build_equivalence_report
from nomad_sec_ops.models import AnalysisReport, AnalysisStatus, RepositoryInfo
from nomad_sec_ops.progress import STATUS_COLORS, run_with_progress
from nomad_sec_ops.repositories import (
    DEFAULT_CHECKOUT_ROOT,
    InvalidTargetError,
    RepositoryProvider,
    RepositoryTarget,
)
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
    branch: Annotated[
        str | None,
        typer.Option(
            "--branch",
            help="Branch to scan with --repo. Defaults to the remote default branch.",
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

    def show_target(repository: RepositoryInfo) -> None:
        if repo is not None:
            typer.echo(f"Remote repository: {repository.remote}")
        else:
            typer.echo(f"Local path: {repository.local_path}")
        checked_out_branch = repository.branch or (
            "detached HEAD" if repository.commit else "unavailable"
        )
        typer.echo(f"Branch: {checked_out_branch}")
        typer.echo(f"Commit: {repository.commit or 'unavailable'}")

    def run_checks(target: RepositoryTarget) -> AnalysisReport:
        steps: list[AnalysisStep] = []
        if demo:
            typer.echo("Demo mode: npm, Python, and Docker steps simulate work only.")
            steps.extend((NpmDependencies(), PythonDependencies(), DockerAnalysis()))
        steps.append(CICDAnalysis())
        return run_with_progress(target, steps)

    try:
        report = _run_static_analysis(
            path,
            repo=repo,
            provider=provider,
            branch=branch,
            checkout_root=DEFAULT_CHECKOUT_ROOT,
            on_target=show_target,
            run_checks=run_checks,
        )
    except InvalidTargetError as error:
        hint = f"--{error.parameter}" if error.parameter is not None else None
        raise typer.BadParameter(str(error), param_hint=hint) from error
    except AnalysisError as error:
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
        if result.tool == "zizmor":
            for finding in result.findings:
                typer.echo(
                    f"{finding.file}:{finding.line}:{finding.column}: "
                    f"{finding.severity}[{finding.rule_id}] {finding.message}"
                )
                if finding.evidence:
                    typer.echo(f"  {finding.evidence}")
                typer.echo(f"  fix: {finding.remediation}")
        if result.stderr:
            typer.echo(result.stderr, nl=False, err=True)
    raise typer.Exit(report.exit_code)
