"""Command-line interface for Nomad SecOps."""

import subprocess
from pathlib import Path
from typing import Annotated

import typer

from nomad_sec_ops import __version__
from nomad_sec_ops.analysis import analyze_repository
from nomad_sec_ops.equivalence import build_equivalence_report
from nomad_sec_ops.models import AnalysisStatus
from nomad_sec_ops.repositories import RepositoryProvider, resolve_target

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
    include_online: Annotated[
        bool,
        typer.Option("--all", help="Include online zizmor rules in the inventory."),
    ] = False,
    details: Annotated[
        bool, typer.Option("--details", help="List implemented and missing rule IDs.")
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the full report as JSON.")
    ] = False,
) -> None:
    """Report GitLab rule coverage against pinned zizmor (offline by default)."""
    report = build_equivalence_report(include_online=include_online)
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
        report = analyze_repository(target)
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
        typer.echo(
            f"[{step.name}] {result.message}",
            err=result.status == AnalysisStatus.ERROR,
        )
        if result.stdout:
            typer.echo(result.stdout, nl=False)
        if result.stderr:
            typer.echo(result.stderr, nl=False, err=True)
    raise typer.Exit(report.exit_code)
