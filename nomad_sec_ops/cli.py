"""Command-line interface for Nomad SecOps."""

import subprocess
from pathlib import Path
from typing import Annotated

import typer

from nomad_sec_ops import __version__
from nomad_sec_ops.analysis import analyze_repository
from nomad_sec_ops.models import AnalysisStatus
from nomad_sec_ops.repositories import resolve_target

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
        target = resolve_target(path=path, repo=repo)
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
