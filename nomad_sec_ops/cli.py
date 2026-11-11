"""Command-line interface for Nomad SecOps."""

import subprocess
from pathlib import Path
from typing import Annotated

import typer

from nomad_sec_ops import __version__
from nomad_sec_ops.repositories import local_remote, parse_remote
from nomad_sec_ops.zizmor import exit_code, run_zizmor

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
        if repo is not None:
            remote = parse_remote(repo)
            typer.echo(f"Remote repository: {repo}")
        else:
            path = path if path is not None else Path.cwd().resolve()
            typer.echo(f"Local path: {path}")
            remote = local_remote(path)

        if remote is None:
            typer.echo("zizmor not evaluated: no Git origin identifies the host.")
            raise typer.Exit(3)
        if remote.host == "gitlab.com":
            typer.echo("Skipping zizmor: GitLab repository.")
            return
        if remote.host != "github.com":
            typer.echo(f"zizmor not evaluated: unsupported host {remote.host}.")
            raise typer.Exit(3)

        target = remote.github_slug if repo is not None else str(path)
        typer.echo("Running zizmor...")
        result = run_zizmor(target)
    except FileNotFoundError as error:
        guidance = "Install Git." if error.filename == "git" else "Run uv sync."
        typer.echo(
            f"Required executable unavailable: {error.filename}. {guidance}",
            err=True,
        )
        raise typer.Exit(2) from error
    except subprocess.TimeoutExpired as error:
        typer.echo("Repository detection or zizmor timed out.", err=True)
        raise typer.Exit(2) from error
    except (OSError, ValueError) as error:
        typer.echo(f"Analysis error: {error}", err=True)
        raise typer.Exit(2) from error

    if result.stdout:
        typer.echo(result.stdout, nl=False)
    if result.stderr:
        typer.echo(result.stderr, nl=False, err=True)
    if result.returncode == 3:
        typer.echo("zizmor not evaluated: no supported inputs were found.")
    elif exit_code(result.returncode) == 2:
        typer.echo(f"zizmor failed with exit code {result.returncode}.", err=True)
    raise typer.Exit(exit_code(result.returncode))
