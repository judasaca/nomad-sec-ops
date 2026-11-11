"""Command-line interface for Nomad SecOps."""

from pathlib import Path
from typing import Annotated

import typer

from nomad_sec_ops import __version__

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
    """Select a local or remote repository for static analysis."""
    if path is not None and repo is not None:
        raise typer.BadParameter("--path and --repo cannot be used together.")

    if repo is not None:
        if not repo.strip():
            raise typer.BadParameter(
                "Repository URL cannot be empty.", param_hint="--repo"
            )
        typer.echo(f"Remote repository: {repo}")
    else:
        local_path = path if path is not None else Path.cwd().resolve()
        typer.echo(f"Local path: {local_path}")

    typer.echo("Security analysis is not implemented yet.")
