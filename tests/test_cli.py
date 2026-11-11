"""Verify the public CLI entry point."""

import subprocess
import sys

import pytest
from typer.testing import CliRunner

from nomad_sec_ops import __version__
from nomad_sec_ops.cli import app

runner = CliRunner()


@pytest.mark.parametrize("args", [["--help"], []])
def test_help(args: list[str]) -> None:
    result = runner.invoke(app, args)

    assert result.exit_code == (0 if args else 2)
    assert "Security analysis" in result.output
    assert "--version" in result.output


def test_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == f"nomadsecops {__version__}"


def test_module_entry_point() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "nomad_sec_ops", "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == f"nomadsecops {__version__}"
