"""Verify the public CLI entry point."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

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


def test_installed_command(tmp_path: Path) -> None:
    command = Path(sys.executable).parent / (
        "nomadsecops.exe" if sys.platform == "win32" else "nomadsecops"
    )
    result = subprocess.run(
        [str(command), "--version"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == f"nomadsecops {__version__}"


def test_target_help() -> None:
    result = runner.invoke(app, ["static-analysis", "--help"])

    assert result.exit_code == 0
    assert "--path" in result.output
    assert "--repo" in result.output
    assert "Local project directory." in result.output


def test_default_target(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["static-analysis"])

    assert result.exit_code == 3
    assert f"Local path: {tmp_path.resolve()}" in result.output
    assert "no Git origin" in result.output


@pytest.mark.parametrize("option", ["--path", "-p"])
def test_local_target(option: str, tmp_path: Path) -> None:
    target = tmp_path / "project with spaces"
    target.mkdir()

    result = runner.invoke(app, ["static-analysis", option, str(target)])

    assert result.exit_code == 3
    assert f"Local path: {target.resolve()}" in result.output


def test_relative_target(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "project"
    target.mkdir()

    result = runner.invoke(app, ["static-analysis", "--path", "project"])

    assert result.exit_code == 3
    assert f"Local path: {target.resolve()}" in result.output


@pytest.mark.parametrize(
    "repo",
    ["https://github.com/org/repo.git", "git@gitlab.com:org/repo.git"],
)
@pytest.mark.parametrize("option", ["--repo", "-r"])
def test_remote_target(option: str, repo: str, monkeypatch: pytest.MonkeyPatch) -> None:
    scanner = Mock(
        return_value=subprocess.CompletedProcess([], 0, "audit output\n", "")
    )
    monkeypatch.setattr("nomad_sec_ops.cli.run_zizmor", scanner)
    result = runner.invoke(app, ["static-analysis", option, repo])

    assert result.exit_code == 0
    assert f"Remote repository: {repo}" in result.output
    assert "Local path:" not in result.output
    if "github.com" in repo:
        scanner.assert_called_once_with("org/repo")
        assert "audit output" in result.output
    else:
        scanner.assert_not_called()
        assert "Skipping zizmor" in result.output


def test_conflicting_targets(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "static-analysis",
            "--path",
            str(tmp_path),
            "--repo",
            "https://github.com/org/repo.git",
        ],
    )

    assert result.exit_code == 2
    assert "cannot be used together" in result.output


@pytest.mark.parametrize("target_kind", ["missing", "file"])
def test_invalid_local_target(target_kind: str, tmp_path: Path) -> None:
    target = tmp_path / "project"
    if target_kind == "file":
        target.write_text("not a directory")

    result = runner.invoke(app, ["static-analysis", "--path", str(target)])

    assert result.exit_code == 2
    assert "Local path:" not in result.output


@pytest.mark.parametrize("repo", ["", "   "])
def test_empty_remote_target(repo: str) -> None:
    result = runner.invoke(app, ["static-analysis", "--repo", repo])

    assert result.exit_code == 2
    assert "Repository URL cannot be empty" in result.output
