"""Verify provider dispatch, scanner execution, and result handling."""

import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from nomad_sec_ops.cli import app
from nomad_sec_ops.repositories import local_remote, parse_remote
from nomad_sec_ops.zizmor import exit_code, run_zizmor

runner = CliRunner()


def create_repository(path: Path, remote: str | None) -> None:
    subprocess.run(["git", "init", "--quiet", str(path)], check=True, timeout=10)
    if remote is not None:
        subprocess.run(
            ["git", "-C", str(path), "remote", "add", "origin", remote],
            check=True,
            timeout=10,
        )


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/org/repo.git",
        "https://GITHUB.COM/org/repo/",
        "ssh://git@github.com/org/repo.git",
        "git@github.com:org/repo.git",
        "git://github.com/org/repo.git",
    ],
)
def test_github_urls(url: str) -> None:
    remote = parse_remote(url)
    assert remote.host == "github.com"
    assert remote.github_slug == "org/repo"


@pytest.mark.parametrize(
    "url",
    [
        "not-a-url",
        "https://github.com",
        "https://github.com/org",
        "https://github.com/org/repo/tree/main",
        "https://github.com/-org/repo",
        "https://github.com/org/repo?query=value",
        "https://github.com/org/repo with spaces",
        "file:///tmp/repo",
    ],
)
def test_invalid_urls(url: str) -> None:
    with pytest.raises(ValueError):
        parse_remote(url)


@pytest.mark.parametrize(
    ("url", "expected_code"),
    [
        ("https://gitlab.com/group/subgroup/repo.git", 0),
        ("git@gitlab.com:group/repo.git", 0),
        ("https://github.com.example.org/org/repo.git", 3),
        ("https://github.com@example.org/org/repo.git", 3),
        ("https://gitlab.example.org/group/repo.git", 3),
    ],
)
def test_non_github_does_not_run_scanner(
    url: str, expected_code: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    scanner = Mock()
    monkeypatch.setattr("nomad_sec_ops.cli.run_zizmor", scanner)

    result = runner.invoke(app, ["static-analysis", "--repo", url])

    assert result.exit_code == expected_code
    scanner.assert_not_called()


@pytest.mark.parametrize("host", ["github.com", "gitlab.com"])
@pytest.mark.parametrize("use_default", [False, True])
def test_local_dispatch(
    host: str, use_default: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    create_repository(tmp_path, f"git@{host}:org/repo.git")
    monkeypatch.chdir(tmp_path)
    scanner = Mock(
        return_value=subprocess.CompletedProcess([], 0, "audit output\n", "")
    )
    monkeypatch.setattr("nomad_sec_ops.cli.run_zizmor", scanner)
    args = ["static-analysis"]
    if not use_default:
        args.extend(["--path", str(tmp_path)])

    result = runner.invoke(app, args)

    assert result.exit_code == 0
    if host == "github.com":
        scanner.assert_called_once_with(str(tmp_path.resolve()))
        assert "audit output" in result.output
    else:
        scanner.assert_not_called()
        assert "Skipping zizmor" in result.output


def test_nested_local_directory(tmp_path: Path) -> None:
    create_repository(tmp_path, "https://github.com/org/repo.git")
    nested = tmp_path / "src"
    nested.mkdir()

    remote = local_remote(nested)

    assert remote is not None
    assert remote.host == "github.com"


def test_missing_origin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    create_repository(tmp_path, None)
    scanner = Mock()
    monkeypatch.setattr("nomad_sec_ops.cli.run_zizmor", scanner)

    result = runner.invoke(app, ["static-analysis", "--path", str(tmp_path)])

    assert result.exit_code == 3
    assert "no Git origin" in result.output
    scanner.assert_not_called()


@pytest.mark.parametrize(
    ("scanner_code", "expected"),
    [(0, 0), (11, 1), (12, 1), (13, 1), (14, 1), (1, 2), (2, 2), (3, 3), (-9, 2)],
)
def test_scanner_exit_codes(
    scanner_code: int, expected: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    scanner = Mock(
        return_value=subprocess.CompletedProcess(
            [], scanner_code, "scanner stdout\n", "scanner stderr\n"
        )
    )
    monkeypatch.setattr("nomad_sec_ops.cli.run_zizmor", scanner)

    result = runner.invoke(
        app, ["static-analysis", "--repo", "https://github.com/org/repo.git"]
    )

    assert exit_code(scanner_code) == expected
    assert result.exit_code == expected
    assert "scanner stdout" in result.stdout
    assert "scanner stderr" in result.stderr


@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError(2, "Missing executable", "zizmor"),
        subprocess.TimeoutExpired("zizmor", 300),
        PermissionError("Cannot execute zizmor"),
    ],
)
def test_scanner_execution_errors(
    error: Exception, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("nomad_sec_ops.cli.run_zizmor", Mock(side_effect=error))

    result = runner.invoke(
        app, ["static-analysis", "--repo", "https://github.com/org/repo.git"]
    )

    assert result.exit_code == 2
    assert "Traceback" not in result.output


def test_scanner_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    process = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr("nomad_sec_ops.zizmor.subprocess.run", process)

    run_zizmor("org/repo")

    process.assert_called_once_with(
        ["zizmor", "--format=plain", "--gh-hostname=github.com", "--", "org/repo"],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def test_real_offline_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    create_repository(tmp_path, "https://github.com/org/repo.git")
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "name: Unsafe workflow\n"
        "on: pull_request_target\n"
        "jobs:\n"
        "  example:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo '${{ github.event.pull_request.title }}'\n"
    )
    monkeypatch.setenv("ZIZMOR_OFFLINE", "true")

    result = runner.invoke(app, ["static-analysis", "--path", str(tmp_path)])

    assert result.exit_code == 1
    assert "template-injection" in result.output
