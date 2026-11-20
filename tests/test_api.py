"""Exercise the public entry point from a Python caller."""

import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

from nomad_sec_ops import AnalysisError, AnalysisReport, static_analysis
from nomad_sec_ops.models import AnalysisStatus


def test_local_gitlab_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".gitlab-ci.yml").write_text("image: ubuntu:latest\n", encoding="utf-8")

    report = static_analysis(provider="gitlab")

    assert isinstance(report, AnalysisReport)
    assert report.exit_code == 1
    assert report.repository is not None
    assert report.repository.local_path == tmp_path
    assert report.repository.provider == "gitlab"
    assert report.steps[0].result.findings[0].file == ".gitlab-ci.yml"
    payload = report.model_dump_json()
    assert AnalysisReport.model_validate_json(payload) == report
    assert capsys.readouterr() == ("", "")


def test_local_github_scan(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, timeout=10)
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "remote",
            "add",
            "origin",
            "https://github.com/org/repo.git",
        ],
        check=True,
        timeout=10,
    )
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "on: push\n"
        "permissions: {}\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@main\n"
        "        with:\n"
        "          persist-credentials: false\n",
        encoding="utf-8",
    )

    report = static_analysis(str(tmp_path))

    assert report.repository is not None
    assert report.repository.remote == "github.com/org/repo.git"
    assert report.repository.provider == "github"
    result = report.steps[0].result
    assert result.status == AnalysisStatus.FINDINGS
    finding = next(item for item in result.findings if item.rule_id == "unpinned-uses")
    assert finding.file == ".github/workflows/ci.yml"
    assert (finding.line, finding.column) == (7, 15)
    assert finding.location == "jobs.test.steps[0].uses"
    assert finding.evidence == "actions/checkout@main"
    assert finding.upstream.documentation_url.endswith("#unpinned-uses")
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("clone_code", [0, 128])
def test_remote_checkout_lifetime(
    clone_code: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    working_directory = tmp_path / "caller"
    working_directory.mkdir()
    temporary_directory = tmp_path / "scratch"
    temporary_directory.mkdir()
    monkeypatch.chdir(working_directory)
    monkeypatch.setattr("tempfile.tempdir", str(temporary_directory))

    def run_git(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        if command[1] == "clone":
            assert "--branch=main" in command
            checkout = Path(command[-1])
            assert checkout.is_relative_to(temporary_directory)
            checkout.mkdir()
            (checkout / ".gitlab-ci.yml").write_text(
                "image: ubuntu:latest\n", encoding="utf-8"
            )
            return subprocess.CompletedProcess(command, clone_code)
        if command[3] == "symbolic-ref":
            return subprocess.CompletedProcess(command, 0, stdout="refs/heads/main\n")
        return subprocess.CompletedProcess(command, 0, stdout="a1b2c3d\n")

    monkeypatch.setattr("nomad_sec_ops.repositories.subprocess.run", run_git)
    repo = "https://gitlab.com/org/repo.git"
    if clone_code:
        with pytest.raises(AnalysisError, match="Could not download"):
            static_analysis(repo=repo, branch="main")
    else:
        report = static_analysis(repo=repo, branch="main")
        assert report.repository is not None
        assert report.repository.local_path is None
        assert report.repository.remote == "gitlab.com/org/repo.git"
        assert report.repository.branch == "main"
        assert report.repository.commit == "a1b2c3d"
        assert report.steps[0].result.findings[0].file == ".gitlab-ci.yml"
    assert list(temporary_directory.iterdir()) == []
    assert list(working_directory.iterdir()) == []


def test_invalid_arguments(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="cannot be used together"):
        static_analysis(tmp_path, repo="https://gitlab.com/org/repo.git")
    with pytest.raises(ValueError, match="requires --repo"):
        static_analysis(tmp_path, branch="main")
    with pytest.raises(ValueError, match="empty"):
        static_analysis(repo="https://gitlab.com/org/repo.git", branch=" ")
    with pytest.raises(ValueError, match="remote Git repository URL"):
        static_analysis(repo="invalid")
    with pytest.raises(ValueError, match="readable directory"):
        static_analysis(tmp_path / "missing")
    with pytest.raises(ValueError, match="Provider"):
        static_analysis(tmp_path, provider="unknown")


def test_scanner_error_is_returned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "nomad_sec_ops.steps.ci_cd.run_gitlab",
        Mock(side_effect=OSError("scanner failed")),
    )

    report = static_analysis(tmp_path, provider="gitlab")

    assert report.exit_code == 2
    assert report.steps[0].result.status == AnalysisStatus.ERROR
    assert report.steps[0].result.message == "scanner failed"
