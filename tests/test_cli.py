"""Verify the public CLI entry point."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from nomad_sec_ops import __version__
from nomad_sec_ops.cli import app
from nomad_sec_ops.models import (
    AnalysisReport,
    AnalysisStatus,
    CheckResult,
    Finding,
    StepResult,
)
from nomad_sec_ops.scanners.gitlab.rules.unpinned_images import UPSTREAM

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
    assert "--branch" in result.output
    assert "Local project directory." in result.output


@pytest.mark.parametrize("verbose", [False, True])
@pytest.mark.parametrize("color", [False, True])
def test_findings_grouped_across_steps(
    verbose: bool, color: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = Finding(
        rule_id=UPSTREAM.rule_id,
        severity="high",
        confidence="high",
        persona="regular",
        file="high-first.yml",
        line=1,
        column=1,
        location="image",
        message="Example finding",
        evidence="",
        remediation="Use an immutable digest.",
        upstream=UPSTREAM,
    )
    steps = [
        StepResult(
            name="first",
            result=CheckResult(
                status=AnalysisStatus.FINDINGS,
                message="First check",
                findings=[
                    finding.model_copy(update={"severity": "low", "file": "low.yml"}),
                    finding,
                ],
            ),
        ),
        StepResult(
            name="second",
            result=CheckResult(
                status=AnalysisStatus.FINDINGS,
                message="Second check",
                findings=[
                    finding.model_copy(
                        update={"severity": "medium", "file": "medium.yml"}
                    ),
                    finding.model_copy(update={"file": "high-second.yml"}),
                    finding.model_copy(
                        update={"severity": "informational", "file": "info.yml"}
                    ),
                ],
            ),
        ),
    ]
    monkeypatch.setattr(
        "nomad_sec_ops.cli._run_static_analysis",
        Mock(return_value=AnalysisReport(steps=steps)),
    )

    args = ["static-analysis", "--verbose"] if verbose else ["static-analysis"]
    result = runner.invoke(app, args, color=color)

    assert result.exit_code == 1
    expected = [
        "High severity",
        "high-first.yml:1",
        "high-second.yml:1",
        "Medium severity",
        "medium.yml:1",
        "Low severity",
        "low.yml:1",
        "Informational severity",
        "info.yml:1",
        "Total findings: 5",
    ]
    offsets = [result.stdout.index(item) for item in expected]
    assert offsets == sorted(offsets)
    assert result.stdout.count("High severity") == 1
    if color:
        for ansi, label, count in [
            (31, "High", 2),
            (33, "Medium", 1),
            (36, "Low", 1),
            (94, "Informational", 1),
        ]:
            assert f"\x1b[{ansi}m\x1b[1m{label} severity" in result.stdout
            assert f"\x1b[{ansi}m\x1b[1m{label}: {count}" in result.stdout
    else:
        assert "\x1b[" not in result.stdout
        assert (
            "Total findings: 5 (High: 2, Medium: 1, Low: 1, Informational: 1)"
            in result.stdout
        )


def test_default_target(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["static-analysis"])

    assert result.exit_code == 3
    assert f"Local path: {tmp_path.resolve()}" in result.output
    assert "Branch: unavailable" in result.output
    assert "Commit: unavailable" in result.output
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


@pytest.mark.parametrize("checkout", ["branch", "detached", "unborn"])
def test_local_revision_header(tmp_path: Path, checkout: str) -> None:
    git = ["git", "-C", str(tmp_path)]
    subprocess.run(
        [*git, "init", "--quiet", "--initial-branch=feature/security"],
        check=True,
        timeout=10,
    )
    commit = "unavailable"
    if checkout != "unborn":
        subprocess.run(
            [
                *git,
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.org",
                "commit",
                "--allow-empty",
                "--quiet",
                "-m",
                "Initial commit",
            ],
            check=True,
            timeout=10,
        )
        commit = subprocess.check_output(
            [*git, "rev-parse", "--short", "HEAD"], text=True, timeout=10
        ).strip()
    if checkout == "detached":
        subprocess.run(
            [*git, "checkout", "--quiet", "--detach"], check=True, timeout=10
        )

    result = runner.invoke(app, ["static-analysis", "--path", str(tmp_path)])

    branch = "detached HEAD" if checkout == "detached" else "feature/security"
    assert result.exit_code == 3
    assert f"Branch: {branch}" in result.output
    assert result.output.index(f"Commit: {commit}") < result.output.index("Running")


@pytest.mark.parametrize(
    ("repo", "label", "provider"),
    [
        ("https://github.com/org/repo.git", "github.com/org/repo.git", None),
        ("git@gitlab.com:org/repo.git", "gitlab.com/org/repo.git", None),
        (
            "ssh://git@code.example.org:2222/group/subgroup/repo.git",
            "code.example.org/group/subgroup/repo.git",
            "gitlab",
        ),
    ],
)
@pytest.mark.parametrize("option", ["--repo", "-r"])
@pytest.mark.parametrize("valid_config", [True, False])
@pytest.mark.parametrize("branch", [None, "feature/ci-cd-security"])
def test_remote_target(
    option: str,
    repo: str,
    label: str,
    provider: str | None,
    valid_config: bool,
    branch: str | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    checkouts: list[Path] = []

    def run_git(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        if command[1] == "-C":
            assert Path(command[2]) == checkouts[0]
            if command[3] == "symbolic-ref":
                ref = f"refs/heads/{branch or 'main'}\n"
                return subprocess.CompletedProcess(command, 0, stdout=ref)
            assert command[3:] == ["rev-parse", "--verify", "--short", "HEAD"]
            return subprocess.CompletedProcess(command, 0, stdout="a1b2c3d\n")
        assert command[:3] == ["git", "clone", "--depth=1"]
        assert command[-2] == repo
        branch_args = [option for option in command if option.startswith("--branch")]
        assert branch_args == ([] if branch is None else [f"--branch={branch}"])
        checkout = Path(command[-1])
        checkout.mkdir()
        checkouts.append(checkout)
        (checkout / ".gitlab-ci.yml").write_text("build: {script: [echo ok]}")
        rule_id = "template-injection" if valid_config else "typo"
        config = f"rules: {{{rule_id}: {{disable: true}}}}"
        (checkout / "nomad-sec-ops-ci-cd.yml").write_text(config)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr("nomad_sec_ops.repositories.subprocess.run", run_git)
    scanner = Mock(
        return_value=CheckResult(
            status=AnalysisStatus.PASSED, message="zizmor", stdout="audit output\n"
        )
    )
    monkeypatch.setattr("nomad_sec_ops.steps.ci_cd.run_zizmor", scanner)
    args = ["static-analysis", option, repo]
    if provider is not None:
        args.extend(("--provider", provider))
    if branch is not None:
        args.extend(("--branch", branch))

    result = runner.invoke(app, args)

    assert result.exit_code == (0 if valid_config else 3)
    assert f"Remote repository: {label}" in result.output
    assert f"Branch: {branch or 'main'}" in result.output
    assert result.output.index("Commit: a1b2c3d") < result.output.index("Running")
    assert "Local path:" not in result.output
    assert len(checkouts) == 1
    root = tmp_path / ".nomad-sec-ops-checkouts"
    assert checkouts[0].is_relative_to(root)
    assert list(root.iterdir()) == [root / ".gitignore"]
    assert (root / ".gitignore").read_text() == "*\n"
    if not valid_config:
        scanner.assert_not_called()
        assert "Unknown rule IDs 'typo'" in result.stderr
        assert "CI/CD skipped" in result.output
    elif "github.com" in repo:
        scanner.assert_called_once_with(
            str(checkouts[0]), rule_overrides={"template-injection": True}
        )
        assert "audit output" in result.output
    else:
        scanner.assert_not_called()
        assert "GitLab CI/CD: 1 rule(s) completed (passed)." in result.output


@pytest.mark.parametrize("branch", [None, "missing-branch"])
def test_failed_download_cleans_up_and_skips_scanning(
    branch: str | None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    def clone(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        Path(command[-1]).mkdir()
        return subprocess.CompletedProcess(command, 128)

    monkeypatch.setattr("nomad_sec_ops.repositories.subprocess.run", clone)
    scanner = Mock()
    monkeypatch.setattr("nomad_sec_ops.steps.ci_cd.run_zizmor", scanner)

    args = ["static-analysis", "--repo", "https://github.com/org/repo.git"]
    if branch is not None:
        args.extend(("--branch", branch))
    result = runner.invoke(app, args)

    assert result.exit_code == 2
    assert "Could not download github.com/org/repo.git" in result.stderr
    if branch is not None:
        assert f"branch {branch!r}" in result.stderr
    root = tmp_path / ".nomad-sec-ops-checkouts"
    assert list(root.iterdir()) == [root / ".gitignore"]
    scanner.assert_not_called()


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


def test_branch_requires_remote_target(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["static-analysis", "--path", str(tmp_path), "--branch", "ci-cd-security"]
    )

    assert result.exit_code == 2
    assert "--branch requires --repo" in result.output


def test_empty_branch() -> None:
    result = runner.invoke(
        app,
        [
            "static-analysis",
            "--repo",
            "https://github.com/org/repo.git",
            "--branch",
            "",
        ],
    )

    assert result.exit_code == 2
    assert "Branch name cannot be empty" in result.output


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
