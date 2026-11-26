"""Exercise demo opt-in, progress rendering, and continued analysis on failure."""

from io import StringIO
from pathlib import Path
from unittest.mock import Mock, call

import pytest
from rich.console import Console
from typer.testing import CliRunner

from nomad_sec_ops.cli import app
from nomad_sec_ops.models import AnalysisStatus, CheckResult
from nomad_sec_ops.progress import run_with_progress
from nomad_sec_ops.repositories import RepositoryTarget
from nomad_sec_ops.steps.docker import DockerAnalysis


@pytest.mark.parametrize("demo", [False, True])
@pytest.mark.parametrize("color", [False, True])
@pytest.mark.parametrize(
    ("status", "exit_code", "ansi_color"),
    [
        (AnalysisStatus.PASSED, 0, 32),
        (AnalysisStatus.FINDINGS, 1, 33),
        (AnalysisStatus.NOT_EVALUATED, 3, 33),
        (AnalysisStatus.ERROR, 2, 31),
    ],
)
def test_demo_cli(
    demo: bool,
    color: bool,
    status: AnalysisStatus,
    exit_code: int,
    ansi_color: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleep = Mock()
    monkeypatch.setattr("nomad_sec_ops.demo.sleep", sleep)
    monkeypatch.setattr(
        "nomad_sec_ops.steps.ci_cd.run_gitlab",
        Mock(return_value=CheckResult(status=status, message="CI/CD result")),
    )
    args = ["static-analysis", "--path", str(tmp_path), "--provider", "gitlab"]
    if demo:
        args.append("--demo")

    result = CliRunner().invoke(app, args, color=color)

    assert result.exit_code == exit_code
    assert "Running [ci-cd]" in result.stderr
    assert "[repository-settings] skipped" in result.stderr
    assert "Repository settings checks are planned." in result.stdout
    if color:
        assert f"\x1b[{ansi_color}m\x1b[1m[ci-cd]" in result.output
    else:
        assert "\x1b[" not in result.output
    assert "No pyproject.toml found at the repository root." in result.stdout
    assert "Auditing Python dependencies" not in result.stderr
    if demo:
        assert sleep.call_args_list == [call(4.0)] * 2
        assert "Demo mode:" in result.output
        for name in ["npm-dependencies", "python-dependencies", "docker"]:
            assert result.stderr.index(f"[{name}] skipped") < result.stderr.index(
                "Running [ci-cd]"
            )
            assert f"[{name}] skipped" in result.stderr
            if color:
                assert f"\x1b[90m\x1b[1m[{name}]" in result.stdout
        assert result.stdout.count("No security scan performed.") == 2
    else:
        sleep.assert_not_called()
        assert "Demo mode:" not in result.output
        assert "npm-dependencies" not in result.output


def test_cli_reports_python_manifest_before_auditing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "pyproject.toml").touch()
    (tmp_path / "uv.lock").touch()
    monkeypatch.setattr(
        "nomad_sec_ops.steps.ci_cd.run_gitlab",
        Mock(
            return_value=CheckResult(
                status=AnalysisStatus.PASSED, message="CI/CD passed"
            )
        ),
    )

    def check_progress(root: Path) -> CheckResult:
        assert root == tmp_path
        assert "Found pyproject.toml and uv.lock. Auditing Python dependencies..." in (
            capsys.readouterr().err
        )
        return CheckResult(status=AnalysisStatus.PASSED, message="uv audit completed")

    audit = Mock(side_effect=check_progress)
    monkeypatch.setattr("nomad_sec_ops.steps.python_dependencies.run_uv_audit", audit)

    app(
        ["static-analysis", "--path", str(tmp_path), "--provider", "gitlab"],
        standalone_mode=False,
    )

    audit.assert_called_once_with(tmp_path)
    stdout, stderr = capsys.readouterr()
    assert "[python-dependencies] passed" in stderr
    assert "[python-dependencies] uv audit completed" in stdout


@pytest.mark.parametrize("interactive", [False, True])
def test_progress_with_step_failure(
    interactive: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleep = Mock()
    monkeypatch.setattr("nomad_sec_ops.demo.sleep", sleep)
    output = StringIO()
    console = Console(file=output, force_terminal=interactive, width=100)

    class BrokenStep:
        name = "broken"

        def run(self, target: RepositoryTarget) -> CheckResult:
            raise OSError("scanner failed")

    report = run_with_progress(
        RepositoryTarget(None, None),
        [BrokenStep(), DockerAnalysis()],
        console=console,
    )

    assert report.exit_code == 2
    assert [step.result.status for step in report.steps] == [
        AnalysisStatus.ERROR,
        AnalysisStatus.SKIPPED,
    ]
    assert "[broken] error" in output.getvalue()
    assert "[docker] skipped" in output.getvalue()
    sleep.assert_called_once_with(4.0)
    if interactive:
        assert "Analyzing broken" in output.getvalue()
        assert "Analyzing docker" in output.getvalue()
        assert "1/2" in output.getvalue()
    else:
        assert "Running [broken]..." in output.getvalue()
        assert "\x1b[" not in output.getvalue()
