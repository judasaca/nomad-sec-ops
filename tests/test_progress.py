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
from nomad_sec_ops.steps.demo import DemoAnalysis


@pytest.mark.parametrize("demo", [False, True])
@pytest.mark.parametrize(
    ("status", "exit_code"),
    [
        (AnalysisStatus.PASSED, 0),
        (AnalysisStatus.FINDINGS, 1),
        (AnalysisStatus.ERROR, 2),
    ],
)
def test_demo_cli(
    demo: bool,
    status: AnalysisStatus,
    exit_code: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sleep = Mock()
    monkeypatch.setattr("nomad_sec_ops.steps.demo.sleep", sleep)
    monkeypatch.setattr(
        "nomad_sec_ops.steps.ci_cd.run_gitlab",
        Mock(return_value=CheckResult(status=status, message="CI/CD result")),
    )
    args = ["static-analysis", "--path", str(tmp_path), "--provider", "gitlab"]
    if demo:
        args.append("--demo")

    result = CliRunner().invoke(app, args)

    assert result.exit_code == exit_code
    assert "Running [ci-cd]" in result.stderr
    assert "\x1b[" not in result.output
    if demo:
        assert sleep.call_args_list == [call(4.0)] * 3
        assert "Demo mode:" in result.output
        for name in ["npm-dependencies", "python-dependencies", "docker"]:
            assert f"Running [{name}]" in result.stderr
            assert f"[{name}] skipped" in result.stderr
        assert result.stdout.count("No security scan performed.") == 3
    else:
        sleep.assert_not_called()
        assert "Demo mode:" not in result.output
        assert "npm-dependencies" not in result.output


@pytest.mark.parametrize("interactive", [False, True])
def test_progress_with_step_failure(
    interactive: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleep = Mock()
    monkeypatch.setattr("nomad_sec_ops.steps.demo.sleep", sleep)
    output = StringIO()
    console = Console(file=output, force_terminal=interactive, width=100)

    class BrokenStep:
        name = "broken"

        def run(self, target: RepositoryTarget) -> CheckResult:
            raise OSError("scanner failed")

    report = run_with_progress(
        RepositoryTarget(None, None),
        [BrokenStep(), DemoAnalysis("docker", "Docker")],
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
