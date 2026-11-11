"""Verify GitLab routing and rule aggregation."""

from dataclasses import dataclass
from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from nomad_sec_ops.cli import app
from nomad_sec_ops.models import AnalysisStatus, CheckResult
from nomad_sec_ops.repositories import (
    RemoteRepository,
    RepositoryProvider,
    RepositoryTarget,
)
from nomad_sec_ops.scanners.gitlab import GitLabContext, run_gitlab
from nomad_sec_ops.steps.ci_cd import CICDAnalysis


@pytest.mark.parametrize("local", [False, True])
@pytest.mark.parametrize("host", ["gitlab.com", "code.example.org"])
def test_gitlab_dispatch(
    local: bool, host: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = RepositoryTarget(
        tmp_path if local else None,
        RemoteRepository(host, "group/subgroup/repo"),
        RepositoryProvider.GITLAB if host != "gitlab.com" else None,
    )
    result = CheckResult(status=AnalysisStatus.NOT_EVALUATED, message="scaffold")
    gitlab = Mock(return_value=result)
    zizmor = Mock()
    monkeypatch.setattr("nomad_sec_ops.steps.ci_cd.run_gitlab", gitlab)
    monkeypatch.setattr("nomad_sec_ops.steps.ci_cd.run_zizmor", zizmor)

    assert CICDAnalysis().run(target) == result
    gitlab.assert_called_once_with(target)
    zizmor.assert_not_called()


@pytest.mark.parametrize("local", [False, True])
def test_self_hosted_cli(local: bool, tmp_path: Path) -> None:
    args = ["static-analysis", "--provider", "gitlab"]
    args.extend(
        ["--path", str(tmp_path)]
        if local
        else ["--repo", "ssh://git@code.example.org:2222/group/subgroup/repo.git"]
    )

    result = CliRunner().invoke(app, args)

    assert result.exit_code == 3
    expected = (
        "No .gitlab-ci.yml found" if local else "Offline rule requires a local checkout"
    )
    assert expected in result.output


def test_invalid_provider() -> None:
    result = CliRunner().invoke(app, ["static-analysis", "--provider", "unknown"])

    assert result.exit_code == 2


def test_empty_registry_does_not_pass() -> None:
    result = run_gitlab(RepositoryTarget(None, None), rules=[])

    assert result.status == AnalysisStatus.NOT_EVALUATED
    assert result.tool == "gitlab-ci"


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([AnalysisStatus.PASSED], AnalysisStatus.PASSED),
        ([AnalysisStatus.SKIPPED], AnalysisStatus.SKIPPED),
        ([AnalysisStatus.SKIPPED, AnalysisStatus.PASSED], AnalysisStatus.PASSED),
        (
            [AnalysisStatus.PASSED, AnalysisStatus.NOT_EVALUATED],
            AnalysisStatus.NOT_EVALUATED,
        ),
        (
            [AnalysisStatus.NOT_EVALUATED, AnalysisStatus.FINDINGS],
            AnalysisStatus.FINDINGS,
        ),
        ([AnalysisStatus.FINDINGS, AnalysisStatus.ERROR], AnalysisStatus.ERROR),
    ],
)
def test_rule_results(
    statuses: list[AnalysisStatus], expected: AnalysisStatus, tmp_path: Path
) -> None:
    target = RepositoryTarget(tmp_path, None, RepositoryProvider.GITLAB)
    contexts: list[GitLabContext] = []

    @dataclass
    class ExampleRule:
        name: str
        status: AnalysisStatus

        def run(self, context: GitLabContext) -> CheckResult:
            contexts.append(context)
            return CheckResult(
                status=self.status,
                message=f"result {self.name}",
                stdout=f"evidence {self.name}\n",
                stderr=f"diagnostic {self.name}\n",
            )

    rules = [
        ExampleRule(f"rule-{index}", status) for index, status in enumerate(statuses)
    ]

    result = run_gitlab(target, rules=rules)

    assert result.status == expected
    assert len(contexts) == len(rules)
    assert all(context.target is target for context in contexts)
    for rule in rules:
        assert f"[{rule.name}] result {rule.name}" in result.stdout
        assert f"evidence {rule.name}" in result.stdout
        assert f"diagnostic {rule.name}" in result.stderr
