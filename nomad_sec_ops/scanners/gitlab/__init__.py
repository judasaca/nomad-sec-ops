"""GitLab CI/CD adapter, shared by hosted and self-hosted GitLab instances."""

from collections.abc import Sequence
from typing import Protocol

from nomad_sec_ops.models import AnalysisReport, AnalysisStatus, CheckResult, StepResult
from nomad_sec_ops.repositories import RepositoryTarget
from nomad_sec_ops.scanners.gitlab.context import GitLabContext as GitLabContext
from nomad_sec_ops.scanners.gitlab.unpinned_images import UnpinnedImages


class GitLabRule(Protocol):
    @property
    def name(self) -> str:
        """Stable check identifier, matching zizmor where semantics align."""
        ...

    def run(self, context: GitLabContext) -> CheckResult: ...


DEFAULT_RULES: tuple[GitLabRule, ...] = (UnpinnedImages(),)


def run_gitlab(
    target: RepositoryTarget, *, rules: Sequence[GitLabRule] | None = None
) -> CheckResult:
    """Run the registered GitLab rules using the shared status contract."""
    selected_rules = DEFAULT_RULES if rules is None else rules
    if not selected_rules:
        return CheckResult(
            status=AnalysisStatus.NOT_EVALUATED,
            message="GitLab CI/CD not evaluated: no security rules are registered.",
            tool="gitlab-ci",
        )

    context = GitLabContext(target)
    results = [
        StepResult(name=rule.name, result=rule.run(context)) for rule in selected_rules
    ]
    report = AnalysisReport(steps=results)
    status = {
        0: (
            AnalysisStatus.PASSED
            if any(item.result.status == AnalysisStatus.PASSED for item in results)
            else AnalysisStatus.SKIPPED
        ),
        1: AnalysisStatus.FINDINGS,
        2: AnalysisStatus.ERROR,
        3: AnalysisStatus.NOT_EVALUATED,
    }[report.exit_code]
    return CheckResult(
        status=status,
        message=f"GitLab CI/CD: {len(results)} rule(s) completed ({status.value}).",
        tool="gitlab-ci",
        stdout="".join(
            f"[{item.name}] {item.result.message}\n{item.result.stdout}"
            for item in results
        ),
        stderr="".join(item.result.stderr for item in results),
        findings=[finding for item in results for finding in item.result.findings],
    )
