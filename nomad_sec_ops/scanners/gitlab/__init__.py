"""GitLab CI/CD adapter, shared by hosted and self-hosted GitLab instances.

Rules will implement GitLab equivalents of applicable zizmor checks. This
scaffold does not claim security coverage until those rules are implemented.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from nomad_sec_ops.models import AnalysisReport, AnalysisStatus, CheckResult, StepResult
from nomad_sec_ops.repositories import RepositoryTarget


@dataclass(frozen=True)
class GitLabContext:
    """Repository metadata available to each rule.

    Pipeline parsing, include resolution, and authenticated API access belong in
    shared context preparation when rules need them, rather than in each rule.
    """

    target: RepositoryTarget


class GitLabRule(Protocol):
    @property
    def name(self) -> str:
        """Stable check identifier, matching zizmor where semantics align."""
        ...

    def run(self, context: GitLabContext) -> CheckResult: ...


# Add production rules here as they are implemented; no checks run implicitly.
DEFAULT_RULES: tuple[GitLabRule, ...] = ()


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
    )
