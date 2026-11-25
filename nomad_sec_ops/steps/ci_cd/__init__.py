"""Analyze CI/CD configuration using the implementation for its hosting service."""

from nomad_sec_ops.models import AnalysisStatus, CheckResult
from nomad_sec_ops.repositories import RepositoryProvider, RepositoryTarget
from nomad_sec_ops.scanners.github import run_github
from nomad_sec_ops.scanners.gitlab import run_gitlab
from nomad_sec_ops.steps import AnalysisStep


class CICDAnalysis(AnalysisStep):
    name = "ci-cd"

    def run(self, target: RepositoryTarget) -> CheckResult:
        provider = target.hosting_provider
        if provider == RepositoryProvider.GITHUB:
            return run_github(target)
        if provider == RepositoryProvider.GITLAB:
            return run_gitlab(target)

        remote = target.remote
        if remote is None:
            return CheckResult(
                status=AnalysisStatus.NOT_EVALUATED,
                message="CI/CD not evaluated: no Git origin identifies the host.",
            )
        return CheckResult(
            status=AnalysisStatus.NOT_EVALUATED,
            message=f"CI/CD not evaluated: unsupported host {remote.host}.",
        )
