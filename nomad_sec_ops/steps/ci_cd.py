"""Analyze CI/CD configuration using the implementation for its hosting service."""

from nomad_sec_ops.models import AnalysisStatus, CheckResult
from nomad_sec_ops.repositories import RepositoryProvider, RepositoryTarget
from nomad_sec_ops.scanners.gitlab import run_gitlab
from nomad_sec_ops.scanners.zizmor import run_zizmor
from nomad_sec_ops.steps import AnalysisStep


class CICDAnalysis(AnalysisStep):
    name = "ci-cd"

    def run(self, target: RepositoryTarget) -> CheckResult:
        remote = target.remote
        if target.hosting_provider == RepositoryProvider.GITLAB:
            return run_gitlab(target)
        if remote is None:
            return CheckResult(
                status=AnalysisStatus.NOT_EVALUATED,
                message="CI/CD not evaluated: no Git origin identifies the host.",
            )
        if (
            target.hosting_provider != RepositoryProvider.GITHUB
            or remote.host != "github.com"
        ):
            return CheckResult(
                status=AnalysisStatus.NOT_EVALUATED,
                message=f"CI/CD not evaluated: unsupported host {remote.host}.",
            )
        if target.local_path is not None:
            return run_zizmor(str(target.local_path))
        return run_zizmor(remote.github_slug, remote=True)
