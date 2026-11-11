"""Analyze CI/CD configuration using the implementation for its hosting service."""

from nomad_sec_ops.models import AnalysisStatus, CheckResult
from nomad_sec_ops.repositories import RepositoryTarget
from nomad_sec_ops.scanners.zizmor import run_zizmor


class CICDAnalysis:
    name = "ci-cd"

    def run(self, target: RepositoryTarget) -> CheckResult:
        remote = target.remote
        if remote is None:
            return CheckResult(
                status=AnalysisStatus.NOT_EVALUATED,
                message="CI/CD not evaluated: no Git origin identifies the host.",
            )
        if remote.host == "gitlab.com":
            return CheckResult(
                status=AnalysisStatus.SKIPPED,
                message="Skipping CI/CD analysis: GitLab provider is not implemented.",
            )
        if remote.host != "github.com":
            return CheckResult(
                status=AnalysisStatus.NOT_EVALUATED,
                message=f"CI/CD not evaluated: unsupported host {remote.host}.",
            )
        scanner_target = (
            str(target.local_path)
            if target.local_path is not None
            else remote.github_slug
        )
        return run_zizmor(scanner_target)
