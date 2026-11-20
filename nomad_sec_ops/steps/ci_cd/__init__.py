"""Analyze CI/CD configuration using the implementation for its hosting service."""

from nomad_sec_ops.models import AnalysisStatus, CheckResult
from nomad_sec_ops.repositories import RepositoryProvider, RepositoryTarget
from nomad_sec_ops.scanners.gitlab import run_gitlab
from nomad_sec_ops.scanners.zizmor import run_zizmor
from nomad_sec_ops.steps import AnalysisStep
from nomad_sec_ops.steps.ci_cd.config import CONFIG_FILENAME, validate_ci_cd_config


class CICDAnalysis(AnalysisStep):
    name = "ci-cd"

    def run(self, target: RepositoryTarget) -> CheckResult:
        if target.local_path is not None:
            config_path = target.local_path / CONFIG_FILENAME
            try:
                validate_ci_cd_config(config_path)
            except (OSError, ValueError) as error:
                return CheckResult(
                    status=AnalysisStatus.NOT_EVALUATED,
                    message="CI/CD skipped because its settings are invalid.",
                    stderr=f"Warning [{config_path}] {error}\n",
                )

        remote = target.remote
        if target.hosting_provider == RepositoryProvider.GITLAB:
            return run_gitlab(target)
        if remote is None:
            return CheckResult(
                status=AnalysisStatus.NOT_EVALUATED,
                message="CI/CD not evaluated: no Git origin identifies the host.",
            )
        if target.hosting_provider != RepositoryProvider.GITHUB:
            return CheckResult(
                status=AnalysisStatus.NOT_EVALUATED,
                message=f"CI/CD not evaluated: unsupported host {remote.host}.",
            )
        if target.local_path is not None:
            return run_zizmor(str(target.local_path))
        return CheckResult(
            status=AnalysisStatus.NOT_EVALUATED,
            message="CI/CD not evaluated: GitHub checks require a local checkout.",
        )
