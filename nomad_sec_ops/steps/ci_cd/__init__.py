"""Analyze CI/CD configuration using the implementation for its hosting service."""

from nomad_sec_ops.models import AnalysisStatus, CheckResult
from nomad_sec_ops.repositories import RepositoryProvider, RepositoryTarget
from nomad_sec_ops.scanners.gitlab import run_gitlab
from nomad_sec_ops.scanners.zizmor import run_zizmor
from nomad_sec_ops.steps import AnalysisStep
from nomad_sec_ops.steps.ci_cd.config import (
    CONFIG_FILENAME,
    CICDSettings,
    load_ci_cd_settings,
)


class CICDAnalysis(AnalysisStep):
    name = "ci-cd"

    def run(self, target: RepositoryTarget) -> CheckResult:
        settings = CICDSettings()
        if target.local_path is not None:
            candidate = target.local_path / CONFIG_FILENAME
            try:
                settings = load_ci_cd_settings(candidate)
            except (OSError, ValueError) as error:
                return CheckResult(
                    status=AnalysisStatus.NOT_EVALUATED,
                    message="CI/CD skipped because its settings are invalid.",
                    stderr=f"Warning [{candidate}] {error}\n",
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
            rule_overrides = {
                rule_id: rule.disable for rule_id, rule in settings.rules.items()
            }
            return run_zizmor(str(target.local_path), rule_overrides=rule_overrides)
        return CheckResult(
            status=AnalysisStatus.NOT_EVALUATED,
            message="CI/CD not evaluated: GitHub checks require a local checkout.",
        )
