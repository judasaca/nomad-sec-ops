"""Placeholder for security checks against repository hosting settings."""

from nomad_sec_ops.models import AnalysisStatus, CheckResult
from nomad_sec_ops.repositories import RepositoryTarget


class RepositorySettingsAnalysis:
    name = "repository-settings"

    def run(self, target: RepositoryTarget) -> CheckResult:
        return CheckResult(
            status=AnalysisStatus.SKIPPED,
            message="Repository settings checks are planned.",
        )
