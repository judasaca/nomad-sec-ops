"""Shared behavior for simulated analysis steps."""

from time import sleep

from nomad_sec_ops.models import AnalysisStatus, CheckResult
from nomad_sec_ops.repositories import RepositoryTarget


class DemoAnalysis:
    name: str
    label: str
    delay_seconds = 4.0

    def run(self, target: RepositoryTarget) -> CheckResult:
        sleep(self.delay_seconds)
        return CheckResult(
            status=AnalysisStatus.SKIPPED,
            message=f"Demo completed: {self.label}. No security scan performed.",
            tool="demo",
        )
