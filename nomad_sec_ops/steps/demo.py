"""Simulated analysis steps for CLI demonstrations; no scanners are invoked."""

from dataclasses import dataclass
from time import sleep

from nomad_sec_ops.models import AnalysisStatus, CheckResult
from nomad_sec_ops.repositories import RepositoryTarget


@dataclass(frozen=True)
class DemoAnalysis:
    name: str
    label: str
    delay_seconds: float = 4.0

    def run(self, target: RepositoryTarget) -> CheckResult:
        sleep(self.delay_seconds)
        return CheckResult(
            status=AnalysisStatus.SKIPPED,
            message=f"Demo completed: {self.label}. No security scan performed.",
            tool="demo",
        )


def demo_steps() -> tuple[DemoAnalysis, ...]:
    return (
        DemoAnalysis("npm-dependencies", "npm dependencies"),
        DemoAnalysis("python-dependencies", "Python dependencies"),
        DemoAnalysis("docker", "Docker"),
    )
