"""Audit the versions recorded in a Python project's uv.lock."""

from collections.abc import Callable

from nomad_sec_ops.models import AnalysisStatus, CheckResult
from nomad_sec_ops.repositories import RepositoryTarget
from nomad_sec_ops.scanners.uv_audit import run_uv_audit


class PythonDependencies:
    name = "python-dependencies"

    def __init__(self, on_scan: Callable[[str], None] | None = None) -> None:
        self.on_scan = on_scan

    def run(self, target: RepositoryTarget) -> CheckResult:
        root = target.root_path or target.local_path
        if root is None:
            return CheckResult(
                status=AnalysisStatus.SKIPPED,
                message="Repository checkout unavailable.",
            )

        manifest = root / "pyproject.toml"
        if not manifest.is_file():
            return CheckResult(
                status=AnalysisStatus.SKIPPED,
                message="No pyproject.toml found at the repository root.",
            )

        if not (root / "uv.lock").is_file():
            return CheckResult(
                status=AnalysisStatus.NOT_EVALUATED,
                message="Found pyproject.toml, but no uv.lock at the repository root.",
            )

        if self.on_scan is not None:
            self.on_scan(
                "Found pyproject.toml and uv.lock. Auditing Python dependencies..."
            )
        try:
            return run_uv_audit(root)
        except FileNotFoundError as error:
            if error.filename != "uv":
                raise
            return CheckResult(
                status=AnalysisStatus.ERROR,
                message="Required executable unavailable: uv. Install uv on PATH.",
                tool="uv",
            )
