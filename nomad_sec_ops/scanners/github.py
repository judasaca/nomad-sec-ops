"""GitHub Actions CI/CD adapter."""

from nomad_sec_ops.config import (
    CONFIG_FILENAME,
    PINNING_RULE,
    load_defaults,
    load_repository_settings,
)
from nomad_sec_ops.models import AnalysisStatus, CheckResult
from nomad_sec_ops.repositories import RepositoryTarget
from nomad_sec_ops.scanners.zizmor import run_zizmor


def run_github(target: RepositoryTarget) -> CheckResult:
    """Resolve GitHub Actions settings and run zizmor on the checkout."""
    path = target.local_path
    if path is None:
        return CheckResult(
            status=AnalysisStatus.NOT_EVALUATED,
            message="CI/CD not evaluated: GitHub checks require a local checkout.",
        )

    try:
        defaults = load_defaults().ci_cd
    except (OSError, ValueError) as error:
        return CheckResult(
            status=AnalysisStatus.ERROR,
            message=f"Invalid shipped defaults ({CONFIG_FILENAME}): {error}",
        )

    config_path = (target.root_path or path) / CONFIG_FILENAME
    try:
        overrides = load_repository_settings(config_path).ci_cd
    except (OSError, ValueError) as error:
        return CheckResult(
            status=AnalysisStatus.NOT_EVALUATED,
            message="CI/CD skipped because its settings are invalid.",
            stderr=f"Warning [{config_path}] {error}\n",
        )

    settings = defaults.with_overrides(overrides)
    pinning = settings.rules.get(PINNING_RULE)
    return run_zizmor(
        str(path),
        rule_overrides={
            rule_id: rule.disable for rule_id, rule in settings.rules.items()
        },
        unpinned_uses_policies=pinning.policies if pinning is not None else {},
    )
