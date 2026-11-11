"""Report mapped GitLab rule coverage against a versioned zizmor inventory."""

from collections.abc import Sequence
from typing import Literal

from pydantic import BaseModel

from nomad_sec_ops.models import UpstreamRule
from nomad_sec_ops.scanners.gitlab import DEFAULT_RULES, GitLabRule
from nomad_sec_ops.scanners.zizmor_catalog import (
    AUDITS,
    ZIZMOR_COMMIT,
    ZIZMOR_SOURCE_ROOT,
    ZIZMOR_VERSION,
)

COVERAGE_NOTE = (
    "Measures mapped rule coverage, not full behavioral equivalence. "
    "GitHub-specific rules remain in the denominator; "
    "implemented rules retain their documented scope limits."
)


class RuleCoverage(BaseModel):
    rule_id: str
    offline: bool
    implemented: bool
    source_url: str


class EquivalenceReport(BaseModel):
    metric: str = "mapped_rule_coverage"
    provider: str = "gitlab"
    upstream_tool: str = "zizmor"
    upstream_version: str = ZIZMOR_VERSION
    upstream_commit: str = ZIZMOR_COMMIT
    inventory_source_url: str = f"{ZIZMOR_SOURCE_ROOT}/crates/zizmor/src/registry.rs"
    scope: Literal["offline", "all"]
    implemented_count: int
    total_count: int
    percentage: float
    rules: list[RuleCoverage]
    unmatched_implementations: list[str]
    note: str = COVERAGE_NOTE


def build_equivalence_report(
    *,
    include_online: bool = False,
    rules: Sequence[GitLabRule] | None = None,
) -> EquivalenceReport:
    """Count unique upstream IDs only when their versioned metadata matches."""
    selected = DEFAULT_RULES if rules is None else rules
    inventory = {audit.rule_id: audit for audit in AUDITS}
    implemented: set[str] = set()
    unmatched: list[str] = []
    for rule in selected:
        upstream = getattr(rule, "upstream", None)
        if (
            isinstance(upstream, UpstreamRule)
            and upstream.tool == "zizmor"
            and upstream.version == ZIZMOR_VERSION
            and upstream.commit == ZIZMOR_COMMIT
            and upstream.rule_id in inventory
            and upstream.source_url == inventory[upstream.rule_id].source_url
        ):
            implemented.add(upstream.rule_id)
        else:
            unmatched.append(rule.name)
    coverage = [
        RuleCoverage(
            rule_id=audit.rule_id,
            offline=audit.offline,
            implemented=audit.rule_id in implemented,
            source_url=audit.source_url,
        )
        for audit in AUDITS
        if include_online or audit.offline
    ]
    count = sum(rule.implemented for rule in coverage)
    return EquivalenceReport(
        scope="all" if include_online else "offline",
        implemented_count=count,
        total_count=len(coverage),
        percentage=round(100 * count / len(coverage), 2) if coverage else 0.0,
        rules=coverage,
        unmatched_implementations=sorted(set(unmatched)),
    )
