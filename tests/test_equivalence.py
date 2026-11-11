"""Verify the coverage metric, version matching, and offline reporting CLI."""

import json
from dataclasses import dataclass
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from nomad_sec_ops.cli import app
from nomad_sec_ops.equivalence import build_equivalence_report
from nomad_sec_ops.models import CheckResult, UpstreamRule
from nomad_sec_ops.scanners.gitlab import GitLabContext
from nomad_sec_ops.scanners.gitlab.unpinned_images import UPSTREAM, UnpinnedImages
from nomad_sec_ops.scanners.zizmor_catalog import AUDITS


@dataclass
class MappedRule:
    upstream: UpstreamRule
    name: str = "example"

    def run(self, context: GitLabContext) -> CheckResult:
        raise AssertionError("Coverage reporting must not execute audits")


def test_pinned_inventory() -> None:
    assert len(AUDITS) == len({audit.rule_id for audit in AUDITS}) == 41
    assert {audit.rule_id for audit in AUDITS if not audit.offline} == {
        "impostor-commit",
        "known-vulnerable-actions",
        "ref-confusion",
        "ref-version-mismatch",
        "stale-action-refs",
    }


@pytest.mark.parametrize(
    ("include_online", "total", "percentage"), [(False, 36, 2.78), (True, 41, 2.44)]
)
def test_default_coverage(include_online: bool, total: int, percentage: float) -> None:
    report = build_equivalence_report(include_online=include_online)

    assert report.total_count == total
    assert report.implemented_count == 1
    assert report.percentage == percentage
    assert [rule.rule_id for rule in report.rules if rule.implemented] == [
        "unpinned-images"
    ]
    assert report.unmatched_implementations == []


def test_empty_and_duplicate_implementations() -> None:
    assert build_equivalence_report(rules=[]).percentage == 0
    report = build_equivalence_report(rules=[UnpinnedImages(), UnpinnedImages()])

    assert report.implemented_count == 1
    assert report.percentage == 2.78


@pytest.mark.parametrize(
    "changes",
    [
        {"version": "other"},
        {"commit": "other"},
        {"tool": "other"},
        {"rule_id": "unknown-rule"},
        {"source_url": "https://example.org/other.rs"},
    ],
)
def test_mismatched_mapping_is_excluded(changes: dict[str, str]) -> None:
    rule = MappedRule(UPSTREAM.model_copy(update=changes))

    report = build_equivalence_report(rules=[rule])

    assert report.implemented_count == 0
    assert report.percentage == 0
    assert report.unmatched_implementations == [rule.name]


def test_online_mapping_only_counts_in_all_scope() -> None:
    audit = next(audit for audit in AUDITS if not audit.offline)
    upstream = UPSTREAM.model_copy(
        update={
            "rule_id": audit.rule_id,
            "source_url": audit.source_url,
        }
    )
    rule = MappedRule(upstream)

    assert build_equivalence_report(rules=[rule]).implemented_count == 0
    assert (
        build_equivalence_report(rules=[rule], include_online=True).implemented_count
        == 1
    )


def test_cli_is_independent_of_git_and_scanners(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = Mock(side_effect=AssertionError("No subprocesses expected"))
    monkeypatch.setattr("subprocess.run", process)

    result = CliRunner().invoke(app, ["equivalence"])

    assert result.exit_code == 0
    assert "Rule coverage: 2.78% (1/36)" in result.output
    assert "Implemented: unpinned-images" in result.output
    assert "not full behavioral equivalence" in result.output
    process.assert_not_called()


def test_cli_all_with_details() -> None:
    result = CliRunner().invoke(app, ["equivalence", "--all", "--details"])

    assert result.exit_code == 0
    assert "Rule coverage: 2.44% (1/41)" in result.output
    assert "  implemented: unpinned-images" in result.output
    assert "  missing: ref-version-mismatch" in result.output
    assert result.output.count("  missing:") == 40


def test_cli_json() -> None:
    result = CliRunner().invoke(app, ["equivalence", "--json"])

    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["metric"] == "mapped_rule_coverage"
    assert report["scope"] == "offline"
    assert report["upstream_commit"] == UPSTREAM.commit
    assert report["percentage"] == 2.78
    assert report["total_count"] == len(report["rules"]) == 36
    assert "ref-version-mismatch" not in [rule["rule_id"] for rule in report["rules"]]


def test_unmapped_rule_is_excluded() -> None:
    class UnmappedRule:
        name = "no-upstream"

        def run(self, context: GitLabContext) -> CheckResult:
            raise AssertionError("Coverage reporting must not execute audits")

    report = build_equivalence_report(rules=[UnmappedRule()])

    assert report.implemented_count == 0
    assert report.unmatched_implementations == ["no-upstream"]
