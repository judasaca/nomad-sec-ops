"""Audit inventory pinned to zizmor v1.32.0, independent of network access.

Inventory: crates/zizmor/src/registry.rs at ZIZMOR_COMMIT.
Offline eligibility: audit constructors in crates/zizmor/src/audit/*.rs.
Five constructors skip loading when state.no_online_audits is true. In
particular ref-version-mismatch is online despite its documentation table.
Audits with optional online enhancements count as offline if they still load.
Review this inventory and rule mappings explicitly when upgrading the baseline.
"""

from dataclasses import dataclass

ZIZMOR_VERSION = "1.32.0"
ZIZMOR_COMMIT = "21bd300700d43d9ba04b0c1fce72a89391ac80b4"
ZIZMOR_SOURCE_ROOT = f"https://github.com/zizmorcore/zizmor/blob/{ZIZMOR_COMMIT}"


@dataclass(frozen=True)
class ZizmorAudit:
    rule_id: str
    offline: bool

    @property
    def source_url(self) -> str:
        filename = self.rule_id.replace("-", "_")
        return f"{ZIZMOR_SOURCE_ROOT}/crates/zizmor/src/audit/{filename}.rs"


ONLINE_RULES = frozenset(
    {
        "impostor-commit",
        "known-vulnerable-actions",
        "ref-confusion",
        "ref-version-mismatch",
        "stale-action-refs",
    }
)

# Exact registered identifiers, including rules without a GitLab adaptation yet.
AUDITS = tuple(
    ZizmorAudit(rule_id, offline=rule_id not in ONLINE_RULES)
    for rule_id in (
        "adhoc-packages",
        "anonymous-definition",
        "archived-uses",
        "artipacked",
        "bot-conditions",
        "cache-poisoning",
        "concurrency-limits",
        "dangerous-triggers",
        "dependabot-cooldown",
        "dependabot-execution",
        "excessive-permissions",
        "forbidden-uses",
        "github-app",
        "github-env",
        "hardcoded-container-credentials",
        "impostor-commit",
        "insecure-commands",
        "insecure-url-scheme",
        "known-vulnerable-actions",
        "misfeature",
        "obfuscation",
        "overprovisioned-secrets",
        "ref-confusion",
        "ref-version-mismatch",
        "secrets-inherit",
        "secrets-outside-env",
        "self-hosted-runner",
        "self-repository",
        "stale-action-refs",
        "superfluous-actions",
        "template-injection",
        "typosquat-uses",
        "undocumented-permissions",
        "unpinned-images",
        "unpinned-tools",
        "unpinned-uses",
        "unredacted-secrets",
        "unsound-condition",
        "unsound-contains",
        "unsound-ternary",
        "use-trusted-publishing",
    )
)
