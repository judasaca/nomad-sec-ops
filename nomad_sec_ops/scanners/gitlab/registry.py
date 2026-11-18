"""Map zizmor audit IDs to their GitLab implementations."""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Protocol

from nomad_sec_ops.models import CheckResult
from nomad_sec_ops.scanners.gitlab.context import GitLabContext
from nomad_sec_ops.scanners.gitlab.rules.unpinned_images import UnpinnedImages


class GitLabRule(Protocol):
    @property
    def name(self) -> str:
        """Stable check identifier, matching zizmor where semantics align."""
        ...

    def run(self, context: GitLabContext) -> CheckResult: ...


RULE_REGISTRY: Mapping[str, GitLabRule] = MappingProxyType(
    {UnpinnedImages.upstream.rule_id: UnpinnedImages()}
)
