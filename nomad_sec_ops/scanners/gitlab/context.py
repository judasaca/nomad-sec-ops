"""Shared input context for offline GitLab rules."""

from dataclasses import dataclass

from nomad_sec_ops.repositories import RepositoryTarget


@dataclass(frozen=True)
class GitLabContext:
    """Selected repository; offline rules only read the local checkout."""

    target: RepositoryTarget
