"""Identify the hosting service of local and remote repositories."""

import re
import subprocess
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit


class RepositoryProvider(StrEnum):
    GITHUB = "github"
    GITLAB = "gitlab"


@dataclass(frozen=True)
class RemoteRepository:
    host: str
    path: str

    @property
    def github_slug(self) -> str:
        slug = self.path.removesuffix(".git")
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", slug, flags=re.ASCII):
            raise ValueError("GitHub URL must identify an owner and repository.")
        if any(part.startswith(("-", ".")) for part in slug.split("/")):
            raise ValueError("Invalid GitHub owner or repository name.")
        return slug


@dataclass(frozen=True)
class RepositoryTarget:
    """Repository context shared by all analysis steps."""

    local_path: Path | None
    remote: RemoteRepository | None
    provider: RepositoryProvider | None = None

    @property
    def hosting_provider(self) -> RepositoryProvider | None:
        if self.provider is not None:
            return self.provider
        if self.remote is not None:
            return {
                "github.com": RepositoryProvider.GITHUB,
                "gitlab.com": RepositoryProvider.GITLAB,
            }.get(self.remote.host)
        return None


def resolve_target(
    path: Path | None = None,
    repo: str | None = None,
    provider: RepositoryProvider | None = None,
) -> RepositoryTarget:
    if path is not None and repo is not None:
        raise ValueError("--path and --repo cannot be used together.")
    if repo is not None:
        return RepositoryTarget(
            local_path=None, remote=parse_remote(repo), provider=provider
        )
    local_path = (path if path is not None else Path.cwd()).resolve()
    return RepositoryTarget(
        local_path=local_path, remote=local_remote(local_path), provider=provider
    )


def parse_remote(url: str) -> RemoteRepository:
    """Parse HTTPS, SSH, Git transport, and SCP-style Git remote URLs."""
    if any(character.isspace() for character in url):
        raise ValueError("Repository URL must not contain whitespace.")
    if "://" in url:
        parsed = urlsplit(url)
        if parsed.scheme not in {"https", "http", "ssh", "git"}:
            raise ValueError("Unsupported repository URL scheme.")
        if not parsed.hostname or parsed.query or parsed.fragment:
            raise ValueError("Invalid repository URL.")
        host = parsed.hostname.lower()
        path = parsed.path.strip("/")
    else:
        match = re.fullmatch(r"(?:[^@/:]+@)?([^/:]+):(.+)", url)
        if match is None:
            raise ValueError("Expected a remote Git repository URL.")
        host, path = match.groups()
        host = host.lower()
        path = path.strip("/")
    if not path:
        raise ValueError("Repository URL must include a repository path.")
    remote = RemoteRepository(host, path)
    if host == "github.com":
        _ = remote.github_slug
    return remote


def local_remote(path: Path) -> RemoteRepository | None:
    """Use origin as the authoritative host, including from nested directories."""
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0 or result.stdout.strip() != "true":
        return None
    result = subprocess.run(
        ["git", "-C", str(path), "config", "--get", "remote.origin.url"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode == 1:
        return None
    if result.returncode != 0:
        raise ValueError("Could not read the repository's origin URL.")
    return parse_remote(result.stdout.strip())
