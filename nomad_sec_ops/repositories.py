"""Identify repositories and prepare local checkouts for analysis."""

import os
import re
import subprocess
from collections.abc import Generator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from tempfile import TemporaryDirectory
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
        if self.provider == RepositoryProvider.GITHUB and (
            self.remote is None or self.remote.host != "github.com"
        ):
            return None
        if self.provider is not None:
            return self.provider
        if self.remote is not None:
            return {
                "github.com": RepositoryProvider.GITHUB,
                "gitlab.com": RepositoryProvider.GITLAB,
            }.get(self.remote.host)
        return None


@contextmanager
def resolve_target(
    path: Path | None = None,
    repo: str | None = None,
    provider: RepositoryProvider | None = None,
    *,
    branch: str | None = None,
) -> Generator[RepositoryTarget]:
    """Keep the checkout available for the lifetime of an analysis run."""
    if path is not None and repo is not None:
        raise ValueError("--path and --repo cannot be used together.")
    if repo is not None:
        remote = parse_remote(repo)
        target = RepositoryTarget(local_path=None, remote=remote, provider=provider)
        if target.hosting_provider is None:
            yield target
            return
        with checkout_repository(repo, remote, branch=branch) as local_path:
            yield replace(target, local_path=local_path)
        return

    local_path = (path if path is not None else Path.cwd()).resolve()
    yield RepositoryTarget(local_path, local_remote(local_path), provider)


@contextmanager
def checkout_repository(
    url: str, remote: RemoteRepository, *, branch: str | None = None
) -> Generator[Path]:
    root = Path.cwd() / ".nomad-sec-ops-checkouts"
    root.mkdir(mode=0o700, exist_ok=True)
    # Keep downloads ignored in directories outside the Nomad SecOps source repo too.
    with (
        suppress(FileExistsError),
        (root / ".gitignore").open("x", encoding="utf-8") as ignore,
    ):
        ignore.write("*\n")

    label = f"{remote.host}/{remote.path}"
    branch_args: list[str] = []
    if branch is not None:
        label += f" at branch {branch!r}"
        branch_args = [f"--branch={branch}"]
    with TemporaryDirectory(dir=root) as directory:
        checkout = Path(directory) / "repo"
        try:
            result = subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth=1",
                    "--no-tags",
                    "--no-recurse-submodules",
                    "--config=core.symlinks=false",
                    *branch_args,
                    "--",
                    url,
                    str(checkout),
                ],
                capture_output=True,
                timeout=300,
                check=False,
                env={
                    **os.environ,
                    "GIT_TERMINAL_PROMPT": "0",
                    "GIT_ALLOW_PROTOCOL": "http:https:ssh:git",
                },
            )
        except subprocess.TimeoutExpired as error:
            raise ValueError(f"Repository download timed out for {label}.") from error
        if result.returncode != 0:
            raise ValueError(
                f"Could not download {label} (Git exit code {result.returncode}). "
                "Check the repository URL, branch, and your Git credentials."
            )
        yield checkout


def checkout_revision(path: Path) -> tuple[str | None, str | None]:
    """Read the current branch and abbreviated HEAD, when available."""

    def git_output(*args: str) -> str | None:
        try:
            result = subprocess.run(
                ["git", "-C", str(path), *args],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=10,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return None
        return result.stdout.strip() if result.returncode == 0 else None

    ref = git_output("symbolic-ref", "--quiet", "HEAD")
    commit = git_output("rev-parse", "--verify", "--short", "HEAD")
    return ref.removeprefix("refs/heads/") if ref else None, commit


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
