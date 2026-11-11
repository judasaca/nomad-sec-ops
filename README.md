# Nomad SecOps

Nomad SecOps is a security analysis CLI for auditing GitHub and GitLab
repositories in the Nomad ecosystem. It aims to help maintainers identify insecure
repository settings, improve CI/CD practices, and apply consistent security checks
across projects.

The tool should detect the technologies a repository uses, select the relevant
checks, and produce actionable findings. Maintainers should be able to run the same
analysis locally and in CI/CD pipelines.

> **Status:** The CLI runs zizmor for GitHub repositories and skips it for GitLab
> repositories. Other checks, shared configuration, and structured reports remain
> planned features.

## Development setup

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then run
the following commands from the repository root. The project uses Python 3.14;
uv can download it if needed.

```sh
uv sync --locked
uv run nomadsecops --help
uv run nomadsecops --version
```

The initial toolchain is:

| Tool | Purpose |
| --- | --- |
| uv | Python, environment, and dependency management. |
| Typer | CLI commands, arguments, and help. |
| Pydantic | Validation and structured models as analysis features are added. |
| Ruff | Linting, import sorting, and formatting. |
| pytest | Unit and CLI tests. |
| ty | Static type checking. |
| zizmor | Security analysis of GitHub Actions and related configuration. |

Run the development checks with:

```sh
uv run ruff check .
uv run ruff format --check .
uv run ty check
uv run pytest
```

Use `uv run ruff format .` to format code. Commit `uv.lock` when dependencies
change. CI runs these same checks against the committed lockfile.

To call `nomadsecops` directly, activate the project's virtual environment:

```sh
source .venv/bin/activate
nomadsecops --help
```

The command is installed into the virtual environment by `uv sync`. The project
uses `uv_build` for packaging. The module entry point,
`uv run python -m nomad_sec_ops`, also remains available.

## Objectives

- Audit repositories hosted on GitHub and GitLab, including projects that use
  multiple languages or contain several packages.
- Define a shared security baseline for the Nomad ecosystem, with explicit,
  documented exceptions where needed.
- Check both repository contents and GitHub and GitLab repository settings.
- Verify that relevant security checks exist in CI/CD and, where supported, run
  the underlying analysis tools.
- Provide useful results locally and enforce configurable security requirements
  in CI/CD.

## Checks

### Implemented: GitHub analysis with zizmor

- Local targets: read the Git `origin` URL to identify the host, then run zizmor
  against the selected directory. Git must be installed. Host detection also works
  when the selected directory is inside a repository.
- Remote GitHub targets: convert HTTPS or SSH URLs to zizmor's `owner/repo` input.
  Zizmor fetches the remote content; Nomad SecOps does not clone the repository.
- GitLab targets: skip zizmor and return `0` without running a scanner.
- Directories without a Git origin and hosts other than `github.com` and
  `gitlab.com`: report the rule as not evaluated and return `3`. Self-hosted
  GitHub and GitLab instances are not yet detected.

Zizmor is installed by `uv sync`. Local scans work without credentials, using
zizmor's offline mode; audits that need API access are unavailable in that mode.
For remote scans, set `GH_TOKEN`, `GITHUB_TOKEN`, or `ZIZMOR_GITHUB_TOKEN` to a token
with access to the target repository. Zizmor inherits these settings from the
environment. See [zizmor operating modes](https://docs.zizmor.sh/usage/#operating-modes)
for authentication details. `ZIZMOR_OFFLINE` prevents remote scans.

Scanner output is displayed directly. For this first rule, any reported finding
causes exit code `1`; scanner failures, missing executables, and timeouts produce
`2`; a scan with no supported inputs produces warning code `3`. A successful scan
without findings returns `0`. The scanner timeout is five minutes.

### Planned checks

| Area | What the tool should check |
| --- | --- |
| CI/CD practices | Required validation jobs, restricted job permissions, pinned external dependencies, safe handling of untrusted contributions, and appropriate use of secrets. |
| Repository configuration | Protected default branches, review requirements, required status checks, ownership rules, and a documented security reporting process. |
| Python dependencies | Detect Python projects and verify that CI includes dependency vulnerability checks covering the project's dependency manifests or lockfiles. |
| npm dependencies | Detect npm projects and verify that CI includes dependency vulnerability checks and uses lockfiles for reproducible dependency installation. |
| Docker | Detect Dockerfiles and container build jobs; check for Dockerfile security analysis and image vulnerability scanning, and review practices such as base image pinning and non-root execution. |
| GitHub Actions | Expand the existing [zizmor](https://docs.zizmor.sh/) integration with structured reports and configurable failure thresholds. |
| GitLab CI/CD | Review pipeline configuration, job token permissions, protected variables, and controls around privileged jobs and deployment environments. |

Checks should distinguish between a missing security job, a configured job whose
execution has not been verified, and a scan that actually ran and reported
findings. The presence of a workflow file alone does not demonstrate that a
repository passes its security checks.

GitHub and GitLab repository settings require API access and suitable permissions. Local analysis
should still work without credentials, but inaccessible settings must be reported
as **not evaluated**, with the reason, rather than as passing checks. Checks that
do not apply to a repository should be marked **not applicable**.

## CLI

The main entry point is:

```sh
nomadsecops static-analysis
```

By default, the target is the current working directory. Select another local
directory with `--path` (`-p`) or a remote Git repository with `--repo` (`-r`):

```sh
nomadsecops static-analysis --path /path/to/project
nomadsecops static-analysis --repo https://github.com/org/repo.git
nomadsecops static-analysis --repo git@gitlab.com:org/repo.git
```

`--path` must identify an existing, readable directory. Relative paths are resolved
against the current working directory. `--path` and `--repo` are mutually exclusive;
passing both produces usage error code `2`.

The command identifies the hosting service and runs applicable checks. GitHub
repository URLs must identify an owner and repository, rather than a web page for
a branch or individual file. Remote reachability and authentication are checked
by zizmor when it fetches the target.

### Results and exit codes

Each finding should include a stable check identifier, severity, affected file or
repository setting, supporting evidence, and a suggested fix. Reports should also
identify skipped checks, unavailable scanners, and incomplete API access.

The exit code contract is below. Severity thresholds and advisory findings below
a threshold are planned; the current zizmor rule treats every finding as blocking.

| Code | Meaning |
| --- | --- |
| `0` | Analysis completed with no findings or evaluation warnings. |
| `1` | Analysis completed and at least one finding met or exceeded the failure threshold. |
| `2` | Analysis could not complete the requested checks because of an execution, configuration, authentication, or required scanner error. |
| `3` | Analysis completed with advisory findings below the failure threshold, or warnings about optional checks that could not be evaluated. |

When multiple conditions apply, execution errors (`2`) take precedence over
blocking findings (`1`), followed by advisory warnings (`3`). Reports must retain
all findings regardless of the final exit code. With `--fail-on high`, for example,
medium-severity findings produce `3`, while high- or critical-severity findings
produce `1` if analysis completes.

Optional checks that cannot run should remain visible in the report. If a policy
requires a check, inability to evaluate it should prevent a successful result.

Exit codes alone do not create warning annotations on every CI platform. The
integration must map advisory code `3` to a visible, nonblocking warning, while
preserving failures for codes `1`, `2`, and unexpected nonzero codes.
