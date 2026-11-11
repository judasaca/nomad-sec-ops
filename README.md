# Nomad SecOps

Nomad SecOps is a planned security analysis CLI for auditing GitHub and GitLab
repositories in the Nomad ecosystem. It aims to help maintainers identify insecure
repository settings, improve CI/CD practices, and apply consistent security checks
across projects.

The tool should detect the technologies a repository uses, select the relevant
checks, and produce actionable findings. Maintainers should be able to run the same
analysis locally and in CI/CD pipelines.

> **Status:** The development setup, CLI help/version options, and target selection
> are available. Security analysis, configuration, and integrations described below
> are planned features. Target selection does not clone repositories or run checks.

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

## Planned checks

| Area | What the tool should check |
| --- | --- |
| CI/CD practices | Required validation jobs, restricted job permissions, pinned external dependencies, safe handling of untrusted contributions, and appropriate use of secrets. |
| Repository configuration | Protected default branches, review requirements, required status checks, ownership rules, and a documented security reporting process. |
| Python dependencies | Detect Python projects and verify that CI includes dependency vulnerability checks covering the project's dependency manifests or lockfiles. |
| npm dependencies | Detect npm projects and verify that CI includes dependency vulnerability checks and uses lockfiles for reproducible dependency installation. |
| Docker | Detect Dockerfiles and container build jobs; check for Dockerfile security analysis and image vulnerability scanning, and review practices such as base image pinning and non-root execution. |
| GitHub Actions | Integrate [zizmor](https://docs.zizmor.sh/) to audit workflow security using its [audit rules](https://docs.zizmor.sh/audits/). |
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

Currently, this command prints the selected target and a notice that security
analysis is not implemented. Remote URLs are accepted as target strings; their
syntax, reachability, and authentication are not verified yet. The planned analysis
will detect applicable technologies and print findings with remediation guidance.

### Results and exit codes

Each finding should include a stable check identifier, severity, affected file or
repository setting, supporting evidence, and a suggested fix. Reports should also
identify skipped checks, unavailable scanners, and incomplete API access.

The proposed exit code contract is:

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
