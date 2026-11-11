# Nomad SecOps

Nomad SecOps is a security analysis CLI for auditing GitHub and GitLab
repositories in the Nomad ecosystem. It aims to help maintainers identify insecure
repository settings, improve CI/CD practices, and apply consistent security checks
across projects.

The tool should detect the technologies a repository uses, select the relevant
checks, and produce actionable findings. Maintainers should be able to run the same
analysis locally and in CI/CD pipelines.

> **Status:** Repository analysis currently has one step: CI/CD security analysis.
> That step uses zizmor for GitHub and an offline `unpinned-images` rule for GitLab.
> Other analysis steps, shared configuration, and exported reports remain planned
> features.

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
| Pydantic | Structured check results, step results, and repository reports. |
| Ruff | Linting, import sorting, and formatting. |
| pytest | Unit and CLI tests. |
| ty | Static type checking. |
| zizmor | Security analysis of GitHub Actions and related configuration. |
| PyYAML | Read local GitLab CI/CD configuration with source locations. |

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

### Analysis structure

Repository analysis runs independent steps and collects their results. Each step
owns its applicability and implementation; the CLI selects the target and renders
the combined report.

```text
CLI
  -> repository analysis
       -> CI/CD analysis step
            -> GitHub: zizmor adapter
            -> GitLab (including self-hosted): offline rules
       -> future steps, such as Docker image detection and analysis
```

The code follows this structure:

| Module | Responsibility |
| --- | --- |
| `repositories.py` | Resolve a shared repository target and hosting metadata. |
| `analysis.py` | Run analysis steps and collect their results. |
| `models.py` | Define step outcomes and the aggregate report and exit code. |
| `steps/ci_cd.py` | Select the CI/CD implementation for the repository host. |
| `scanners/zizmor.py` | Invoke zizmor and translate its output and status. |
| `scanners/gitlab/` | GitLab adapter, rule interface, and rule registry. |
| `cli.py` | Parse arguments and render results. |

To add an analysis step, implement `name` and `run(target) -> CheckResult`, then
include it in the default steps in `analyze_repository`. Docker detection and
scanning will be a separate step; they are not implemented yet. A skipped,
unevaluated, or failed CI/CD step does not prevent later steps from running.
All step results are retained. Aggregate exit codes follow the precedence
`2` (error), `1` (findings), `3` (not evaluated), then `0` (passed or skipped).

### Implemented: CI/CD analysis

- Local GitHub targets: read the Git `origin` URL to identify the host, then run zizmor
  against the selected directory. Git must be installed. Host detection also works
  when the selected directory is inside a repository.
- Remote GitHub targets: convert HTTPS or SSH URLs to zizmor's `owner/repo` input.
  Zizmor fetches the remote content; Nomad SecOps does not clone the repository.
- Local GitLab targets: inspect `.gitlab-ci.yml` in the selected directory using
  the offline `unpinned-images` rule. Findings return `1`; unavailable inputs or
  incomplete coverage without findings return `3`.
- Remote GitLab targets: report not evaluated (`3`); offline rules require a
  local checkout and do not fetch remote content.
- Self-hosted GitLab: select `--provider gitlab` with a local checkout or remote URL.
  Hostnames are not guessed; `gitlab.com` is detected automatically. An explicit
  provider also allows local analysis without an origin.
- Directories without a Git origin or an explicit provider, and unrecognized hosts:
  report the CI/CD step as not evaluated (`3`). Self-hosted GitHub is unsupported.

Zizmor is installed by `uv sync`. Local scans work without credentials, using
zizmor's offline mode; audits that need API access are unavailable in that mode.
For remote scans, set `GH_TOKEN`, `GITHUB_TOKEN`, or `ZIZMOR_GITHUB_TOKEN` to a token
with access to the target repository. Zizmor inherits these settings from the
environment. See [zizmor operating modes](https://docs.zizmor.sh/usage/#operating-modes)
for authentication details. `ZIZMOR_OFFLINE` prevents remote scans.

Scanner output is displayed under its step. Any reported finding gives the CI/CD
step outcome `findings` (`1`); scanner failures, missing executables, and timeouts produce
`2`; a scan with no supported inputs produces warning code `3`. A successful scan
without findings returns `0`. The scanner timeout is five minutes.

### Extending the GitLab adapter

The adapter implements GitLab equivalents of applicable zizmor checks.
GitHub-specific checks need explicit GitLab semantics before implementation.

Implement `GitLabRule` in `scanners/gitlab/` with a stable `name` and
`run(context: GitLabContext) -> CheckResult`, then register the instance in
`DEFAULT_RULES`. Use the corresponding zizmor identifier where semantics align.
The context carries the full `RepositoryTarget`, including the host, project path,
and optional local checkout. Rule results follow the shared status and exit code
precedence; structured findings, evidence, and diagnostics are retained in adapter output.
Tests can inject a rule sequence through `run_gitlab(target, rules=...)`.

Include resolution, remote retrieval, and self-hosted API authentication remain
unimplemented. Rules must report unavailable inputs as not evaluated rather than
passing.

```sh
nomadsecops static-analysis --path /path/to/checkout --provider gitlab
nomadsecops static-analysis --repo https://code.example.org/group/project.git --provider gitlab
```

### GitLab rule: `unpinned-images`

The rule ID is exactly **`unpinned-images`**, matching
[zizmor's audit](https://docs.zizmor.sh/audits/#unpinned-images). The reference
implementation is pinned to **zizmor v1.32.0**, commit
`21bd300700d43d9ba04b0c1fce72a89391ac80b4`:
[upstream source](https://github.com/zizmorcore/zizmor/blob/21bd300700d43d9ba04b0c1fce72a89391ac80b4/crates/zizmor/src/audit/unpinned_images.rs).
`UnpinnedImages.upstream` exposes this identity. Every structured finding includes
the same metadata in `upstream`, plus its `rule_id`, severity, confidence, persona,
file, line, column, YAML location, image reference, and suggested fix.

| Image reference | Default (regular) persona | Pedantic persona |
| --- | --- | --- |
| No tag, or `:latest` | High severity, high confidence | Same |
| Other explicit tag | Suppressed | High severity, high confidence |
| Digest suffix (`@...`) | No finding | No finding |
| Dynamic reference (`$IMAGE`, `${IMAGE}`, `$[[ inputs.image ]]`) | High severity, low confidence | Same |
| Empty string | No finding | No finding |

The lexical classification, severity, confidence, and persona follow upstream.
As in the reference implementation, a digest suffix is accepted without checking
its algorithm, length, contents, or registry existence. This is a pinning audit,
not an image reference validator. Registry ports are distinguished from tags.
The CLI uses the regular persona. Python callers can select pedantic behavior
with `run_gitlab(target, rules=[UnpinnedImages(persona="pedantic")])`.

GitHub job containers map to GitLab `image`; GitHub service containers map to
GitLab `services`. The rule scans both string and `name` forms in top-level
defaults, `default:`, jobs, and hidden templates. It inspects declarations once
per location rather than expanding inheritance into every job. YAML aliases are
supported; their source position points to the anchor definition.

GitLab variables and input expressions are opaque, analogous to upstream's
non-matrix expressions. Variable expansion, matrix expansion, `extends`
resolution, YAML merge keys, `!reference`, includes (including local includes),
custom CI configuration paths, and runner-provided defaults are outside this
first rule's scope. Encountered includes, merge keys, and image/service
`!reference` nodes produce visible not-evaluated diagnostics. Findings still
take exit-code precedence over those diagnostics. No API or registry is queried.
Malformed relevant YAML produces an execution error (`2`).

`tests/test_unpinned_images.py` runs the installed, locked zizmor executable with
`--offline`, comparing equivalent GitHub/GitLab inputs in both personas. The test
checks the upstream version, identifier, annotation, severity, confidence, and
persona; upgrading zizmor requires reviewing the versioned mapping.

```sh
uv run pytest tests/test_unpinned_images.py
nomadsecops static-analysis --path /home/judasaca/Documents/nomad-distro-dev/packages/nomad-gui --provider gitlab
```

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

Report the percentage of zizmor rules with a registered GitLab equivalent:

```sh
uv run nomadsecops equivalence
uv run nomadsecops equivalence --all --details
uv run nomadsecops equivalence --json
```

Compares registered GitLab equivalents against zizmor v1.32.0: offline rules by
default, or all rules with `--all`. Use `--details` to list rule status and `--json`
for structured output. The percentage measures mapped rule coverage, not full
behavioral equivalence; no scans or network requests are performed.

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
a threshold are planned; the current CI/CD step treats every finding as blocking.

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
