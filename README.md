# Nomad SecOps

Nomad SecOps checks GitHub and GitLab repositories against a shared security
baseline for the NOMAD plugin ecosystem. Run it locally or in CI.

## Security policies

- [CI/CD](docs/ci-cd.md) covers GitHub Actions and GitLab CI, including the
  rules currently enforced and the plan for GitLab coverage.
- [Python dependencies](docs/python-dependencies.md) covers the `uv.lock`
  requirement and vulnerability checks for locked versions.

## Scanner configuration

Use a single optional `nomad-sec-ops.yml` at the root of the repository being
scanned. The file overrides settings from the shipped defaults. See each
policy's configuration section for supported options and examples.
[Shipped defaults](nomad-sec-ops.yml) · [CI/CD configuration](docs/ci-cd.md#configuration) · [Python dependency configuration](docs/python-dependencies.md#configuration)

## Usage

Install uv, then run `uv sync --locked` from the Nomad SecOps checkout. The project
uses Python 3.14, which uv can install if needed. Local host detection uses Git.

```sh
uv run nomadsecops --help
uv run nomadsecops static-analysis
uv run nomadsecops static-analysis --path /path/to/project
uv run nomadsecops static-analysis --path /path/to/checkout --provider gitlab
uv run nomadsecops static-analysis --repo https://github.com/org/repo.git
uv run nomadsecops static-analysis --repo https://github.com/org/repo.git --branch ci-cd-security
```

With neither `--path` nor `--repo`, the command scans the current directory.
Use `--provider gitlab` for self-hosted GitLab or a local GitLab checkout without an
origin. For `--repo`, Nomad SecOps shallow-clones the default branch unless you
select a branch with `--branch`. The checkout goes into
`.nomad-sec-ops-checkouts/` under the current working directory. Git ignores
this directory, and Nomad SecOps removes the checkout after the scan. Private
repositories use your Git HTTPS or SSH credentials.

Local scans read the working tree, including any uncommitted changes.

Use `--verbose` or `-v` to see evidence and suggested fixes.
Use `--quiet` or `-q` to keep repository details, progress, step results, and
finding totals while hiding individual findings. If both flags are supplied,
`--quiet` takes precedence.

Add `--demo` to preview the npm and Docker steps.

### GitHub Actions

Save this caller as `.github/workflows/nomad-sec-ops.yml` in the repository
you want to scan. It runs the shared workflow from `develop` when a pull request
opens or updates and on pushes to `develop` and `main`, including merges into
either branch. Adjust the push filter to match your project's branch names.

Keep `@develop` in the `uses` reference so the organization can roll out
security workflow changes to all calling repositories on their next run.
A commit SHA freezes the workflow definition at that revision and requires
each repository to update its caller to receive workflow changes.

```yaml
name: Nomad SecOps

on:
  push:
    branches: [develop, main]
  pull_request:

permissions:
  contents: read

jobs:
  security-scan:
    uses: judasaca/nomad-sec-ops/.github/workflows/security-scan.yml@develop
```

The shared workflow checks out the calling repository, installs Nomad SecOps
from `develop`, and writes findings to the job log. The runner needs Git read
access to the Nomad SecOps repository. The job fails on any nonzero
[exit code](#exit-codes).

### Python API

Install into a project that uses Python 3.14 or newer and has Git on its PATH.
Install a wheel built with `uv build --wheel` from this repository, or add the
package as a Git dependency at a commit containing the API.

```sh
uv add /path/to/nomad-sec-ops/dist/nomad_sec_ops-0.1.0-py3-none-any.whl
# Or install from Git using the desired commit SHA.
uv add 'nomad-sec-ops @ git+https://github.com/judasaca/nomad-sec-ops.git@COMMIT_SHA'
```

```python
from nomad_sec_ops import static_analysis

report = static_analysis("/path/to/checkout", provider="gitlab")
# Remote example: static_analysis(repo="https://github.com/org/repo.git", branch="main")

for step in report.steps:
    for finding in step.result.findings:
        print(f"{finding.file}:{finding.line} {finding.rule_id} {finding.message}")

payload = report.model_dump(mode="json")
```

With neither `path` nor `repo`, the function scans the current directory.
The call is synchronous and silent. Findings from both providers use paths
relative to the scanned directory and one-based line and column numbers.
The Python step exposes its audit results in `step.result.dependency_audit`.
`report.repository` records the resolved provider and the available branch and
abbreviated commit. Remote checkouts use the system temporary directory and are
removed when the call ends.

Invalid arguments raise `ValueError`. Target preparation failures raise
`nomad_sec_ops.AnalysisError`. Findings and scanner failures are represented by
per-step statuses in the returned `AnalysisReport`. The computed
`report.exit_code` follows the CLI's exit code rules and is available on the
Python model.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Completed with no findings or evaluation warnings. |
| `1` | Security findings reported. |
| `2` | Execution or usage error. |
| `3` | A check could not be fully evaluated. |

When outcomes are combined, precedence is `2`, then `1`, then `3`, then `0`.

## Known limitations

- Remote scans support GitHub.com, GitLab.com, and self-hosted GitLab with
  `--provider gitlab`. Unsupported hosts are reported as not evaluated.
- Remote checkouts skip submodules. Git checks out symbolic links as plain files
  containing their link text.
- The npm and Docker steps in `--demo` simulate work.

## Planned features

- Broader GitHub Actions and GitLab CI checks for job permissions, secrets,
  and required security jobs.
- [Repository settings](docs/repository-settings.md) checks for branch
  protection, required reviews, and required status checks. The step currently
  reports `skipped`.
- npm dependency checks using project manifests and lockfiles.
- Dockerfile and image checks for build practices and known vulnerabilities.
- More shared policy settings, configurable failure thresholds, and exported reports.
