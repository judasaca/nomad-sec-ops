# Nomad SecOps

Nomad SecOps is a Python library and command-line tool for security analysis of
GitHub and GitLab repositories in the Nomad ecosystem.

## Objectives

- Apply a shared security baseline across projects, with documented exceptions.
- Detect the technologies a repository uses and run the relevant checks locally
  and in CI.
- Give maintainers actionable findings with evidence and suggested fixes.

## Current scope

| Target | Available checks |
| --- | --- |
| GitHub.com | GitHub Actions audits via zizmor on a local checkout. |
| GitLab.com and self-hosted GitLab | The offline `unpinned-images` check reads `.gitlab-ci.yml` in a local checkout. |

Local scans require no credentials.

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

**Default finding format**

```text
<file>:<line>: [<rule-id>] <message>  <rule-documentation-url>
```

**Example GitLab CI scan output**

```text
Local path: /path/to/project
Branch: main
Commit: 7ce3ede
Running [ci-cd]...
[ci-cd] findings
[ci-cd] GitLab CI/CD: 1 rule(s) completed (findings).

High severity
.gitlab-ci.yml:2: [unpinned-images] container image is unpinned  https://docs.zizmor.sh/audits/#unpinned-images
Total findings: 1 (High: 1, Medium: 0, Low: 0, Informational: 0)
```

Use `--verbose` or `-v` to see evidence and suggested fixes.

Add `--demo` to preview the Python, npm, and Docker steps. To see which
zizmor rules have a registered GitLab equivalent, run:

```sh
uv run nomadsecops equivalence --details
```

Use `--json` for structured output.

### GitHub Actions

Save this caller as `.github/workflows/nomad-sec-ops.yml` in the repository
you want to scan. It runs the shared workflow from `develop` when a pull request
opens or updates and on pushes to `develop` and `main`, including merges into
either branch. Adjust the push filter to match your project's branch names. Use
a full commit SHA in the `uses` ref to pin the shared workflow.

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
from the latest commit on `develop`, and writes findings to the job log. It
refreshes the package on each run. The runner needs Git read access to the Nomad
SecOps repository to install the package.

Nomad SecOps accepts the branch reference for this shared workflow by default.
Other workflow and action references still follow zizmor's SHA pinning policy.

The job fails on any nonzero [exit code](#exit-codes), including when the scan
reports findings or cannot fully evaluate a check. To configure the audit rules,
add `nomad-sec-ops.yml` at the root of the repository being scanned.

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
`report.repository` records the resolved provider and the available branch and
abbreviated commit. Remote checkouts use the system temporary directory and are
removed when the call ends.

Invalid arguments raise `ValueError`. Target preparation failures raise
`nomad_sec_ops.AnalysisError`. Findings and scanner failures are represented by
per-step statuses in the returned `AnalysisReport`. The computed
`report.exit_code` follows the CLI's exit code rules and is available on the
Python model.

### Repository configuration

Nomad SecOps ships the defaults from [`nomad-sec-ops.yml`](nomad-sec-ops.yml).
For GitHub Actions scans, place an optional file with the same name at the root
of the scanned checkout to override individual settings.

```yaml
ci-cd:
  rules:
    unpinned-images:
      disable: true
    unpinned-uses:
      policies:
        "judasaca/nomad-sec-ops/.github/workflows/security-scan.yml": ref-pin
```

Use zizmor rule IDs under `ci-cd.rules`. Set `disable: true` to skip a rule or
`disable: false` to enable it. For `unpinned-uses`, each entry in `policies`
sets the requirement for a repository pattern. The accepted values are
`hash-pin`, `ref-pin`, and `any`. The shared workflow uses `ref-pin` by default,
which accepts a branch, tag, or commit SHA. See the
[zizmor repository pattern syntax](https://docs.zizmor.sh/configuration/#repository-patterns).

Omitted rules, fields, and policy entries inherit their shipped defaults. An
empty mapping also inherits the corresponding defaults.

An unreadable configuration file or invalid settings schema marks CI/CD as not
evaluated and allows other analysis steps to continue.

The GitHub scan ignores repository `zizmor.yml` files, `ZIZMOR_CONFIG`, and
inline zizmor ignore comments.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Completed with no findings or evaluation warnings. |
| `1` | Security findings reported. |
| `2` | Execution or usage error. |
| `3` | A check could not be fully evaluated. |

When outcomes are combined, precedence is `2`, then `1`, then `3`, then `0`.

## Known limitations

- Both scanners run offline audits only. The equivalence report covers offline
  zizmor rules.
- Remote scans support GitHub.com, GitLab.com, and self-hosted GitLab with
  `--provider gitlab`. Unsupported hosts are reported as not evaluated.
- Remote checkouts skip submodules. Git checks out symbolic links as plain files
  containing their link text.
- The GitLab image-pinning check reads declarations from the local
  `.gitlab-ci.yml`. It does not resolve included files, YAML merge keys,
  `!reference` tags, or image references that depend on CI/CD variables.
- PyYAML silently keeps the last value for a duplicate key, so earlier values are
  discarded before validation. Duplicate-key detection could be added through an
  upstream fix or a separate verification step.
  [PyYAML issue #701](https://github.com/yaml/pyyaml/issues/701)
- The Python, npm, and Docker steps in `--demo` simulate work.

## Planned features

- Broader GitHub Actions and GitLab CI checks for job permissions, secrets,
  and required security jobs.
- API-based checks for repository settings such as branch protection, review
  requirements, and required status checks.
- Python and npm dependency checks using project manifests and lockfiles.
- Dockerfile and image checks for build practices and known vulnerabilities.
- Shared policy configuration, configurable failure thresholds, and exported reports.
