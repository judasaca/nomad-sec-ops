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

The scan logs the checkout's branch and short HEAD commit before the checks
start. Local scans read the working tree, including any uncommitted changes.
By default, each finding shows the file, line number, short message, and link
to the upstream rule documentation. Both output modes group findings from high
to informational severity and show the total and per-severity counts. Terminals
display severity headings and counts in color. Use `--verbose` or `-v` to see
details such as evidence and suggested fixes.

Add `--demo` to preview the Python, npm, and Docker steps. To see which
zizmor rules have a registered GitLab equivalent, run:

```sh
uv run nomadsecops equivalence --details
```

Use `--json` for structured output.

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

### CI/CD settings

Nomad SecOps looks for an optional `nomad-sec-ops-ci-cd.yml` in the directory
being scanned, including a downloaded checkout. The settings use zizmor rule IDs
and accept a boolean `disable` field for each listed rule.

```yaml
rules:
  unpinned-images:
    disable: true
```

For GitHub Actions, `disable: true` skips the named zizmor audit. Omit the file or
use `rules: {}` to leave all applicable audits enabled. Nomad SecOps passes the
validated file directly to zizmor. Use YAML syntax compatible with zizmor. The
scan ignores repository `zizmor.yml` files, `ZIZMOR_CONFIG`, and inline zizmor
ignore comments.

If the file is unreadable or invalid, the CI/CD step is reported as not evaluated
with a warning, and any other analysis steps continue.

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
- GitLab CI validates the settings file. Rule overrides currently apply to
  GitHub Actions.
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
