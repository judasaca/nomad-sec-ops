# Nomad SecOps

Nomad SecOps is a security analysis CLI for GitHub and GitLab repositories in the
Nomad ecosystem.

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
```

With neither `--path` nor `--repo`, the command scans the current directory.
Use `--provider gitlab` for self-hosted GitLab or a local GitLab checkout without an
origin. For `--repo`, Nomad SecOps shallow-clones the default branch of a
supported repository into `.nomad-sec-ops-checkouts/` under the current working
directory. Git ignores this directory, and Nomad SecOps removes the checkout
after the scan. Private repositories use your Git HTTPS or SSH credentials.

Add `--demo` to preview the Python, npm, and Docker steps. To see which
zizmor rules have a registered GitLab equivalent, run:

```sh
uv run nomadsecops equivalence --details
```

Use `--json` for structured output.

### CI/CD settings

Nomad SecOps looks for an optional `nomad-sec-ops-ci-cd.yml` in the directory
being scanned, including a downloaded checkout. The settings use zizmor rule IDs
and accept a boolean `disable` field for each listed rule.

```yaml
rules:
  unpinned-images:
    disable: true
```

Omit the file or use `rules: {}` to leave all applicable rules enabled. If the
file is unreadable or invalid, the CI/CD step is reported as not evaluated with
a warning, and any other analysis steps continue.

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
- Remote checkouts use the tip of the default branch and skip submodules. Git
  checks out symbolic links as plain files containing their link text.
- The GitLab image-pinning check reads declarations from the local
  `.gitlab-ci.yml`. It does not resolve included files, YAML merge keys,
  `!reference` tags, or image references that depend on CI/CD variables.
- The CI/CD step validates the settings file before scanning. Applying rule
  overrides is a later step.
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
