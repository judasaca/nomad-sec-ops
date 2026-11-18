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
| GitHub.com | GitHub Actions audits via zizmor on a local checkout or remote repository. Remote scans fetch repository content through the GitHub API. |
| GitLab.com and self-hosted GitLab | The offline `unpinned-images` check reads `.gitlab-ci.yml` in a local checkout. Included files are outside the current scan scope. |

Both scanners currently run offline audits. Local scans require no credentials.
Remote GitLab targets and unsupported hosts are reported as not evaluated.

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
origin. For remote GitHub scans, set `GH_TOKEN`, `GITHUB_TOKEN`, or
`ZIZMOR_GITHUB_TOKEN` to a token with access to the repository.

Add `--demo` to preview simulated Python, npm, and Docker steps. To see which
zizmor rules have a registered GitLab equivalent, run:

```sh
uv run nomadsecops equivalence --details
```

The coverage report covers offline rules. Use `--json` for structured output.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Completed with no findings or evaluation warnings. |
| `1` | Security findings reported. |
| `2` | Execution or usage error. |
| `3` | A check could not be fully evaluated. |

When outcomes are combined, precedence is `2`, then `1`, then `3`, then `0`.

## Planned features

- Broader GitHub Actions and GitLab CI checks for job permissions, secrets,
  and required security jobs.
- API-based checks for repository settings such as branch protection, review
  requirements, and required status checks.
- Python and npm dependency checks using project manifests and lockfiles.
- Dockerfile and image checks for build practices and known vulnerabilities.
- Shared policy configuration, configurable failure thresholds, and exported reports.
