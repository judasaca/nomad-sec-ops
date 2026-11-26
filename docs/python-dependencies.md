# Python dependency security policy

Python plugins in the NOMAD ecosystem are expected to use uv and commit a
`uv.lock` file alongside `pyproject.toml` at the repository root. The lockfile
records the exact dependency versions the `python-dependencies` step audits
for known vulnerabilities.

## Project detection

| Repository layout | Scan behavior |
| --- | --- |
| Root `pyproject.toml` and `uv.lock` | Audits the versions in the lockfile. |
| Root `pyproject.toml` without a root `uv.lock` | Reports the missing lockfile as `not_evaluated`. |
| No root `pyproject.toml` | Skips the step, even if a subdirectory contains a Python project. |

Treat a missing `uv.lock` as a policy violation. The current scanner reports it
as an incomplete check (exit code `3` when no higher-priority outcome applies).
Generate the lockfile with `uv lock` at the project root and commit it. Root-only
project detection is an accepted limitation. Other package managers' lockfiles
are outside this check's scope.
[Exit codes](../README.md#exit-codes) · [uv locking documentation](https://docs.astral.sh/uv/concepts/projects/sync/)

## How the audit runs

Nomad SecOps runs `uv audit --frozen` against the existing lockfile. The scan
leaves the lockfile and project environment untouched and requires `uv` on
`PATH` and network access for vulnerability lookups. Keep the lockfile current
when dependency declarations change so the scan reflects the versions the
project intends to use. [uv audit command](https://docs.astral.sh/uv/reference/cli/#uv-audit)

The audit report includes the affected package and locked version, advisory ID
and link, and available fixed versions. Use `--verbose` to show fixed versions
in the CLI. When a fixed version is available, update the locked package with
`uv lock --upgrade-package <package>` and rerun the scan.
[uv lockfile upgrades](https://docs.astral.sh/uv/concepts/projects/sync/#upgrading-locked-package-versions)

Vulnerabilities and deprecations are findings. Either yields exit code `1`
unless an execution error takes precedence. Archived statuses are audit
metadata. The CLI includes uv findings in its total under
**Severity unavailable**.

## Configuration

The Python dependency step currently has no settings in `nomad-sec-ops.yml`.
It uses the same root-level detection and audit settings across repositories.
Nomad SecOps invokes uv with `--no-config`, so uv audit settings from files
such as `pyproject.toml` and `uv.toml` are ignored.

`uv audit` and its JSON output are preview features. New uv releases may change
the command or report format. The shared workflow pins uv `0.13.1`. For local
scans, use that version to match CI.
[uv preview features](https://docs.astral.sh/uv/concepts/preview/) · [Shared workflow](../.github/workflows/security-scan.yml)
