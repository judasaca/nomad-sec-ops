# CI/CD security policy

The `ci-cd` step checks pipeline definitions for risks such as excessive job
permissions, unsafe use of workflow inputs, and mutable dependencies. Both
providers scan pipeline files offline against the checkout. A separate step is
planned for controls managed by the repository host.
[Repository settings policy](repository-settings.md)

## GitHub Actions

Nomad SecOps always runs zizmor in offline mode for GitHub Actions. For the
full rule list and details, see the [zizmor audit documentation](https://docs.zizmor.sh/audits/).

The shipped defaults enable `unpinned-uses`. It requires a full commit SHA for
repository actions and reusable workflows by default. A `ref-pin` exception
lets callers follow the shared Nomad SecOps workflow on `@develop`, so changes
to the workflow reach all calling repositories on their next run.
[Shared workflow setup](../README.md#github-actions) · [Shipped defaults](../nomad-sec-ops.yml) · [zizmor action pinning policy](https://docs.zizmor.sh/audits/#unpinned-uses)

Nomad SecOps preserves the severity assigned by zizmor for each finding
(informational, low, medium, or high).

## GitLab CI

The goal is a one-to-one GitLab counterpart for each zizmor rule, with 100% mapped
coverage of the offline rule inventory as the target for the current scanner.
GitHub-specific rules remain in that inventory. The coverage percentage counts
registered counterparts. Each counterpart can still have limits on what it
evaluates.

The current implementation covers `unpinned-images` on GitLab.com and
self-hosted GitLab. It reads image and service declarations from the local
`.gitlab-ci.yml` at the top level, under `default`, and in jobs. It reports
untagged images and `latest` as high severity. References containing variables
are reported as potentially unpinned with low confidence. Explicit version tags
are accepted in normal scans. Pinning by digest, such as `image@sha256:<digest>`,
keeps the referenced image fixed.
[Upstream image-pinning rule](https://docs.zizmor.sh/audits/#unpinned-images)

The scan inspects local declarations. Includes, YAML merge keys, `!reference`
tags, and variable expansion are outside its scope. If the file is missing, or
an unresolved construct such as an include limits the scan and there are no
findings, the step reports `not_evaluated`.

Run `equivalence --details` to list the mapped and missing rule IDs. Add `--json`
for structured output.

```sh
uv run nomadsecops equivalence --details
```

## Reading findings

The CLI groups findings from all steps by severity. CI/CD findings show the
rule ID, file location, and documentation link in the default view. Use
`--verbose` for evidence and suggested fixes.

## Configuration

GitHub Actions rule settings apply within the offline scan. Put overrides under
`ci-cd.rules` in the scanned repository's root `nomad-sec-ops.yml`. Use zizmor
rule IDs. Set `disable: true` to skip a rule or `disable: false` to enable an
offline rule. GitLab currently uses its registered rules directly.

### Allow a branch or tag for a trusted reusable workflow

Add a `ref-pin` policy for the exact workflow path. Other action and workflow
references keep their existing pinning requirements.

```yaml
ci-cd:
  rules:
    unpinned-uses:
      policies:
        "example-org/automation/.github/workflows/test.yml": ref-pin
```

### Require a commit SHA for a specific workflow

Use `hash-pin` on an exact workflow path to require a commit SHA even when a
broader pattern allows branches and tags.

```yaml
ci-cd:
  rules:
    unpinned-uses:
      policies:
        "example-org/*": ref-pin
        "example-org/automation/.github/workflows/release.yml": hash-pin
```

### Disable a rule for a project

Set `disable: true` if the project has a documented exception to the
`unpinned-images` audit. This applies to the entire GitHub Actions scan for the
repository.

```yaml
ci-cd:
  rules:
    unpinned-images:
      disable: true
```

Only `unpinned-uses` supports `policies`. Each entry matches a repository or
workflow pattern. The available values are `hash-pin` for a full commit SHA,
`ref-pin` for a branch, tag, or commit SHA, and `any` for no pinning requirement
from this rule. The most specific matching pattern wins.
[zizmor repository pattern syntax](https://docs.zizmor.sh/configuration/#repository-patterns)

Omitted rules, fields, and policy entries inherit their shipped defaults. An
empty mapping also inherits defaults. Keep each YAML key unique because the
configuration loader keeps only the last value of a duplicate key.

An unreadable file or invalid configuration marks the GitHub CI/CD step as
`not_evaluated`. Other analysis steps continue. The GitHub scan takes its rule
settings from `nomad-sec-ops.yml` and ignores repository `zizmor.yml` files,
`ZIZMOR_CONFIG`, and inline zizmor ignore comments.
