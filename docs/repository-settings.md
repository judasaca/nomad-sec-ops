# Repository settings security policy

The `repository-settings` step is planned to check security controls configured
on GitHub and GitLab through their hosting APIs. These controls govern how
changes reach protected branches in NOMAD plugin repositories.

## Planned checks

- **Branch protection** restricts direct pushes to the default branch and other
  designated branches.
- **Required reviews** require approval before merging a pull request or merge
  request.
- **Required status checks** require designated CI jobs to pass before merging.

## Current behavior

The step appears as `skipped` in CLI and Python API reports. It runs as a local
placeholder and leaves the scan's exit code to the other steps.
