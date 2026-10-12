### Added: CI pull requests are compared with their base branch

- A pull request into a release branch is now judged against that branch
  instead of the default branch: the gate and `baseline-diff` use the base
  branch (GitHub's signed `base_ref` claim, else the new optional `base_ref`
  field of `POST /api/v1/ci/oidc/exchange`) when the repository has scanned it
  and it is a release line (default, protected, or of type main or release).
  Anything else falls back to the default branch, so a reported base branch can
  never make a feature branch the baseline. Runs record it in
  `ci_runs.base_ref` (migration `ci_runs_base_ref`).
