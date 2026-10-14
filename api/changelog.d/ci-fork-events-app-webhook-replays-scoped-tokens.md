### Security: CI fork events never stand for the default branch; GitHub App webhook replays and token scope

- A CI run triggered by a fork event (`pull_request_target`, `workflow_run`,
  a GitLab external pull request) carries the base branch's ref and commit.
  It was counted as a default-branch run: its findings became default-branch
  exposure and its verdict was posted as the "OpenCTEM gate" check on the
  base commit. Such a run is now never a default-branch run, its findings go
  to a `fork/...` branch that does not count as exposure (branch-only until a
  real branch sees them), and no check goes on the base commit.
- The GitHub App webhook refuses a replayed delivery: after the signature
  check each `X-GitHub-Delivery` id is accepted once for 24 hours across
  replicas, and the webhook fails closed (503) when the store is down.
- Installation tokens used to post checks and comments are narrowed to the
  one repository and to `checks: write`, `pull_requests: write`,
  `metadata: read`, and cached per repository.
