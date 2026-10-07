### Added: CI trust for Azure Pipelines, Bitbucket Pipelines, CircleCI and Jenkins

- CI jobs on Azure Pipelines, Bitbucket Pipelines, CircleCI and Jenkins (OpenID Connect provider plugin) exchange their OIDC token for a run token, like GitHub Actions and GitLab CI. Each trust names one CI organization, workspace or controller; there is no wildcard issuer.
- Per provider: Azure tokens must carry the issuer's `org_id`; Bitbucket trust pins the workspace UUID and lists repositories by UUID, and a reported repository name stays bound to the first repository UUID that used it; CircleCI SSH re-runs are refused; pull request builds on Azure, CircleCI and Jenkins are refused unless fork pull requests are admitted (their tokens cannot tell a fork's). Bitbucket, CircleCI and Jenkins audiences must contain the organization id.
- Tokens without a `jti` (Bitbucket, CircleCI, Jenkins) are accepted once by the token's hash.
- A commit the token does not sign (CircleCI, Jenkins without a `sha` claim) is the job's report: the run marks it unverified (`ci_runs.commit_verified`, migration `001240`) and a break-glass never applies to it.
- `POST /api/v1/ci/trust-configs/preview` (`scans:ci:write`, rate limited): verifies a sample token against a draft trust and shows its claims and whether the rules admit it; nothing is stored.
