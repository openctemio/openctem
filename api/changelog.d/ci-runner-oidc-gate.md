### Added: CI pipelines authenticate with their OIDC token and ask a central gate (RFC-051)

- `POST /api/v1/ci/oidc/exchange`: a GitHub Actions or GitLab CI job exchanges its OIDC token, checked against the organization's CI trust configurations, for a run upload token that expires within 15 minutes and is bound to one run on one repository asset. Fork pull requests get none by default; each OIDC token is exchanged once; every exchange is audited.
- `POST /api/v1/ci/runs/{id}/results` and `/evaluate`: upload results for the run's repository only, then get pass or fail with reasons and links from the gate policy (repository, business unit, organization, default): new findings only against the default branch, accepted risk honored, committed secrets always fail. Audited break-glass per commit.
- CI runs are not sensors: the console lists them under CI runners; trust, gate policy and break-glass are under Settings > Scanning > CI pipelines.
- Permissions `scans:ci:read` (all system roles), `scans:ci:write` and `scans:ci:override` (owner and admin only; refused on custom roles). Migration `001053`.

### Deprecated: sensor API keys for CI runners

- A `runner`-type sensor authenticating with an API key keeps working, and every response now carries `Deprecation` and a `Link` to the OIDC exchange.
