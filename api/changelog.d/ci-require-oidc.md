### Security: organizations can require OIDC for CI; on by default for new ones

- New setting **Require OIDC for CI** (`GET/PUT /api/v1/ci/settings`, `scans:ci:read` / `scans:ci:write`; console: top of Settings > Scanning > CI pipelines). When on, the key of a one-shot (CI) sensor is refused on every sensor route (protocol v2: `403` problem `ci-oidc-required`) and the refusal is audited (`ci_run.runner_key_refused`, at most once per sensor every ten minutes). CI jobs then authenticate only with their provider's OIDC token.
- Migration `001120` adds `tenants.ci_require_oidc`: existing organizations keep accepting CI sensor keys (`false`) and see a banner until they opt in; every organization created afterwards starts with it on.
- **Upgrade note:** after moving pipelines to OIDC, turn the setting on; a CI job that still sends a sensor key gets `403` once it is on.
