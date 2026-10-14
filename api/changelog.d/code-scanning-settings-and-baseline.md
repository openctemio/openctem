### Added: code scanning settings, protected branches and the baseline of each branch

- CI/CD gains code scanning of repositories (RFC-091), with an organization template that repositories inherit and per-repository overrides. The settings are:
  - protected branches: the default branch and `develop` by default, names or `release/*` patterns, at most 20;
  - capabilities: SAST, secrets, SCA, IaC;
  - the full rescan schedule (weekly by default);
  - routing;
  - on or off.
- Each branch records its baseline: none, queued, running, done (with the commit and date) or failed, and the trigger of its last full scan.
- `POST /api/v1/ci/code-scanning/repositories/{id}/baseline` sets a new baseline: it queues a full scan of a repository's protected branches. The scans themselves run on sensors in a later change.
- API: `GET/PUT /api/v1/ci/code-scanning/settings`, `GET /api/v1/ci/code-scanning/repositories[/{id}]`, `PUT/DELETE /api/v1/ci/code-scanning/repositories/{id}/settings`. Reading needs `scans:ci:read`; changes need `scans:ci:write` and are audited. Repositories outside the caller's data scope answer 404 and are not listed.
- Migration `code_scan_settings`: a new table, and new columns on `repository_branches` with constant defaults (no table rewrite).
