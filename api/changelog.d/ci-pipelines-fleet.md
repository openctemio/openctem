### Added: CI pipelines in the fleet

- Each workflow file of each repository that runs with CI OIDC is now a CI pipeline (migration `001063`), keyed by the provider's immutable repository id and the workflow path from the verified token, so renames and branches never add rows. Pipelines are created only at an admitted exchange, capped per organization (2,000) and per trust configuration (1,000), and audited (`ci_pipeline.created`).
- A pipeline's status is fresh, stale (two missed scheduled cycles, or three times its usual interval, 7 to 30 days), archived (90 days idle), failing (last default-branch verdict), degraded (scanner errors, runner below `SENSOR_MIN_VERSION`) or revoked; never offline. Fork runs attach to the upstream pipeline and never change its status.
- New read endpoints: `GET /api/v1/fleet?mode=all|daemon|runner` (sensors and CI pipelines in one list, each mode under its own permission), `GET /api/v1/ci/pipelines`, `GET /api/v1/ci/pipelines/{id}`, and `pipeline_id` on `GET /api/v1/ci/runs`.
- Existing runs are backfilled into pipelines; the first verified run of each adopts it.

### Security: withdrawn CI trust takes effect at once

- Disabling or deleting a CI trust configuration, or changing its issuer or audience, revokes its pipelines and invalidates the upload tokens of its runs still running (audited, `ci_pipeline.revoked`). Before, those tokens kept working until they expired.
- A CI token without a numeric repository or project id, or without a usable workflow path, is refused. GitLab's `user_email` claim is never read or stored.
