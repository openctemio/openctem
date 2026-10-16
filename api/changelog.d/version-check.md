### Added: version check for new and security releases

- The API reads a signed release feed once a day and the platform console tells platform administrators when a newer release exists or when the running release is affected by a published security advisory (RFC-105, `docs/architecture/version-check.md`).
- The request carries no instance id, no version and no counts: one anonymous download of a static file, compared on the instance. The feed is verified with a root key pinned in the build (Ed25519, the shared signed-feed format); rollback, expired and tampered feeds are refused.
- On by default; `VERSION_CHECK_ENABLED=false` stops the download, `VERSION_CHECK_URL` points at a mirror. Air-gapped instances fail silently, back off to weekly and can import the same file in the console (super administrator, step-up, audited).
- New console routes `GET /api/v1/admin/version-check/` (any administrator) and `POST /api/v1/admin/version-check/import` (super administrator + step-up). Migration `002600_version_check_state` (new table, instance-level).
- No usage telemetry is sent; its rules are recorded in RFC-105 as deferred and opt-in only.
- **Upgrade note:** nothing to do. The check stays inert until a release pins the release feed root.
