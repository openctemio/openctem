### Added: shared sensor enrollment with a single-use instance enrollment token

- A super administrator issues a single-use token in the console
  (`POST /api/v1/admin/shared-sensors/enrollment-tokens`: super admin, console
  step-up, a reason; valid 5 to 60 minutes; shown once, stored only as a keyed
  hash; console audit row). A sensor that starts pairing with it
  (`enrollment_token`) becomes a shared sensor: no organization, trust level
  trusted, the least-privilege grant. Redemption, approval and confirmation
  are audited in the console log. A malformed, unknown, expired or used token
  gets one `401`; no organization can look up, approve or deny such a request.
- `bootstrap-admin sensor-token` registers the token an install generated for
  its bundled sensor (`-from-env SENSOR_INSTANCE_ENROLLMENT_TOKEN`), or mints
  and prints one.
- A key-bound shared sensor now authenticates its signed requests (its key has
  no tenant and resolves only to a sensor of scope instance); it never gets a
  tenant context.
- Migration 002866 adds `instance_enrollment_tokens` and
  `sensor_pairings.instance_token_id`.
