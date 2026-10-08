### Added: the sign-up policy is a console setting (System > Sign-up)

- Who may create an organization (`admin_only` or `self_service`, plus whether
  people may request access) is now one platform setting, stored in the new
  `platform_settings` table (migration 001313) and edited on Console > System >
  Sign-up. create-first-team, `POST /tenants` and `GET /auth/providers` read
  it per request; a read failure means `admin_only`.
- Any administrator reads it. A super admin changes it with a fresh
  authenticator code and the version read (409 on a concurrent change). Every
  change writes a critical admin audit row (`platform.signup_policy_changed`)
  and emails the other administrators. Existing organizations, users and
  sessions are never affected by a change.
- **Upgrade note:** `TENANT_CREATION_MODE` now only seeds the setting on the
  first start after this upgrade. Change it in the console afterwards; editing
  the environment variable no longer has an effect once the row exists.
