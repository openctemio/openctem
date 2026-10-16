### Behaviour change: platform administrators act as read-only until they elevate

- With `ADMIN_ELEVATION=required` (the default), a console session acts as read-only. To change anything, the administrator elevates the session (`POST /api/v1/admin/auth/elevate`: a role no higher than their own, 15 to 60 minutes, a reason, and a fresh authenticator code); the elevation is audited at high severity and ends on request or when the time is up. The console shows a bar to elevate or end. Another session of the same administrator stays read-only.
- `GET /api/v1/admin/auth/validate` now returns `role` (what the session acts as), `max_role` and `elevated_until`.
- Migration 002740 adds `admin_sessions.elevated_role`, `elevated_until`, `elevation_reason` (nullable, no backfill).
- **Upgrade note:** administrators press Elevate before making changes. `ADMIN_ELEVATION=off` keeps the old behaviour (each administrator acts as their own role from sign-in).
