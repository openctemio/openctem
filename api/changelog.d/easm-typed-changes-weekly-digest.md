### Added: what changed on the attack surface, and a weekly digest

- `GET /api/v1/easm/changes` lists typed changes of the external attack
  surface: new and removed hosts, opened and closed ports, new and expiring
  certificates, DNS changes and dangling records, technology changes and new
  exposures, with counts per kind, narrowed to the caller's data scope
  (RFC-080).
- Attack surface › Changes shows them by kind and window (en, vi).
- Each organization gets a weekly digest of those changes (in-app for owners
  and administrators, and the `attack_surface_digest` notification event,
  added to every channel that already receives `new_exposure`). It is on by
  default, sent once per week on the chosen weekday at 08:00 UTC, silent for a
  week without changes, and switched off or moved on the monitoring card
  (`weekly_digest_enabled`, `digest_weekday` on `/api/v1/easm/settings`).
