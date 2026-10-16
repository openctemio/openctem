### Security: the daily limit of shared sensor scans is enforced

- `platform_scans_per_day` (a generic per-organization limit, read by key
  through the entitlement service) is now checked when a scan would go to
  shared (platform) sensors. Over the limit, an explicit shared-sensor scan
  is refused with the limit, and an `auto` scan or workflow stays on the
  organization's own sensors. An unreadable limit refuses (fail closed).
- Usage counts scans started since 00:00 UTC, one per run however many
  chunks it has.
- Upgrade note: no action. Organizations without a limit are unaffected, and
  shared sensors stay unavailable to every organization until RFC-100's gate
  is met.
