### Changed: intrusive (T2) scope entries may last longer, up to an owner-set limit

- An entry that allows intrusive (T2) probes was bound by the one-off limit (at most 30 days, 7 by default). It now has its own limit, set by an owner: 7, 30 (default), 90 or 365 days, or permanent. A T2 entry still needs a verified domain for its probes and an approval when it is added or widened.
- `PUT /api/v1/scope/settings/intrusive` (owner, re-authentication, reason; audited at high severity, every administrator told) changes it; `PUT /api/v1/scope/settings` keeps it. `GET /api/v1/scope/settings` adds `t2_max_duration`, `t2_max_days` and `t2_permanent_allowed`.
- The add and edit dialogs offer durations up to the limit, and "Permanent" for a T2 entry only when the owner allows it. Turning one-off entries off no longer blocks an expiring T2 entry.
- New refusal code `INTRUSIVE_TOO_LONG`. No migration.
