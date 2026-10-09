### Added: scan window policies (when scans may touch which targets)

- Allow windows (scan the selected targets only inside them) and blackout windows (never inside them), selected by asset tags, asset groups, asset types, criticality, business units, scope entries, scan zones and bug-bounty programs; weekly slots and dated one-offs in an IANA time zone; all tools, active and intrusive, or intrusive only; a grace for running work; optional rate and concurrency caps. RFC-067, `docs/architecture/scan-windows.md`.
- `/api/v1/scan-window-policies` (read with `scans:read`, manage with the new `scans:windows:manage`), `POST /api/v1/scan-window-policies/preview`, `POST /api/v1/scan-windows/preview` (why a target or asset cannot be scanned now and when it can), `/api/v1/scan-window-overrides`.
- Bug-bounty program testing windows are evaluated with the policies; no override ever lifts them.
- Emergency override: suspends one or every policy for 15 minutes to 24 hours with a reason and a current authenticator code (`scans:windows:override`, owner and admin); audited and notified to every owner and administrator.
- Run tasks carry `window_hold` and runs `window_waits`; the zone routing and workflow previews carry `windows`.

### Behaviour change: scans outside their windows wait instead of being refused or skipped

- Jobs outside their windows are deferred at the claim to the next opening; a job of a run step with targets inside and outside is split, the open targets go now. Waiting no longer counts against the job's expiry or the run's deadline, and the unclaimed-run reaper leaves such runs alone.
- A manual run during a blackout starts and waits (formerly `409 SCAN_FREEZE_ACTIVE`). A scheduled run with nothing open is deferred to the next opening; a scheduled run outside a program's testing windows is no longer skipped.
- A target whose windows never open refuses the run with `409 SCAN_WINDOW_NEVER_OPENS`.
- When a window closes under a running job, it may continue for the policy's grace (default 15 minutes; program windows none), then it goes back to the queue for the next opening and its sensor is told to stop.
- Held jobs no longer fill the claim window: before, 100 jobs outside a program's testing window could keep every other job of the organization from being handed out.

### Removed: scan freeze windows

- `/api/v1/scan-freeze-windows`, the `override_freeze` trigger field, `commands.freeze_override`, `scan_runs.freeze_override` and `PROGRAM_OUTSIDE_WINDOW` are gone. Migration `001660` copies every freeze window into a blackout policy (active and intrusive tools, its zone as the selector); migration `001661` renames `scans:freeze:override` to `scans:windows:override` in every role and API key.
- **Upgrade note:** run the migrations; nothing else to do. Settings › Scan freeze windows becomes Settings › Scan windows. A run started with a freeze override before the upgrade loses the override and waits for the window.
