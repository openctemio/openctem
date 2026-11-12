### Behaviour change: Tenable.sc rotation waits at least a day, and purge joins the modes

- Aging is the recommended license rotation: a dedicated universal rotation repository with 1-day lifetimes as the coverage repository. `coverage_rotation_wait_hours` is now 24-72 (default 26, was 1-72 with 12), because Tenable.sc frees aged data only at its nightly cleanup. A stored value under 24 is refused, and the coverage panel says why coverage waits.
- New mode `purge` (Beta, unverified, behind the same acknowledgement): after the previous batch was ingested, the next batch asks the connector to remove that batch's addresses from its rotation repository (the previous command is read tenant-scoped). A purge the connector cannot confirm (`purge_unverified`) stalls rotation.
- Recycle stays opt-in and needs a Tenable.sc Administrator key on the connector; the connector dialog says so. A refusal before launch keeps the pending recycle or purge and does not stall rotation.
- An import Tenable.sc Blocked for the license (`IMPORT_BLOCKED`) no longer stalls rotation: its targets stay due, and the next batch imports that scan result again with the blocked batch's targets once the license guard sees capacity.
- Needs connector-tenable with the matching release (rotation_mode, purge, reimport_scan_result_id).
