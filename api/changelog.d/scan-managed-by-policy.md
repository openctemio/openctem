### Behaviour change: scans the platform manages are read-only

- Continuous coverage and automatic enrichment scans can no longer be edited, scheduled, paused, deleted, saved, run by hand or taken over through the scan API: every such call returns `409 SCAN_MANAGED_BY_POLICY`. Cloning is allowed; the copy is an ordinary scan you own.
- `GET /scans/{id}` reports `managed_by` and `owner_state: "managed"` for these scans, so a client no longer shows them as orphaned scans.

### Security: members can no longer reshape or hijack the platform's coverage scans

- Any member with `scans:write` could change the settings every coverage batch inherits (tags, profile, windows), pause a capability for good, or (administrators) take ownership so later coverage runs acted as them. All of these are now refused.
