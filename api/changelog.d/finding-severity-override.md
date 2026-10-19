### Fixed: changing a finding's severity recomputes its priority, SLA deadline and reason

- A severity change now reclassifies the finding at once with the same classifier and SLA applier as ingest, and the answer carries the new priority, priority reason and SLA deadline (the finding detail updates "Priority", "SLA due" and "Why it matters" immediately).
- A re-scan no longer reverts an analyst's severity: the reported severity is kept as the source severity, and a change of it under an override adds a `severity_source_changed` review entry to the timeline.

### Added: analyst severity override with approval for downgrades

- `PATCH /api/v1/findings/{id}/severity` takes a required `reason` and `restore: true` to go back to the reported severity. Findings show `source_severity`, `severity_override` and `pending_severity_request`.
- A downgrade follows the organization's false-positive approval policy (level and tiers): when the caller may not decide alone it becomes a pending request, approved or rejected at `POST /api/v1/findings/{id}/severity-requests/{request_id}/{approve,reject}` (`findings:approve`) or withdrawn with `/cancel`. An allowed downgrade may extend the SLA deadline up to the new class's window from the first detection.
- Migrations `002960_finding_severity_override` (columns, `finding_severity_requests`, review trigger) and `002961_finding_severity_override_validate`; safe on populated tables (nullable columns, constraints added NOT VALID then validated).

### Behaviour change: severity changes need a reason

- API clients that change a finding's severity must send `reason`; a downgrade may answer 202 with a pending request instead of 200.
