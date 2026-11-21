### Added: preview what "Make default" would do to open findings

- `GET /api/v1/sla-policies/{id}/default-preview` (`settings:sla:write`, read-only) returns `governed`, `earlier`, `become_overdue` and `later` counts for the open findings the default governs, so the console can show the effect before the switch. Tenant-scoped, one aggregate query; nothing is written. No migration.
- Docs: server/docs/architecture/sla-escalation.md, server/docs/architecture/console-api-screens.md
