### Added: roles and teams lists carry member counts, pending approvals and a team access summary

- `GET /api/v1/roles` returns `members_count` (distinct holders, direct or through a team) and `pending_approvals` (pending finding approval requests the role's holders may decide) per role; `GET /api/v1/groups` returns an `access` summary (scope mode, presets, privileged, hand-bound roles) per team. Both are tenant-scoped, computed with grouped queries and add no request per row. No migration, no permission change.
- Docs: server/docs/architecture/console-api-screens.md
