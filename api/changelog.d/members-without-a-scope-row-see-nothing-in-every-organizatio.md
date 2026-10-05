### Security: members without a scope row see nothing, in every organization

- **The "see everything" mode is retired** (research doc 15 L-04, owner
  decision D2; owner signoff 2026-10-04). A member who is in no access group,
  holds no explicit grant and no `has_full_data_access` role sees no asset or
  finding anywhere (lists, search, stats, exports, dashboards, reports,
  notifications, WebSocket channels); by-id reads answer 404. Before, every
  organization created before migration 000247 showed such members the whole
  tenant, and a member who lost their last scope row silently widened to it.
  Owners, admins and full-data roles (for example a "Global Reader") are
  unchanged.
- `tenants.members_without_group_see` is no longer read; the per-tenant policy
  cache (which treated a read failure as "everything") is gone, and the asset,
  finding and finding-group SQL has no `NOT EXISTS … OR` bypass left.
- Real-time finding/asset pushes now also reach full-data roles, and no
  longer reach members without a scope row.
- **Migration 000910** stores `nothing` for every organization and adds a
  CHECK so `everything` can no longer be stored (its down migration relaxes
  the CHECK without flipping data back). The column is dropped in a later
  release.
- **Removed endpoints:** `GET`/`PATCH /api/v1/tenants/{tenant}/settings/data-scope`
  and `GET /api/v1/organization/settings/data-scope/impact` (404 now). The web
  console's "see everything" banner and the "Members without a team" settings
  card are gone; Settings → Teams states the rule.
