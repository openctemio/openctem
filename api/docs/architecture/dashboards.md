# Dashboards: organization and personal

Design: [RFC-021](../rfcs/RFC-021-customizable-dashboards.md) (§11 is the ownership model).

Every dashboard is a name, a description, a column count and a widget layout
(at most 40 widgets, at most 4 KB of config per widget). There are two kinds,
stored in one table (`user_dashboards.kind`):

| | Organization | Personal |
|---|---|---|
| Owner | the organization (`user_id` NULL) | one user |
| Numbers | the whole organization | the owner's own data scope |
| Who sees it | holders of `dashboards:org:view`, optionally narrowed to an audience of roles or teams | its owner only |
| Who changes it | holders of `dashboards:org:manage` (owner and admin by default), audited | its owner |
| How many | up to 50, ordered, one may be the organization default | up to 30 per person, one may be the person's default |
| Sharing | the dashboard is the shared view | share = send a copy of the layout; the recipient gets a personal dashboard of their own |

## Shipped

- **Model and API.** Personal dashboards under `/api/v1/me/dashboards`
  (list, create, read, replace, delete, default, schedule, share; create with
  `from_organization_dashboard_id` is "duplicate to mine"). Organization
  dashboards under `/api/v1/organization/dashboards` (list, create, read,
  replace, delete, default, order, audience, schedule).
  Organization defaults under `/api/v1/organization/settings/dashboards`. Gates are listed in
  the [authorization matrix](authorization-matrix.md#dashboards-apiv1medashboards-apiv1organizationdashboards).
- **Permissions.** `dashboards:org:view` replaced `dashboard:aggregate`
  (migration `dashboard_ownership`): every role, template role and API key
  scope holding the old permission holds the new one. The migration writes one
  `role.permission_migrated` audit row per custom role (with its members) and
  one notice to every active owner and administrator of an organization where
  members gained it through a custom role, naming them. `dashboards:org:manage`
  is granted to owner and admin.
- **Full-data grade.** Organization dashboards show organization-wide numbers
  and the names in their lists, so `dashboards:org:view` counts like full data
  access (`permission.IsFullDataGrade`): a role holding it is privileged, an
  outside member holding it needs a second factor at sign-in, and binding such a
  role to a team is owner-only with a recent sign-in.
- **Audience.** `dashboard_audience (tenant_id, dashboard_id, principal_type
  role|group, principal_id)`. No rows: every `dashboards:org:view` holder sees
  the dashboard. With rows, a viewer must hold one of the roles (directly or
  through an active team, `v_user_role_grants`) or be in one of the active teams.
  An audience only narrows: its members still need `dashboards:org:view`.
  Outside the audience the dashboard is left out of the list and is 404 by id,
  so its existence does not leak. Managers see every organization dashboard and
  its audience. Roles and teams must belong to the organization (system roles
  allowed); a deleted role or team simply stops matching (fail closed).
- **Refresh schedule.** `refresh_schedule` is `manual`, `5m`, `15m`, `1h`,
  `6h`, `daily` (with `refresh_daily_minute`, UTC) or NULL for the organization
  default (`settings.dashboards.default_refresh_schedule`, 1h when unset).
  `next_refresh_at` and `paused_at` are kept for the refresher. A schedule is
  refused when it is shorter than the organization's **refresh floor**: the
  limit `dashboard_refresh_floor_minutes` ([limits](limits.md)) when it is set
  and longer than 5 minutes, else 5 minutes. The hosting plan (control plane) or
  the operator (Console > organization limits, or the self-service defaults)
  sets the floor; a floor that cannot be read refuses the change. Managers set
  organization schedules (audited); owners set their personal ones.
- **Copies.** "Duplicate to mine" and "Share layout" copy the name,
  description, columns and widgets into a new personal dashboard (`origin`
  `duplicated` or `shared`, name suffixed " (2)" when taken). No data, schedule,
  audience or default travels with a copy, and the copy is computed for its new
  owner's scope. Sharing needs recipients who are active members of the same
  organization (at most 10 per call, skipped when they already have 30) and is
  audited.
- **Audit.** `dashboard.org_created`, `org_updated`, `org_deleted`,
  `org_default_set`, `org_reordered`, `audience_changed`, `schedule_changed`
  (organization dashboards), `dashboard.layout_shared`,
  `dashboard.settings_updated`. Plain views are not audited.

## Threat model

| Actor | Can | Cannot |
|---|---|---|
| Member without `dashboards:org:view` | their own personal dashboards | list, read or duplicate organization dashboards (403) |
| Org viewer outside an audience | the other organization dashboards | see that the dashboard exists (left out, 404) |
| Org viewer | read and duplicate visible organization dashboards | change any (403) |
| Org manager | every organization dashboard change, audited | read anyone's personal dashboard |
| Colleague / administrator | — | read or change another person's personal dashboard (404: personal queries filter on the owner) |
| Another tenant | — | anything: every query filters on the caller's tenant; an audience entry of another tenant is refused |
| Sharer | send a layout copy to members of the same organization | push data or access, or reach users outside the organization |

Numbers on organization dashboards are computed once for the organization by
the platform, never with a person's access, so nobody's access is borrowed when
a manager leaves.

## Planned

- Stored snapshots, the refresher, Refresh now and refresh after the user's own
  actions (dashboard work package 10). Until then a dashboard's widgets read the
  existing live endpoints, which follow the viewer.
- The grouped switcher (Organization / Mine), scope badge, freshness line and
  schedule picker on `/`, and the organization management section on
  `/dashboards` (work packages 11 and 12).
- Typed per-widget config schemas and the widget id migration, with the widget
  registry over the fact tables.

## Key files

- `pkg/domain/dashboard/` — model, kinds, schedule, audience, caps
- `internal/app/dashboard/service.go` — authorization, audit, copies, floor
- `internal/infra/postgres/user_dashboard_repository.go` — tenant- and owner-bound queries, audience SQL
- `internal/infra/http/handler/user_dashboard_handler.go`, `internal/infra/http/routes/dashboard.go`
- `migrations/*_dashboard_ownership.up.sql`
- Tests: `internal/infra/http/routes/dashboard_ownership_db_test.go`,
  `tests/integration/migration_dashboard_ownership_test.go`
