### Security: organization dashboards replace "View Organization Totals"

- The permission `dashboard:aggregate` ("View Organization Totals") is renamed
  `dashboards:org:view` ("View Organization Dashboards") for every holder: the
  built-in owner and admin roles, the program-lead role template (now version 2)
  and custom roles, and API key scopes (migration `002930_dashboard_ownership`).
  The legacy dashboard endpoints keep their behaviour under the new name.
- Organization dashboards show organization-wide numbers and the names in
  their lists, so the permission now counts like full data access: a role that
  holds it is privileged (second factor for members from outside the
  organization, team bindings owner-only).
- The migration writes one `role.permission_migrated` audit row per custom
  role, listing its members, and sends every active owner and administrator of
  an organization where members hold it through a custom role one notice naming
  them. **Upgrade note:** review the roles named in that notice.

### Added: organization and personal dashboards

- Dashboards come in two kinds. Organization dashboards belong to the
  organization (`/api/v1/organization/dashboards`): `dashboards:org:view` to
  read, optionally narrowed per dashboard to roles or teams; the new
  `dashboards:org:manage` (owner and admin) to create, edit, order, delete,
  set the default, the audience and the refresh schedule, every change audited.
  Personal dashboards (`/api/v1/me/dashboards`) stay the owner's own.
- "Duplicate to mine" copies an organization dashboard's layout into a personal
  one; sharing a personal dashboard sends a layout copy to members of the same
  organization. No data or access travels with a copy.
- Every dashboard stores a refresh schedule (manual, 5 min, 15 min, 1 h, 6 h,
  daily, or the organization default set under `/api/v1/organization/settings/dashboards`),
  refused below the organization's refresh floor: the new limit
  `dashboard_refresh_floor_minutes`, 5 minutes when unset. The refresher itself
  is not built yet.
- Limits: at most 30 personal dashboards per person, 50 organization
  dashboards, 40 widgets per dashboard and 4 KB of config per widget.
