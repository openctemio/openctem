### Behaviour change: asset owners and assignees see what they own or are assigned

- A user named `primary` or `secondary` owner of an asset by a person now has
  the asset, and its findings, in their data scope (lists, detail pages,
  dashboards, exports, MCP tools). Ownership adds no permission: the role
  still decides what the owner may do. Owners matched from `owner_ref` and
  stakeholder, informed or regulatory owners grant nothing. Removing or
  demoting the owner removes the view at once, unless a group or an explicit
  grant still gives it.
- Naming, re-typing (into or out of primary/secondary) or removing such an
  owner now needs `team:groups:write` on top of `assets:write` /
  `assets:delete`, refuses naming yourself (non-administrators), and is
  audited as `asset.access_granted` / `asset.access_revoked`.
- A member without full data access who creates an asset now sees it: an
  explicit access grant with source `creator` is added (audited). It used to
  answer 404 right after the 201.
- Assignees see their work: the assignee of a finding sees that finding (not
  its asset or other findings) in the findings list, stats, groups, export,
  detail and bulk actions; the assignee of a remediation campaign sees the
  campaign and the findings it tracks, but changing it still needs every
  finding in their own scope. Unassigning removes the view at once.
- Migration `002980` adds `v_asset_owner_scope`, recomputes scope on
  `asset_owners` changes and backfills the scope of existing primary and
  secondary owners set by a person.
- **Upgrade note:** after the migration, existing primary and secondary user
  owners (set by a person) see their assets. Review owners on the Owners tab
  if some should only be stakeholders.
