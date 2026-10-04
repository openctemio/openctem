# Asset ownership

**Status: SHIPPED.** Owner decision O2 (2026-10-03, assets area review §4).

An asset has owners: the people and groups accountable for it. There is one
owner model, the RACI table `asset_owners`. Every reader and writer of "who
owns this asset" uses it.

| Where | What |
|---|---|
| `migrations/000340_asset_owner_single_model.up.sql` | Folds the old `assets.owner_id` into `asset_owners` |
| `internal/infra/postgres/asset_owner_model.go` | The shared definitions (primary user owner, responsible owner) and the owner_ref sync |
| `internal/infra/http/handler/asset_owner_handler.go` | `GET/POST/PUT/DELETE /api/v1/assets/{id}/owners` |
| `internal/infra/controller/owner_resolution.go` | Matches `owner_ref` to a member every 30 minutes |
| `web/src/features/assets/components/asset-owners-tab.tsx` | The Owners tab |
| `migrations/000372_asset_access_grants.up.sql` | Explicit grants; ownership stops granting access |
| `internal/infra/postgres/asset_access_grant_repository.go` · `handler/asset_access_grant_handler.go` | Grant storage and `/assets/{id}/access-grants` |
| `web/src/features/assets/components/asset-access-grants-section.tsx` | *Direct access* on the Owners tab |

## The model

An `asset_owners` row names one user **or** one group, with:

| Column | Values |
|---|---|
| `ownership_type` | `primary`, `secondary`, `stakeholder`, `informed`, `regulatory` |
| `assignment_source` | `manual` (set by a person on the Owners tab or a group's asset assignment), `scope_rule` (a group scope rule), `owner_ref` (matched from the asset's owner reference) |

A user or group is an owner of an asset at most once (unique indexes on
`(asset_id, user_id)` and `(asset_id, group_id)`). `asset_owners` has no
`tenant_id`: every query reaches the tenant through `assets`, and a user owner
counts only while the user is a member of the tenant.

### Derived definitions

| Term | Definition | Used by |
|---|---|---|
| **Primary user owner** | The earliest-assigned `primary` row that names a user who is a member of the tenant | Finding auto-assign (`POST /findings/actions/assign-to-owners`), "by owner" finding groups (`group_by=owner_id`) |
| **Responsible owner** | A user named directly by a `primary` or `secondary` row | "Assigned to me" (`assigned_to_me=true` on findings and finding groups, the My Work page), who may mark a finding `fix_applied` |
| **Owned asset** | An asset with at least one row (user or group) | Inventory `has_owner`, Scoping `crown_jewels.with_owner`, data-quality "with owner", the risk snapshot ownership % |

The new-finding in-app notice goes to the earliest-assigned primary owner when
that owner is a user, and to the whole tenant otherwise. A group primary owner
is never a finding assignee: a finding is assigned to a user. Members of a group owner do not count as responsible owners for
"assigned to me".

## The owner reference (`owner_ref`)

`assets.owner_ref` is free text from ingest or the asset form (an email, a
team name, a cost center). It is a hint, not an owner:

- When it is the email of a member of the tenant (case-insensitive), that
  member becomes a `primary` owner with source `owner_ref`. This happens when
  an asset is created or updated through the API, and every 30 minutes for
  assets written by ingest (the owner-resolution controller).
- When `owner_ref` changes, the `owner_ref` row of the previous member is
  removed and the new member is added. A value that matches nobody only
  removes it.
- Rows set by a person or a scope rule are never changed by this. If the
  matched member is already an owner of the asset in any role, nothing is
  added.
- Removing an `owner_ref` owner on the Owners tab also clears the asset's
  `owner_ref`, otherwise the controller would add the owner back.
- An `owner_ref` owner never grants data access (see below).

## Ownership and data access

Ownership is accountability, not access (owner decision O1, 2026-10-03). A
**user** owner row, of any type or source, never puts the asset in that user's
data scope. A user who should see an asset gets it from a group that holds the
asset, or from an explicit grant (`asset_access_grants`,
`/api/v1/assets/{id}/access-grants`, `team:groups:write`, audited).

A **group** owner row is the group's asset assignment (the same row the Groups
page and scope rules write), so its members do see the asset. Adding or
removing a group owner therefore needs `team:groups:write`.

Migration `000372` preserved the access users had through ownership: each
direct owner who had the asset in `user_accessible_assets` got a grant with
source `migration`, shown as "From ownership" in the asset's *Direct access*
section, where an administrator can revoke it. It writes the counts to the
database log. See the data-scope section of
[authorization-matrix.md](authorization-matrix.md) and
[access-control-rules.md](access-control-rules.md).

## Migration from `assets.owner_id`

Until 2026-10 an asset also had `assets.owner_id`: one user, set only by the
`owner_ref` email match and read only by finding auto-assign, "assigned to
me", fix-applied and "by owner" finding groups. It did not talk to
`asset_owners`, so a primary owner set on the Owners tab was never
auto-assigned findings, and vice versa.

`000340` copies each `owner_id` into `asset_owners` as a `primary` row with
source `owner_ref`, in keyset batches of 5,000 assets:

- a user who already had a row for the asset keeps it unchanged (an explicit
  choice wins);
- a user who is no longer a member of the tenant is not copied (`owner_ref`
  stays, so they are matched again if they rejoin);
- it writes the three counts (copied, kept, skipped) to the database log.

Nothing reads or writes `assets.owner_id` after this change. The column and
its two indexes are dropped by a later contract migration, after a release
that contains the change, so that a pod of the previous release never meets a
database without the column (the expand-contract rule of
`scripts/check-migrations.sh`). Until then its values are frozen.
