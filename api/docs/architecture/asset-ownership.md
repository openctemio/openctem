# Asset ownership

**Status: SHIPPED.** Decision O2.

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
| `migrations/000372_asset_access_grants.up.sql` | Explicit grants |
| `migrations/003053_asset_owner_view_scope.up.sql` | `v_asset_owner_scope`: primary and secondary owners set by a person see the asset; creator grants |
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

Finding auto-assign assigns only open, unassigned findings in the caller's
data scope. A `confirmed` finding moves to `in_progress`; a `new` finding stays
`new` (assignment is not triage); closed findings are never touched.

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
- An `owner_ref` owner never grants data access (see below): `owner_ref` is
  data from a source or an import, and a source must never widen what a
  member can see.

## Ownership and data scope

Owning an asset grants **view** of it (owner decision 2026-10-19, replacing
O1: owners were assigned findings on assets they could not open). A **user**
owner row with type `primary` or `secondary` and source `manual` (set by a
person) puts the asset in that user's data scope, so they see the asset and
its findings everywhere the data scope applies. Their role still decides what
they may do there; ownership adds no permission.

| Owner row | In the owner's data scope |
|---|---|
| user, `primary` / `secondary`, source `manual` | yes |
| user, `stakeholder` / `informed` / `regulatory` | no |
| user, source `owner_ref` (any type) | no |
| group (any type) | yes, for the group's members (the group's assignment) |

The rule is the view `v_asset_owner_scope` (and the Go mirror
`accesscontrol.UserOwnerGrantsScope`). A trigger on `asset_owners`
recomputes the (user, asset) scope row on every insert, delete and change of
user, type or source, in the same transaction: an ex-owner loses the asset at
once unless a group or an explicit grant still gives it, and the member
lifecycle hand-over (ownership moved to another member) moves the view with
it. Only an active member of the asset's organization gets a row, so naming a
user of another organization grants nothing.

Because such an owner changes who can see the asset, naming one, moving a
user owner into or out of `primary`/`secondary`, or removing one needs
`team:groups:write` on top of `assets:write`/`assets:delete`; a
non-administrator cannot name themself; each change is audited as
`asset.access_granted` / `asset.access_revoked` with `source=ownership`.
`stakeholder` and `informed` owners need only `assets:write`.

A user who should see an asset without owning it gets it from a group that
holds the asset, or from an explicit grant (`asset_access_grants`,
`/api/v1/assets/{id}/access-grants`, `team:groups:write`, audited).

**Creator grant.** A member without full data access who creates an asset
(`POST /api/v1/assets`) gets an explicit grant on it with source `creator`
(audited), so the asset they just created does not answer 404 to them. It
does not make them an owner (finding assignment is unchanged). An
administrator can revoke it in the asset's *Direct access* section.

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

Nothing reads or writes `assets.owner_id` after this change. `001056` (the
contract step, merged after a release that contains the change, so that a pod
of the previous release never meets a database without the column) drops the
column and its two indexes. Its down migration restores the column from the
`owner_ref` rows; the values 000340 skipped are not restored.
