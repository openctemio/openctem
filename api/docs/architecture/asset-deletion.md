# Asset deletion

**Status: SHIPPED.** Owner decision O3 (2026-10-03, assets area review §4).

Deleting an asset never destroys findings. Before this change a delete was
a hard delete, and `findings.asset_id ON DELETE CASCADE` erased every finding
of the asset: its history, SLA evidence and remediation records, in one
click.

| Where | What |
|---|---|
| `migrations/000378_asset_soft_delete.up.sql` | `assets.deleted_at` / `deleted_by`; findings FK becomes `ON DELETE NO ACTION` (added `NOT VALID`) |
| `migrations/000379_findings_asset_fk_validate.up.sql` | Validates that FK without blocking writes |
| `migrations/000380_assets_deleted_index.up.sql` | Partial index for the purge |
| `internal/infra/postgres/asset_soft_delete.go` | The refused-or-soft delete, the detach list, the purge |
| `internal/infra/controller/asset_purge.go` | Purges soft-deleted assets after 30 days |
| `web/src/features/assets/lib/safe-delete.ts` | Every UI delete: refusal message, Archive offer, bulk report |

## Rules

`DELETE /api/v1/assets/{id}` (`assets:delete`, data scope on the asset):

1. **The asset has findings** (any finding, whatever its status): refused
   with **409**, `details = {"reason": "asset_has_findings", "finding_count":
   N, "archive_path": "/api/v1/assets/{id}/archive"}`. Nothing changes.
   Archive it instead (`POST /api/v1/assets/{id}/archive`): it leaves the
   active inventory and its findings stay.
2. **No findings**: soft delete, in one transaction, audited
   (`asset.deleted`):
   - `deleted_at` and `deleted_by` are set;
   - the name is freed. The row keeps a unique tombstone name
     (`<name> [deleted <id>]`), so the same name can be created or ingested
     again at once; the original name and type are in the audit entry;
   - the asset is detached from everything that would surface it or route
     work to it: group membership, owners, data scope
     (`user_accessible_assets`), access grants, relationships and suggestions,
     business units and services, compensating controls, identity
     identifiers, scan coverage state, its discovered services and
     components, pending dedup reviews, and its children's `parent_id`;
   - its history stays: state history, exposure events (not listed and not
     counted as active any more: the exposure list and stats, the EASM
     overview and the daily risk snapshot skip them), attribution evidence.
3. An unknown or already deleted asset, or one of another tenant: 404.

**Every read excludes a deleted asset**: lists, counts, facets, stats,
by-id/by-name/by-IP lookups, ingest correlation, scope rules, scan target
and coverage selection, lifecycle, EASM, dashboards and metrics. Reads of
`assets` carry `deleted_at IS NULL`; reads that reach assets through a
membership table (groups, owners, relationships, business links) are covered
by the detach in step 2, and reads that reach them through findings are
covered because a deleted asset has none. Rows that point at an asset and
are read on their own (exposure events) carry `notOfDeletedAssetSQL`.
`asset_soft_delete_db_test.go` and `asset_soft_delete_reads_db_test.go` check
the repository reads: lookups, lists, counts, search, graph nodes, tag facets,
ingest correlation, groups, scope rules, bulk status, exposures and EASM, with
another tenant's reads unaffected.

**The purge.** `AssetPurgeController` hard-deletes, daily, soft-deleted
assets older than 30 days that still have no findings (a finding that raced
in after the delete keeps the row). Its hard delete cascades the history kept
in step 2.

**No path can cascade findings away.** `findings.asset_id` is
`ON DELETE NO ACTION`: deleting an asset row that still has findings fails,
whoever does it (the purge, an asset merge that forgot to move them, a manual
statement). `NO ACTION` rather than `RESTRICT` because it is checked at the
end of the statement: deleting a tenant cascades to its assets *and* its
findings in one statement and keeps working.

## Name uniqueness

`idx_assets_name_tenant_unique (tenant_id, name)` is still a full unique
index: pods of the previous release run `ON CONFLICT (tenant_id, name)`
without a predicate, which needs a full index. That is why a deleted asset
frees its name by renaming instead of by a partial index. Replacing the full
index with a partial one (`WHERE deleted_at IS NULL`) is a contract step for
a later release; until then a partial index would be inferred together with
the full one and ingest could resolve a name to the deleted row.

## UI

Every delete (typed asset pages, bulk delete, the external attack-surface
page, the repository page) uses one confirmation
(`AssetDeleteDialogShared`) and the helpers in `safe-delete.ts`:

- single delete: a refusal shows "not deleted: it has N findings" with an
  **Archive** action;
- bulk delete: one report of what was deleted, refused (with **Archive these
  N**) and failed; archiving reports what was archived.
