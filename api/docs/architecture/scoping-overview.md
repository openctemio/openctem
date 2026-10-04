# Scoping overview and cycle attacker profiles

**Status: SHIPPED.** Proposal: ui `docs/ui/scoping-ia-2026-10.md` (sections 5.2
and 5.3, decision D9).

The Scoping overview (`/scoping` in the UI) answers one question: is our scope
written down for this cycle? It reads one endpoint. The cycle detail page links
attacker profiles to a cycle and needs to list and unlink them.

| Where | What |
|---|---|
| `pkg/domain/scoping/summary.go` | `Summary` read model and its JSON contract |
| `internal/infra/postgres/scoping_summary_repository.go` | The single aggregate query and the written definitions |
| `internal/infra/http/handler/scoping_handler.go` | `GET /api/v1/scoping/summary` |
| `internal/infra/http/handler/ctem_cycle_handler.go` | `ListProfiles`, `UnlinkProfile` |
| `internal/infra/http/handler/scoping_db_test.go` | Fixtures with known answers, cross-tenant checks |

## `GET /api/v1/scoping/summary`

Permission `assets:read`. No module gate: like the Program Health scorecards it
only counts what the tenant's registers already hold, and a disabled module
shows up as zeros rather than as an error. Tenant-wide: no data scope is
applied, the same as Program Health (the dashboard endpoints take no user).

One SQL statement (scalar subqueries over CTEs); no per-row calls.

```json
{
  "active_cycle": {
    "id": "7aa859d2-...", "name": "Q3 external", "status": "active",
    "start_date": "2026-10-01T00:00:00Z", "end_date": "2026-12-31T00:00:00Z",
    "objectives": 3, "success_criteria": 2, "in_scope_services": 2,
    "exclusions": 1, "threat_scenarios": 0,
    "scope_assets": 2, "attacker_profiles": 1
  },
  "crown_jewels": { "total": 3, "with_owner": 2 },
  "business_services": { "total": 3, "with_assets": 2 },
  "business_units": { "total": 2 },
  "assets": { "total": 4, "in_business_unit": 1 },
  "boundary": { "targets": 2, "exclusions": 1 },
  "attacker_profiles": { "total": 2 },
  "threat_models": { "total": 3, "crown_jewels_covered": 1 },
  "cycles": { "total": 3 }
}
```

### Definitions

| Field | Definition |
|---|---|
| `active_cycle` | The tenant's `active` cycle; else the newest `review`; else the newest `planning` (newest = `created_at`). `null` when there is none. `status` says which. Dates are the cycle's `start_date`/`end_date` at midnight UTC, or `null`. |
| charter counts | Lengths of `objectives`, `success_criteria`, `in_scope_services`, `exclusions`, `threat_scenarios` in the charter JSONB. A key that is missing or not an array counts 0. |
| `active_cycle.scope_assets` | Rows in `ctem_cycle_scope_snapshots` for the cycle (0 until it is activated). |
| `active_cycle.attacker_profiles` | Rows in `ctem_cycle_attacker_profiles` for the cycle whose profile belongs to the tenant. |
| `assets.total` | Assets with `status <> 'archived'`. All counts below that mention assets use the same population. |
| `crown_jewels.total` | Those assets with the `assets.is_crown_jewel` column set. The column is the only crown-jewel store (migration 000390): `PATCH /assets/{id}/crown-jewel` writes it (assets:write, the asset in the caller's data scope, audited as `asset.crown_jewel_changed`), and `is_crown_jewel` is a reserved key that `properties` refuse. |
| `crown_jewels.with_owner` | Crown jewels with an `asset_owners` row that names a user who is a member of the tenant or a group of the tenant (the inventory's `has_owner` test; see [asset-ownership.md](asset-ownership.md)). |
| `business_services.with_assets` | Services with at least one `business_service_assets` row whose asset belongs to the tenant. |
| `assets.in_business_unit` | Assets with a `business_unit_assets` row for one of the tenant's units. A business unit set on an asset group is not counted (see the group-BU follow-up, C14). |
| `boundary` | Every `scope_targets` / `scope_exclusions` row, whatever its status (pending and rejected exclusions included): the `total_targets` / `total_exclusions` of `GET /scope/stats`. It counts the boundary as drawn, not what scans apply — only approved, active, unexpired exclusions are applied (see the scope exclusions section of `authorization-matrix.md`). |
| `attacker_profiles.total` | The tenant's profiles, built-in (`is_default`) ones included: what `GET /attacker-profiles` lists. |
| `threat_models.crown_jewels_covered` | Distinct crown jewels (as above) that a `crown_jewel`-scoped threat model points at through `scope_ref_id`. |
| `cycles.total` | All of the tenant's cycles, any status. |

## Cycle attacker profiles

| Route | Permission | Result |
|---|---|---|
| `GET /api/v1/ctem-cycles/{id}/profiles` | `ctem:cycles:read` | `200 {"data": [AttackerProfile, ...]}`; each item is the shape of `GET /attacker-profiles/{id}`. Built-in profiles first, then by name. |
| `POST /api/v1/ctem-cycles/{id}/profiles` | `ctem:cycles:write` | `204`; body `{"profile_ids": [...]}`. Profiles of another tenant are ignored. |
| `DELETE /api/v1/ctem-cycles/{id}/profiles/{profileId}` | `ctem:cycles:write` | `204`, also when the profile was not linked. |

All three sit behind the `ctem_cycles` module gate and return 404 when the
cycle is not the caller tenant's (or the id is not a UUID).

**System profiles.** `attacker_profiles.tenant_id` is `NOT NULL`; there are no
global rows. The four built-in profiles are seeded per tenant with
`is_default = true` (migration 000147), so they are the tenant's own rows and
can be linked like any other. Rows under the internal `system` tenant are not
listed by `GET /attacker-profiles` and cannot be linked.

## Business services: `asset_count`

`GET /api/v1/business-services` and `GET /{id}` (and the Create/Update
responses) carry `asset_count`: distinct tenant assets linked through
`business_service_assets`, computed as a correlated subquery in the same
query. The Business context page shows it so owners see services with no
assets.

Linking and unlinking are not audit-logged, matching the rest of the cycle
endpoints.
