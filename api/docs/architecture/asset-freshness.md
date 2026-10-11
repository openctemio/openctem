# Asset freshness and automatic enrichment

> Design: [RFC-075](../rfcs/RFC-075-asset-freshness.md). Related:
> [asset-attribute-reconciliation.md](asset-attribute-reconciliation.md)
> (sources, TTL precedence, change timeline),
> [scan-stages.md](scan-stages.md) (stage catalogue, planner, hop router),
> [scan-intensity.md](scan-intensity.md) (passive = in scope and off-target),
> [scan-windows.md](scan-windows.md), [scan-approval.md](scan-approval.md),
> [easm.md](easm.md).

Status: P0 in implementation (#1753 freshness records, #1754 automatic
enrichment, #1755 web).

Every asset found by any source is enriched passively at once, and each of
its enrichable attribute classes records when it was last observed, so the
inventory shows which data is live, stale or dead.

## Attribute classes

`pkg/domain/assetfreshness` holds the class table (code-reviewed platform
data):

| Class | Stage that observes it | Asset types | Base TTL | Passive |
|---|---|---|---|---|
| `dns` | `resolve.dns` | domain, subdomain | 24 h | yes |
| `registration` | `lookup.rdap` | domain | 7 d | yes |
| `network_owner` | `lookup.asn` | ip_address, network | 7 d | yes |
| `http` | `probe.http` | http_service, website, subdomain, ip_address | 3 d | no |
| `tls` | `probe.http` | certificate | 3 d | no |
| `ports` | `scan.ports` | ip_address, host | 7 d | no |

TTL = base × 0.5 when the asset is critical or high or internet-facing
(floor 6 h). State per class: `live` (within TTL), `stale` (past TTL),
`dead` (past 3 × TTL), `never` (a passive class that applies to the type and
nobody observed). The asset's state is its worst class.

## Recording observations

`asset_attribute_freshness` (PK tenant, asset, class; composite FK to the
asset, cascade). The ingest asset processor calls its observed callback once
per batch with every asset the report **wrote** (created or updated), the
report's tool and its observation time (`reportObservedAt`). The recorder
maps the tool to its stages (`stage.ForTool`), each stage to its classes,
keeps the assets whose type the class applies to, and upserts
`observed_at = GREATEST(stored, new)` in one statement. Any report counts:
person-started, scheduled, enrichment, CI. A failure is logged and counted
(`asset_freshness_record_errors_total`) and never fails the ingest.

## Enrichment requests and the controller

`asset_enrichment_requests` (PK tenant, asset): one row per asset,
`requested_at`, `dispatched_at` (NULL = pending), `reason`, `attempts`,
`last_run_id`. Written by:

- ingest's discovered callback (every asset an ingest created: scans, sensor
  reports, CTIS uploads, finding imports, connectors, program targets,
  certificate transparency, CI runs);
- `AssetService.CreateAsset` (manual create);
- the CSV import, after each batch.

An upsert of a pending row keeps it pending; a row dispatched within the
6 h cooldown is not re-opened by `new_asset` (a re-created asset is not
enriched twice in a row).

The `asset-enrichment` controller (every 2 min, one replica at a time,
module `attack_surface`) for each tenant with pending rows past the 60 s
debounce or with 200 pending:

1. reads the tenant's switch (`easm.enrichment_disabled`); off: drains the
   rows without a run;
2. claims up to 500 rows within the daily budget
   (`ASSET_ENRICHMENT_DAILY_BUDGET`, default 2 000 dispatched assets per
   24 h) with `FOR UPDATE SKIP LOCKED`, so replicas never claim the same row;
3. loads the assets (tenant-scoped), drops archived and types without a
   profile, groups them by profile;
4. starts one passive run per profile through
   `scan.Service.StartEnrichment`: the names go through
   `ResolveDispatchTargets` as a passive dispatch by the system (target
   validator, scope exclusions, system act scope, the passive scope rule,
   rejected names); a refused name is dropped and its request settled
   `refused`, never failing the batch. The run is an ad-hoc scan named
   "Automatic enrichment", tagged `auto-enrichment`, intensity passive.
5. settles each request: `dispatched` (with the run), `refused`,
   `no_profile` (archived, deleted, or a type without a profile), `failed`
   (the run could not start), `disabled` (the tenant's switch is off). An
   unreadable switch claims nothing (fail closed).

Profiles (system workflows, migration `asset_enrichment_profiles`):

| Profile | Types | Steps |
|---|---|---|
| Enrich root domains | domain | `resolve.dns`, `lookup.rdap` |
| Enrich host names | subdomain | `resolve.dns` |
| Enrich addresses | ip_address | `lookup.asn` |

## Gates

The run passes every gate a person's passive scan passes: target validation
(no internal, metadata, link-local), the system act scope (scope entries
only), the passive scope rule (`refusePassiveOutOfScope`: an internet name
no scope authority covers is refused), rejected names never, scan windows
(RFC-067, program testing windows included), program rules at delivery
(RFC-065 §12). Passive runs need no approval (RFC-073).

## API

- `GET /api/v1/assets/{id}/freshness` (`assets:read`; the asset is read
  through the data-scope path, so an asset outside the caller's scope or
  another tenant's is 404): classes with `observed_at`, `source`,
  `ttl_seconds`, `state`; the asset `state`; the request (`requested_at`,
  `dispatched_at`, `last_run_id`, `reason`); `next_due_at`.
- `GET /api/v1/assets?freshness=stale|never`: assets with a class past its
  TTL, or with a passive class that applies and was never observed.
- `GET/PUT /api/v1/easm/settings`: `enrichment_enabled` (default true; a PUT
  without the field keeps the stored value).

## Tenant isolation

Every statement carries `tenant_id`; both tables reference assets with
`(tenant_id, asset_id)` composite keys and cascade with the asset and the
tenant. The controller works tenant by tenant and starts runs in the asset's
tenant. Tests: `TestAssetFreshness_TenantAndScopeIsolation`,
`TestEnrichmentRequests_IdempotentCooldownAndTenantIsolation`,
`TestEnricher_StartsPassiveRunForInScopeNamesOnly`.

## Metrics

`openctem_asset_freshness_observations_total{class}`,
`openctem_asset_freshness_record_errors_total`,
`openctem_asset_enrichment_requests_total{reason}`,
`openctem_asset_enrichment_dispatched_total{profile}`,
`openctem_asset_enrichment_skipped_total{reason}`.
