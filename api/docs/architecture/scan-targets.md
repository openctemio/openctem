# Scan targets: literal, groups and dynamic selectors

> Design: [RFC-068](../rfcs/RFC-068-dynamic-scan-targets.md). Run model:
> [scan-lifecycle.md](scan-lifecycle.md). Stages and in-run chaining:
> [scan-stages.md](scan-stages.md). The gate:
> [active-probe-gate.md](active-probe-gate.md).

A scan says **what** to scan in three ways, all resolved again at every run:

| Source | Stored as | Resolved at run start to |
|---|---|---|
| Literal targets | `scans.targets` (a host, an address, a URL, `host:port`, a swept CIDR) | themselves |
| Asset groups | `scans.asset_group_ids` | the group's current members (not archived), by asset id |
| Wildcard domain | `*.example.com` in `scans.targets` | the apex + every domain-class asset at or under it, by asset id |
| Inventory-mode CIDR | a CIDR in `scans.targets` with `target_options.cidr_mode = inventory` | every address asset inside it, by asset id |

`asset_ids` on `POST /scans` are names resolved once at create (they become
literal targets).

## Run start

`internal/app/scan/targets.go` `resolveScanTargets`:

```
targets + groups + selectors
  └─ expandSelectors (target_selectors.go)
       wildcard → apex (literal) + ListSelectorAssets(UnderDomain)
       cidr (inventory mode) → ListSelectorAssets(InCIDR)
       options: seen_within_days, include_stale; cap 5 000 per selector
  └─ scanner type gate (single-scanner runs)
  └─ ResolveDispatchTargets: validator, exclusions, ownership, act scope,
     private ranges, tier ceiling
  └─ run context: targets (workflow), target_types, target_expansion,
     selector_roots, counts and warnings
```

- `ScanSelectorRepository.ListSelectorAssets`
  (`internal/infra/postgres/scan_selector_repository.go`) is one query per
  selector: `tenant_id = $1`, `deleted_at IS NULL`, status `active` (plus
  `stale`, `inactive` with `include_stale`), optional `last_seen >= $n`,
  ordered by `last_seen` descending, `LIMIT cap + 1`. A wildcard matches
  `asset_class = 'domain'` and `lower(name) = root OR name ILIKE '%.' ||
  escaped(root)`. A range matches `ip_address`/`host` assets whose name is a
  single address inside it (`pg_input_is_valid(name, 'inet') AND
  name::inet <<= range`).
- A subdomain discovery tool (`discover.subdomains`) takes the apex: a
  single-scanner run rewrites the pattern to its apex
  (`applyWildcardTargets`) and reads no inventory; a workflow step of that
  stage drops the seeds under a wildcard apex (`DiscoverySeeds`, called in
  `scanrun.queueStepForExecutionWithSettings`).
- A missing or failing reader refuses the run with
  `TARGET_SELECTOR_UNAVAILABLE`.

## During the run

Chained stages add what earlier stages produced, through the inventory and
the per-hop gate (scan-stages.md §3). Over-cap and hop-limit skips are
counted in `scan_stage_targets_skipped_total{reason}` and listed per stage
in `GET /scan-runs/{id}/stages`.

## What a run records

- `dispatch.target_expansion` on `GET /scan-runs/{id}`: per selector the
  pattern, kind, matched count, `capped`, a sample of up to 10 names.
- `dispatch.warnings`: a capped selector.
- `scan_target_selector_expansions_total{kind,outcome}`: `expanded`,
  `empty`, `capped`.
- The scope snapshot (RFC-065 §9) and the in-run provenance
  (`scan_run_targets`) as for every run.

`target_expansion` and `selector_roots` never reach a sensor
(`StepRunContext`).

## Options

`scans.target_options` (migration 001640), `pkg/domain/scan/target_options.go`:
`cidr_mode` (`sweep` default, `inventory`), `seen_within_days` (0–365),
`include_stale`. Set on create and update (`target_options` in the body;
omitted on update = unchanged), exported and imported, copied by clone.

## Preview

The New Scan wizard asks the inventory directly, under the caller's data
scope: `GET /assets?under=<root>` for a wildcard and
`GET /assets?in_cidr=<range>` for an inventory-mode CIDR (count, freshest
name, sample). The run resolves under the scan actor's act scope, so the
numbers are what the caller can see now, not a promise.

## Tests

- `tests/unit/scan_wildcard_targets_test.go`: expansion, re-resolution,
  caps, gate by asset id, cross-tenant reader, CIDR modes, workflow seeds,
  fail closed, export/import.
- `internal/infra/postgres/scan_selector_db_test.go`: the query (tenant,
  status, window, label boundary, LIKE escaping, ranges), options round trip.
- `internal/infra/http/routes/data_scope_asset_in_cidr_db_test.go`:
  `in_cidr` under data scope.
- `tests/integration/scan_dynamic_targets_test.go`: a run on a migrated
  database with the production ownership gate and exclusions.
