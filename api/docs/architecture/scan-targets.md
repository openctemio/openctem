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
| Live-hosts-first CIDR | a CIDR with `cidr_mode = liveness` (the default of a new scan) | the range itself (for host discovery and passive lookups only) + every address asset inside it, by asset id |

`asset_ids` on `POST /scans` are names resolved once at create (they become
literal targets).

## Changing a saved scan's targets

`PUT /scans/{id}` takes `targets`, `asset_ids` and `asset_group_ids`;
omitted means unchanged. `targets` or `asset_ids` replace the literal
targets (the assets are named for the editor, as on create);
`asset_group_ids` replaces the groups (`[]` = none). The new targets pass the
checks a new scan's pass, as the editor: target validation (no internal or
loopback address outside a scan zone), the editor's act scope, ownership for
active scanning, intrusive proof and the scope tier ceiling; a group must be
the organization's (another organization's group is not found). A scan must
keep a target or a group. Editing also needs the editor's act scope to cover
the scan's current targets. The CIDR mode is kept (an edit never switches a
scan to live hosts first unless it names it), and the targets skipped at
create are cleared. A governed scan's approval covers its targets, so a
changed scan needs approving again (`internal/app/scan/edit_targets.go`).
The Edit wizard sends them only when the user changed them.

## Run start

`internal/app/scan/targets.go` `resolveScanTargets`:

```
targets + groups + selectors
  └─ expandSelectors (target_selectors.go)
       wildcard → apex (literal) + ListSelectorAssets(UnderDomain)
       cidr (inventory mode) → ListSelectorAssets(InCIDR)
       cidr (liveness mode) → the range (literal) + ListSelectorAssets(InCIDR)
       options: seen_within_days, include_stale; cap 5 000 per selector
       new_since_last_run: only assets confirmed (or first seen without a
         record) since the previous completed/partial run; no apex literal (RFC-071)
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

### CIDR mode and live hosts first (RFC-088)

| `cidr_mode` | What the steps get |
|---|---|
| `liveness` | Host discovery (`discover.hosts`) and passive lookups get the range pieces. Every other active step gets the addresses host discovery found live (through the hop router) and the addresses the inventory holds in the range, never the range. |
| `sweep` | Every step that takes ranges gets the pieces; an address host discovery found inside a range the same step sweeps is not added again (`covered_by_range`). |
| `inventory` | The inventory's addresses inside the range only. |
| none stored | Sweep: a scan saved before liveness existed keeps sweeping, also when it is edited (an edit that names no mode keeps the stored one). The edit form and the scan detail page suggest live hosts first, with a one-click switch, when its scan can run it (a single scanner, or a workflow with Host discovery). |

- **Default.** A scan saved with a range and no mode gets `liveness` when it
  can run it: a single-scanner scan, or a workflow with a Host discovery
  step. Otherwise it sweeps. An explicit `liveness` on a workflow without
  Host discovery is refused (`LIVENESS_NEEDS_HOST_DISCOVERY`). An explicit
  `sweep` is stored as chosen.
- **Single-scanner scans** have no separate discovery step: a port scan
  takes the range (it probes each address itself), and a scanner that does
  not take ranges gets the inventory's addresses inside it.
- **At run time** the run context carries `cidr_mode: liveness`. An active
  step that would be left with nothing because only ranges were dropped,
  and has no predecessor to feed it, fails with
  `LIVENESS_NEEDS_HOST_DISCOVERY`. A Host discovery step with no address
  or range to probe (a run of names) is settled without a command, and the
  steps after it run on their own targets.
- **Probe ports.** The platform names them in every host discovery job
  (`stage.HostProbePorts`: 80, 443, 22, 3389, 8080, 8443, unless the step
  sets `ports`); the sensor never picks its own.
- The **Network** starter workflow starts with Host discovery
  (migration `network_workflow_host_discovery`); copies a tenant made before
  keep their steps.

## Resolve before active

An active stage (T1 and above, or a tool the catalogue does not know as
passive) takes a host name only while the platform holds recent evidence
that it resolves (RFC-088 A5; `scan.Service.DropStaleNames`):

- **Evidence** is the freshest observation of the name's inventory assets
  in the asset freshness classes `dns`, `http`, `tls` and `ports`
  (`asset_attribute_freshness`, tenant-scoped). A resolver answering for
  it, or a tool reaching it by name, counts.
- **Older than 7 days** (`assetfreshness.ResolveTTL`): the name is left out
  (`not_resolving`) and its enrichment is requested (reason `stale`), so the
  next run knows whether it resolves again.
- **No evidence at all** (a name typed in and never resolved): it is handed
  on. The sensor resolves it and reports it back as `unresolvable` when it
  does not resolve.
- Passive stages (DNS resolution, discovery) still take stale names: that
  is how they get fresh evidence. Names a stage of the same run found are
  fresh by construction.
- Workflow steps apply it to their seeds (an active step left with nothing
  settles without a command); a single-scanner run applies it at run start
  (`not_resolving_target_count`, a warning; a run left with nothing is
  refused `NO_RESOLVING_TARGETS`). A failed evidence read dispatches
  nothing.
- **Wildcard DNS.** The platform sends `wildcard_filter: true` with every
  dnsx job that does not set it (`withWildcardFilter`). A name that resolves
  only through a wildcard record is then never reported and gains no DNS
  evidence. When the job is over (command completed with exit code 0, every
  report filed under it completed with nothing rejected), ingest marks the
  input names it did not report (`asset_wildcard_dns`,
  `ingest.evaluateWildcardDNS`) and clears the mark of the names it did. A
  marked name is passive only: the active-probe gate refuses it, and a
  service or URL on it, as `wildcard_only` until a person confirms it or a
  filtered resolution reports it, and the scope join never confirms it. A
  run with the filter off proves nothing and changes no mark. A name that
  stopped resolving at all is marked too; it has nothing to probe, and the
  mark clears when it resolves again.

## Preview

The New Scan wizard asks the inventory directly, under the caller's data
scope: `GET /assets?under=<root>` for a wildcard and
`GET /assets?in_cidr=<range>` for an inventory-mode CIDR (count, freshest
name, sample). The run resolves under the scan actor's act scope, so the
numbers are what the caller can see now, not a promise.

### Quick Scan

A Quick Scan stores the typed targets on the ad-hoc scan's target list and
nowhere else (a client-supplied `targets` or `target` key in its scanner
settings is dropped), so wildcards and ranges are expanded by the run like
those of a saved scan. `POST /scans/quick/preview` (`scans:write` and
`scans:execute`) shows, before the start, what each typed target becomes:

- the number of known assets a wildcard or inventory-mode range covers;
- how many names the run would scan, and how many it leaves out by reason
  (exclusions and deny list, data scope, unconfirmed ownership, tier ceiling,
  internal addresses outside the zones, scanner type, archived), the matching
  exclusion rules, and up to five sample names;
- for a wildcard with no known name, an offer to run subdomain discovery on
  its apex when an active discovery tool exists.

It calls the run's own resolution (`resolveScanTargets`) as the caller, so the
tenant pin, the caller's data scope, the deny list and the selector cap apply
unchanged. Free text no scope entry covers is rejected before it is resolved.
Output is bounded to 20 targets and 5 sample names each. It creates nothing.

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
