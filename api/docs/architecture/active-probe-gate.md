# Active-probe gate

Every path that makes a sensor send traffic at a tenant's target passes one
fail-closed gate before a command exists. The gate is
`scan.Service.ResolveDispatchTargets` (`internal/app/scan/dispatch_gate.go`),
the same checks a scan trigger applies.

## What the gate checks

For each target, in order:

1. **Scan target validator** with the private-range policy of scan create:
   loopback, link-local, metadata, deny-listed and malformed targets are
   refused; a private address is allowed only inside one of the tenant's scan
   zones.
2. **Scope exclusions** (`scope.Service.ExcludedTargets`), matched as on a scan
   run (URL and `host:port` forms included). When the target is a URL on an
   inventory asset, the asset's inventory name is matched too, so excluding
   `legacy.example.com` also refuses `https://www.legacy.example.com/login`
   probed as that asset.
3. **Attribution** (RFC-036 O4): when the target is an inventory asset
   (`DispatchTargetsInput.Assets`), the asset must not have an attribution
   state other than `confirmed` (`needs_review`, `candidate`, `dependency`,
   `monitor_only`, `rejected` are refused). An asset with no attribution row
   counts as confirmed, as on a scan. Targets the tenant typed itself carry no
   asset and are not attribution-checked (O8).
4. **Scan-zone routing** (RFC-023): a target no zone covers, a zone without
   sensors, or a pinned sensor outside the target's zone is refused. An
   allowed zoned target returns its zone, and the command is stamped with it
   (`commands.scan_zone_id`), so only that zone's sensors can claim it.

**Fail closed.** A missing exclusion filter (`ErrDispatchGateUnavailable`), a
missing attribution check when assets are named
(`ErrAttributionGateUnavailable`), or any lookup error returns an error, and
the caller dispatches nothing.

## Who calls it

| Path | Where | Notes |
|---|---|---|
| Scan trigger | `scan/trigger.go`, `scan/targets.go` | Same checks inline (`resolveScanTargets` + zone planning). Folding it into the gate is RFC-042 S5 (`scope.Gate`). |
| `POST /pipelines/runs` | `pipeline/run_targets.go` | Typed targets; no assets. |
| Coverage dispatcher | `scancoverage/scheduler.go` `gateBatch` | Each candidate passes its asset id, so unconfirmed assets are skipped. |
| Every `validate` command | `validation/dispatcher.go` `CommandDispatcher.Dispatch` | Finding re-check (`POST /findings/{id}/validate`, proof-of-fix fallback, Jira "Done"), continuous retest (both checks), attack-simulation safe-check. |
| `POST /commands` | `scan/command_gate.go` | Member-created scan commands (RFC-040 group A). |

`validation.CommandDispatcher` is the only producer of validate commands. It
runs `validation.CheckTarget` on every job; with a nil gate it refuses every
job. `cmd/server` wires one dispatcher for every validation path through
`lateTargetGate`, which refuses until the scan service exists.

The retest service also calls `Preflight` (the same check) before it records a
retest, so a refused target never takes the finding's retest slot.

### Refusal is policy, not ineligibility

A refusal wraps `validation.ErrTargetRefused` (an `ErrValidation`, HTTP 400
with the reason). It never wraps `retest.ErrNotEligible`. Proof-of-fix falls
back to a plain validation re-check only when a finding has no deterministic
retest. A refused retest therefore stops and is reported; it does not fall
back to another probe of the same target (finding L-08 of research/15). The
auto-retest scheduler logs the refusal and moves on.

## Bypass guard

`internal/app/validation/gate_paths_test.go` scans `internal/` and `pkg/` for
every caller of the command constructor and fails when a file that creates
sensor commands is not listed with the gate it uses. A new dispatch path cannot
merge without either going through the gate or being reviewed into that list.
A second test fails if a validate command is built outside
`CommandDispatcher`.

## Tenant isolation

Every lookup takes the tenant from the caller's authenticated context (the
finding, retest or coverage config), never from a request body: exclusions,
attribution (`asset_attributions.tenant_id`), zones and assets are all
tenant-scoped queries. Another tenant's exclusions, attribution rows or zones
never allow or refuse a probe (`retest/gate_db_test.go`,
`validation/gate_test.go`).

## Where the caller's scope plugs in

`ResolveDispatchTargets` is also where a check of the caller's data scope
belongs (research/15 L-06): one call per dispatch, with the tenant, the
targets and the assets already resolved, before any command exists.
