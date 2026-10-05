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
3. **Ownership** (RFC-036 §6.3 `active_allowed`, `internal/app/easm/active_gate.go`).
   A target is refused when:
   - the inventory asset behind it (`DispatchTargetsInput.Assets`, or a typed
     target that names an asset as typed, lower-cased, or by the host of a
     URL or `host:port`) has an attribution record other than `confirmed`
     (`needs_review`, `candidate`, `dependency`, `monitor_only`, `rejected`);
   - the name, or any parent domain of it, is one the tenant rejected (a
     rejected asset or a live rejection tombstone), unless a person
     confirmed this very asset. This covers a rejected name that was deleted
     and came back, and free text under a rejected name;
   - an internet-facing asset (domain, subdomain, IP, service, web
     endpoint, host, …) has **no record** and is neither inside an active
     scope target nor at or under a root-domain seed or verified domain
     (`unattributed`). Private addresses and internal names are left to scan
     zones; repositories and cloud resources keep the record-only rule.

   Free text that names no asset is checked here only for rejected names;
   whether it matches a scope target is the act-scope check below. The
   caller sees one generic reason; the state that refused the target is
   logged (`active scan target refused`) with the path. A request refused as
   a whole (scan create, clone, import, quick scan, `POST /commands`) is also
   **audited** as `scan.target_refused` (medium, result `failure`) in the
   caller's tenant, with the actor, the path, the exact count and up to 50
   refused targets with the state that refused each.
4. **Scan-zone routing** (RFC-023): a target no zone covers, a zone without
   sensors, or a pinned sensor outside the target's zone is refused. An
   allowed zoned target returns its zone, and the command is stamped with it
   (`commands.scan_zone_id`), so only that zone's sensors can claim it.

**Fail closed.** A missing exclusion filter (`ErrDispatchGateUnavailable`), a
missing ownership check (`ErrAttributionGateUnavailable`, for any target), or
any lookup error returns an error, and the caller dispatches nothing.

### Ownership on every entry point

| Entry point | Behavior on a refused target |
|---|---|
| Scan create, clone, import (`CreateScan`), quick scan, `POST /commands` | the request is refused as a whole (`TARGET_OUT_OF_SCOPE`, 400, the targets named with the generic reason) and audited (`scan.target_refused`) |
| Scan run: manual trigger, schedule, retry controller, workflow trigger | the target (direct or group member) is skipped with a run warning; a run left with nothing is refused (`ALL_TARGETS_UNCONFIRMED`) |
| `POST /pipelines/runs`, `trigger_pipeline`, coverage dispatcher, every validate command (re-checks, proof-of-fix, retests, attack-simulation safe-checks), connector scans | `ResolveDispatchTargets` refuses the target |

`GET /api/v1/assets/{id}/attribution` answers `active_checks_allowed` with the
same gate and names the reason in `active_checks_blocked_by`.

**Existing assets (rollout).** No data migration: the rule is evaluated at
dispatch, so an asset inside a scope target or under a seed stays scannable
with no record, and adding a scope target or confirming the asset takes
effect on the next dispatch. An internet-facing asset that has no record and
is outside every scope target and seed is no longer probed until a person
confirms it on its Ownership tab (`assets:write`, audited) or a scope target
covers it. Runs that skip such targets say so in their warnings.

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

## Act scope: who may scan what

Owner decision D9 (research/15 L-06) limits scan targets to what the actor may
act on. The rule lives in `internal/app/actscope` and uses one helper,
`datascope.Enforcer.CanActOnAssets`. That helper resolves through
`ResolveFor`, so an administrator and any holder of a `has_full_data_access`
role (not through an API key) are unrestricted.

| Actor | Inventory asset (a typed name that is an asset, or a group member) | Free text that is not an asset |
|---|---|---|
| Restricted member | only assets in their data scope | refused |
| Unrestricted (admin, a `has_full_data_access` role, member of a fail-open organization with no scope row, system) | any asset of the tenant | only if it matches an active scope target of the tenant (the allowlist); exclusions still apply |

**The actor** is the request's caller. With no user in the context (a
scheduled run, a workflow action) the actor is the scan owner
(`scans.created_by`, resolved like `ForUser`). With neither, the actor is the
system, which is unrestricted.

| Path | Behavior |
|---|---|
| Scan create, quick scan | refused as a whole (`TARGET_OUT_OF_SCOPE`, 400, with each target and its reason) |
| Scan update | refused when the editor may not scan every direct target of the scan |
| Scan run (manual, scheduled, workflow) | out-of-scope direct targets and group members are skipped, with a run warning; a run left with nothing is refused |
| `POST /pipelines/runs`, `trigger_pipeline` | `ResolveDispatchTargets` with `ActScope: true`; `triggered_by` is the fallback actor; any refused target fails the run |
| `POST /commands` | refused as a whole |

Every lookup error refuses (fail closed). A dispatch that asks for the check
when none is wired gets `ErrActScopeUnavailable`.

**Live impact.** A scan of free text that matches no scope target, in an
organization with no scope targets, now has nothing to scan. Add the ranges
and domains to Scoping › Targets first.

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

`ResolveDispatchTargets` checks the act scope when `DispatchTargetsInput.ActScope`
is set (see above): one call per dispatch, with the tenant, the targets and the
assets already resolved, before any command exists. A new path a person starts
sets it; system paths (coverage, validation re-checks of a finding the caller
was already scope-checked on) leave it off.
