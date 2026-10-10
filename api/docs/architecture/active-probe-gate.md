# Active-probe gate

Every path that makes a sensor send traffic at a tenant's target passes one
fail-closed gate before a command exists. The gate is
`scan.Service.ResolveDispatchTargets` (`internal/app/scan/dispatch_gate.go`):
one function holds every target decision, the scan trigger included.

## Scope patterns

A domain scope target or exclusion `x` covers exactly `x`; `*.x` (and `**.x`)
covers `x` **and** every name below it (RFC-054 §4.1, decision S1). For
the subdomains without the apex, add the wildcard plus an exclusion of exactly
`x`. Verified domains (proof) and the ownership gate use the same "this domain
and everything under it" meaning, so `example.co.uk` is in scope under
`*.example.co.uk`. Matching is case-insensitive, ignores one trailing dot and
compares IDNA ASCII forms (`pkg/domain/scope.matchDomain`).

The sensor-local policy still reads `*.x` as names below `x` (the stricter
reading on its allow list); aligning it is a follow-up in sdk-go and the
sensor.

## Scope entries (RFC-054)

A scope target authorizes probes only while it is **in effect**: status
`active` and not past `expires_at`. The read of active targets filters on
both, so an expired one-off stops authorizing at once; the data-expiration
controller then marks it `expired`.

- **One-off entries** carry `expires_at` (default 7 days, at most the
  organization's `one_off_max_days`, 30 at most) and a `reason`.
- **Intrusive (t2) entries** have their own bound, the owner-only
  `t2_max_duration` (`7d`, `30d` default, `90d`, `365d`, `permanent`;
  RFC-054 §12.4), checked in `scope.resolveExpiry` on create and update
  (also when only the tier is raised: `INTRUSIVE_TOO_LONG`,
  `INTRUSIVE_NEEDS_EXPIRY`). The one-off policy does not apply to them.
  Only `PUT /scope/settings/intrusive` (owner, step-up, reason) changes
  it; `PUT /scope/settings` keeps it (`ScopeSettings.WithIntrusive`).
- **Re-attestation** (RFC-054 §12.5). An active t2 entry that outlives its
  attestation period (owner-set `t2_attestation_days`, default 90) is
  confirmed with `POST /scope/targets/{id}/attest` (`scope:approve`). The
  `scope-attestation` controller (hourly) opens the request (owners and
  administrators told in-app, approvers by email, channels) and, after 14
  days without an answer, sets the entry to t1 with a conditional update
  (`ScopeTargetRepository.DowngradeUnattested`; never a delete), audited as
  `scope_target.t2_downgraded`.
- **Who widens.** Creating, activating, extending or raising the tier of an
  entry is widening. A holder of `attack_surface:scope:approve` re-authenticates
  (step-up) and the entry needs the organization's approval count of other
  approvers (`widening_approvals`, default `min(1, admins − 1)`, at least 1
  with two or more admins and for `t2`); until then it is `pending` and
  authorizes nothing. Anyone else with `scope:write` only **requests** a
  one-off for one name or address, with a reason; it needs an approver.
- **Approving** (`POST /scope/targets/{id}/approve`) needs the approval
  permission and step-up; the requester never approves, nobody approves
  twice. Exclusion removal, deactivation and shortening need step-up too.
- **Who approves** (RFC-054 §12.2). A pending entry answers `approval`:
  the approvals still needed and the members who can give them (owners,
  administrators, holders of `scope:approve`; never the requester or a
  prior approver), named only for callers with `team:members:read`
  (`postgres.ScopeActorRepository.ScopeApprovers`). They are told in-app,
  by email and on the channels; `POST /scope/targets/{id}/remind` repeats
  it once an hour at most (atomic `approval_reminded_at`).
- **No other approver** (RFC-054 §12.3). `POST /scope/targets/{id}/self-approve`
  lets the owner who requested the entry approve it when the eligible
  approvers cannot, with a reason and a code from their authenticator app
  in the request (`auth.AuthService.VerifyFreshTOTP`; replay-proof, counts
  towards the lockout). The approval row is marked `self_approved`; the
  audit event is high severity; every administrator is told.
- Every widening that takes effect, every request, and every settings change
  notifies all active owners and administrators in-app, and is audited.
- Narrowing (deactivate, delete, an earlier expiry, a lower tier) stays one
  click.
- **One authority: scope entries** (RFC-054; migration
  `001262`). Root-domain seeds were folded into permanent `*.<domain>`
  entries and `/api/v1/easm/seeds` is gone; a verified domain, of any
  purpose, is proof only (§8.1 of RFC-054). `scopeauth.Load` reads the
  active entries and the verified domain names (proof); nothing else.
- **Discovery hangs off the entry.** `discovery` on a permanent domain
  entry makes it a discovery root (Certificate Transparency in
  `certmonitor`, DNS checks in `easm_dns`). One-off and non-domain entries
  never discover. Turning discovery on needs `scope:approve` and step-up.

## Platform guardrails (RFC-054 §8)

Operator settings, never tenant settings:

- **New entries** (`scope.Service.CreateTarget`, `pkg/domain/scope/guardrails.go`):
  no public suffix or wildcard of one (embedded Public Suffix List), no
  government or military name, no shared-provider apex as a wildcard root,
  no `0.0.0.0/0`, `::/0`, link-local or metadata address, nothing in
  `SCOPE_DENY_EXTRA`, no public range larger than the CIDR caps.
- **Dispatch** (the ownership gate below): a deny-listed target is refused
  on every path (`platform_denied`); with `SCOPE_ACTIVE_PROOF=all` an
  internet target not at or under a verified domain is refused
  (`proof_required`).
- **Platform sensors** (`scan/active_proof.go`): with `platform_sensors` or
  `all`, a job goes to platform sensors only when every target is verified;
  an explicit platform preference with an unproven target is refused
  (`PROOF_REQUIRED`).
- **Intrusive scans**: a scanner whose stages are all T2 needs every target
  verified, at create, quick scan and every run. A workflow checks each
  intrusive (T2) step on its own: the step gets only the verified targets
  and fails (`STEP_TARGETS_REFUSED`) when none is left.
- **Tier ceilings** (RFC-054 §4.2 step 6, `scan/tier_ceiling.go`): a scope
  entry authorizes probes up to its `max_tier` (verified domains authorize
  nothing). The probe's tier is the tool's highest stage tier (`stage.ProbeTier`,
  unknown tools T1). A target covered only below it is refused `tier_exceeds`
  (fix `raise_tier`): scan create, quick scan and a `POST /commands` scan
  command (at the tier of the scanner it names) refuse the request, a run
  skips the target with a warning (`TIER_EXCEEDS` when nothing is left), a
  workflow step skips it for that step, and `ResolveDispatchTargets` refuses
  it at `DispatchTargetsInput.Tier` (T1 when unset; passive dispatches are
  not checked). `easm.ActiveGate.TierExceeded` answers, tenant-scoped.

## Program entries (RFC-065)

A scope entry records its authorization source. `program` entries come from a
bug-bounty program the organization follows ([bounty-programs.md](bounty-programs.md)):
they authorize like any entry while active, but take effect on the importer's
attestation instead of approvals, allow at most T1, and a target that only
program entries cover is never routed to platform sensors (an explicit
`platform` preference answers `PLATFORM_SENSOR_REFUSED`, `auto` stays on the
tenant's sensors). Each scan run links to a hashed snapshot of the scope in
force when it started.

## Port- and path-limited entries (RFC-065 §16.8)

An entry can be limited to ports and a protocol (`scope_targets.ports`,
`protocol`, migration `001910`; part of the entry's identity, never changed
after creation) and a URL entry with a path is limited to that path.
`scope.EntryMatches` is the one coverage test (`Target.Matches`, the
authority, the signer's ledger):

| Entry | Covers | Does not cover |
|---|---|---|
| `api.x.com` ports `8443` tcp | `api.x.com:8443`, `https://api.x.com:8443/…` | `api.x.com` (the whole host), `api.x.com:22`, `https://api.x.com/` (443) |
| `https://x.com/api*` | `https://x.com/api`, `…/api/v1?q` | `x.com`, `…/apiadmin`, `…/api/../admin`, `…/api/%2e%2e/admin`, another scheme, port or host |

A bare host is never covered by a port-limited entry, so a full port scan of
it is refused by the ordinary "no entry" path. When a job reaches the gate
with its tool and settings (`DispatchTargetsInput.Job`, always set by the
claim re-check), a target that only limited entries cover is refused
(`constrained`) unless `scope.ConstrainedJobRefusal` allows it: only tools
that stay on the target they are given (`naabu` and `httpx` for ports,
`httpx` for paths); a port list must lie within the allowed ports, `naabu`
needs one, and `top_ports` is refused. Crawlers, template scanners, DAST
tools and top-ports scans are allowed there only for a job claimed by a
sensor that enforces scope limits (`JobShape.LimitsEnforced`: the sensor
reports `scope.limits@1` and jobs are signed). The signed statement then
carries the limits and the sensor's task forwarder enforces them
(job-signing.md, "Scope limits"). For any other sensor the claim re-check
withholds such a job so an enforcing sensor can take it. A gate without the
check fails closed. The coverage report counts
only unlimited entries.

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
     (`needs_review`, `candidate`, `dependency`, `monitor_only`, `rejected`).
     **Takeover exception** (`internal/app/easm/takeover_gate.go`):
     a `dependency` asset is admitted to a scan that runs only the nuclei
     `takeover` templates (scanner nuclei, `tags` exactly `takeover`, no
     other template selection; `scan.IsTakeoverOnlyProbe`) while the DNS
     check has an open `dangling_cname` on that asset in the same tenant.
     It applies to scan create, clone, quick scan and scan runs; `POST
     /commands` and the dispatch gate keep the plain rule;
   - the name, or any parent domain of it, is one the tenant rejected (a
     rejected asset or a live rejection tombstone), unless a person
     confirmed this very asset. This covers a rejected name that was deleted
     and came back, and free text under a rejected name;
   - **one authority** (RFC-054 §4.2, `internal/app/scopeauth`): an
     internet-facing asset (domain, subdomain, IP, service, web endpoint,
     host, …), or typed text naming an internet host or public address, is
     not covered by an active scope entry of the tenant (a verified domain is
     proof only). Without a record that is
     `unattributed`; with a **confirmed** record it is `out_of_scope`:
     confirming an asset on its Ownership tab records ownership, it does not
     authorize active probes by itself. Private addresses and internal names
     are left to scan zones; repositories and cloud resources keep the
     record-only rule when they are inventory assets.

   Typed text that names no asset gets the same authority decision as an
   inventory asset; the act-scope check below asks the same `scopeauth`
   package, so a typed name and the same name in the inventory never
   disagree. Every refusal carries a structured code (RFC-054 §6.5:
   `rejected`, `needs_review`, `candidate`, `dependency`, `monitor_only`,
   `no_entry`, `deny_list`, `proof_required`, …); requests refused as a whole
   answer `TARGET_OUT_OF_SCOPE` with `details.refused[]` (`target`, `code`,
   `message`, `fixes`). The act scope runs first on those paths, so a
   restricted member never learns the state of an asset outside their data
   scope. The dry run (`POST /scope/check`) answers the same codes for typed
   targets and for inventory assets (`asset_ids`, checked by name); an asset
   the caller may not see, or that is not the tenant's, answers
   `out_of_data_scope` by its id only, whichever it is. The state is also
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
| Scan create, clone, import (`CreateScan`), quick scan, `POST /commands` | the request is refused as a whole (`TARGET_OUT_OF_SCOPE`, 400, the targets named with the generic reason) and audited (`scan.target_refused`). Exception: a create with `start_when_scope_approved` whose refused targets are all covered by pending entries is saved and started once they are approved, as the requester, with every gate checked again (RFC-054 §12.8, `internal/app/scan/scope_wait.go`) |
| Scan run: manual trigger, schedule, retry controller, workflow trigger | the target (direct or group member) is skipped with a run warning; a run left with nothing is refused (`ALL_TARGETS_UNCONFIRMED`) |
| `POST /scan-workflows/runs`, `trigger_pipeline`, coverage dispatcher, every validate command (re-checks, proof-of-fix, retests, attack-simulation safe-checks), connector scans | `ResolveDispatchTargets` refuses the target |

`GET /api/v1/assets/{id}/attribution` answers `active_checks_allowed` with the
same gate and names the reason in `active_checks_blocked_by`.

**Existing assets (rollout).** No data migration: the rule is evaluated at
dispatch, so an asset inside a scope target stays scannable
with no record, and adding a scope target takes effect on the next dispatch.
An internet-facing asset outside every scope entry is not probed, whether or not a person confirmed it (RFC-054: the
Ownership-tab confirmation no longer authorizes alone). Runs that skip such
targets say so in their warnings; `GET /assets/{id}/attribution` answers
`active_checks_blocked_by: out_of_scope`.

## Who calls it

| Path | Where | Notes |
|---|---|---|
| Scan trigger | `scan/targets.go` `resolveScanTargets` | Builds the candidates (direct targets, asset-group members by asset id, the scanner type gate, archived members, deduplication), then calls the gate once with the trigger options below. Zone routing, batching and pinning stay in the trigger (`planZoneDispatch`), as does the per-run cap after the checks. |
| `POST /scan-workflows/runs` | `pipeline/run_targets.go` | Typed targets; no assets. |
| Coverage dispatcher | `scancoverage/scheduler.go` `gateBatch` | Each candidate passes its asset id, so unconfirmed assets are skipped. |
| Every `validate` command | `validation/dispatcher.go` `CommandDispatcher.Dispatch` | Finding re-check (`POST /findings/{id}/validate`, proof-of-fix fallback, Jira "Done"), continuous retest (both checks), attack-simulation safe-check. |
| `POST /commands` | `scan/command_gate.go` | Member-created scan commands (RFC-040 group A). |

### Gate order and the trigger options

The checks run in one order on every path, each on what the previous ones kept;
a target is refused once, under the first check that refused it: the target
validator, scope exclusions, ownership, the act scope, the private-range rule
(trigger only, see below), the tier ceiling, zone routing. The act scope comes
before the tier ceiling, so an actor never learns the scope entries of a target
they may not scan.

The scan trigger sets options on `DispatchTargetsInput` where it legitimately
differs; each defaults to the strict behaviour every other path gets:

| Option | Why the trigger sets it |
|---|---|
| `AllowNonNetworkTargets` | Group members can be repositories or container images, which the target validator refuses as not network targets. Only the private-range rule stays: an internal address is refused while the tenant has no scan zone (`zone_none`, counted as `internal_outside_zones_target_count`). |
| `SkipZoneRouting` | The trigger routes, batches and pins per zone itself (`planZoneDispatch`) and refuses what no zone covers there. |
| `TakeoverOnly` | A nuclei scan of exactly the `takeover` tag may probe a dependency with an open dangling_cname (`IsTakeoverOnlyProbe`). |
| `ActScopeAssetsByID` | A group member is the asset: its act scope is decided by asset id, not also by its name as free text. |
| `MaxTargets` | Exclusions only remove: the trigger passes twice the per-run cap and caps what is left itself. |
| `Path` | Refusal logs name `scan_run`. |

A `DispatchAsset` with only `AlsoMatch` (no ids) is a typed target with more
names for the exclusion match: a direct target that is also a group member is
decided by name, and excluded when an address of the member is.

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
back to another probe of the same target. The
auto-retest scheduler logs the refusal and moves on.

## Re-check at claim

A probing job (scan, validate, retest, connector scan) can wait in the
queue while its scope changes: an exclusion is
added, a scope entry is removed or its tier lowered, an asset's ownership is
rejected, a scan zone is deleted or shrunk, or the actor's act scope is
revoked. So the gate runs again when a sensor gets the job
(`internal/app/command/scope_recheck.go`).

**One enforcement point.** The command service re-checks on every hand-out
path: the listing poll (`Poll`), claim-N (`Claim`) and the claim by id
(`Acknowledge`). Protocol v2 (`GET /api/v2/sensor/commands`, `POST
.../commands/{id}/claim`) and protocol v3 (`ClaimCommands`,
`TransitionCommand` claim; RFC-059, served through the v2 handler) reach
commands only through them.

**Same inputs as the dispatch.** Each command records, on create, what its
targets were gated with (`commands.dispatch_gate`, migration 001352, written
by the platform only and never sent to a sensor): the probe tier, whether the
stage is passive (only rejected names refused), and the act scope with the
user the job acts for. The claim calls `ResolveDispatchTargets` with that
record, the command's tenant, the targets named in its payload, the claiming
sensor (zone membership), `AllowNonNetworkTargets` unless the record says
the targets passed the full validator, and `SkipZoneRouting` when the
dispatch did not route over zones:

| Creator | Record |
|---|---|
| Workflow step (`scanrun` `QueueRunStep`, seeds and chained hops) | the stage's tier and passive flag (the tool's tier outside the stage catalog); act scope of the run actor (`runActor`) |
| Single-scanner run (`scan/trigger.go`, `scan/zones.go`) | the scanner's tier (`ProbeTier`); passive for a passive or takeover-only probe; act scope of the person who triggered it, else the scan owner |
| `POST /commands` | the tier of the scanner it names (`ProbeTier`, T1 for an unknown one), as `GateCommandPayload` checks it; act scope of the caller |
| Validate and retest commands (`validation.CommandDispatcher`, `CheckTarget`) | the full gate at t1, no act scope (`ProbeDispatchGate`); the zone routing that stamped `scan_zone_id` |
| `connector_scan` (`tenablesc.NewScanCommand`: scan runs and coverage batches) | the full gate at t1 outside every zone (`no_zone_routing`); a scan run adds the act scope of who triggered it, else the scan owner (`connectorDispatchGate`) |
| A scan command without a record (queued before the upgrade) | the baseline: passive, no tier, no act scope (exclusions, rejected names, the private-address and zone rules) |
| A validate, retest or `connector_scan` command without a record (queued before the upgrade) | its type's strict defaults (`StrictDispatchGateFor`): the full gate at t1, no act scope, zone routing as for its type (none for a connector scan); one whose targets cannot be read from its payload is refused with `GATE_RECORD_MISSING` (settled like `SCOPE_CHANGED`) and has to be created again |

Other commands without a record (health checks, config updates, content
refreshes, connector syncs) are not re-checked. A validate command names its
target as `target.address`; the claim reads it there. `AllowNonNetworkTargets` replaces
the validator with the private-range rule, as on the scan trigger (a
repository is dispatched by its asset name, which the validator refuses); an
internal address still needs a scan zone. A target that now routes to
another zone than the command's `scan_zone_id` (or into or out of every
zone) is refused as `zone_changed`. The re-check never asks more than the
dispatch did, so a job is refused only for a change.

**Outcome.** Refused targets are taken out of the job before it is handed
out: out of `targets`, `target` and `context.targets`, in the response and in
the stored payload (a conditional write on the pending command), so result
binding narrows too. A job left with no target is not handed out: it is
failed with `SCOPE_CHANGED: <target> (<code>); ...` (a conditional write on
the pending command, so a second or concurrent claim records nothing), and
what waits on it is settled as on a sensor's failure
(`CommandHandler.OnCommandFailed`, the `command.FailureObserver`): its scan
step fails with `SCOPE_CHANGED` (failure class `scope`, not retried), a
validation run is finished as failed with that code, a retest is settled
(unknown). A
claim by id of such a job answers `command-claimed` (409 in v2, the same
problem in v3), which tells the sensor to drop it; claim-N and the listing
poll simply leave it out. The response shapes do not change.

**Fail closed.** A gate that cannot decide (a lookup error, the gate not
wired yet at startup) withholds the job: it is not handed out, it stays
pending for a later claim, and a claim by id answers `command-claimed`. A
lookup failure is usually short; failing the job would lose work to a
blip, and the command TTL (`COMMAND_EXPIRED`) ends a job that can never be
checked.

**Cost.** Commands with the same record (the chunks of one step) share one
gate call; a claim with only commands that are not re-checked makes none. Each refusal is
logged (`SECURITY: ... at claim`) with the refusal codes.

## Act scope: who may scan what

Decision D9 limits scan targets to what the actor may
act on. The rule lives in `internal/app/actscope` and uses one helper,
`datascope.Enforcer.CanActOnAssets`. That helper resolves through
`ResolveFor`, so an administrator and any holder of a `has_full_data_access`
role (not through an API key) are unrestricted.

| Actor | Inventory asset (a typed name that is an asset, or a group member) | Free text that is not an asset |
|---|---|---|
| Restricted member | only assets in their data scope | refused |
| Unrestricted (admin, a `has_full_data_access` role, member of a fail-open organization with no scope row, system) | any asset of the tenant (the ownership gate still requires scope authority) | only if the tenant's scope authority covers it: an active scope entry (`scopeauth`); exclusions still apply |

**The actor** is the request's caller. With no user in the context (a
scheduled run, a workflow action) the actor is the scan owner
(`scans.created_by`, resolved like `ForUser`). With neither, the actor is the
system, which is unrestricted.

| Path | Behavior |
|---|---|
| Scan create, quick scan | refused as a whole (`TARGET_OUT_OF_SCOPE`, 400, with each target and its reason) |
| Scan update | refused when the editor may not scan every direct target of the scan |
| Scan run (manual, scheduled, workflow) | out-of-scope direct targets and group members are skipped, with a run warning; a run left with nothing is refused |
| `POST /scan-workflows/runs`, `trigger_pipeline` | `ResolveDispatchTargets` with `ActScope: true`; `triggered_by` is the fallback actor; any refused target fails the run |
| `POST /commands` | refused as a whole |

Every lookup error refuses (fail closed). A dispatch that asks for the check
when none is wired gets `ErrActScopeUnavailable`; the scan trigger always asks,
so an unwired exclusion filter, ownership gate or act-scope check stops a run.

**Live impact.** A scan of free text that no scope entry or verified
domain covers has nothing to scan. Add the ranges and domains to Scoping ›
Targets first.

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
