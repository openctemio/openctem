# Scan windows

When may scans touch which targets. Design and decisions:
[RFC-067](../rfcs/RFC-067-scan-window-policies.md).

A **scan window policy** of an organization says that the targets it selects
may be scanned only inside its windows (`allow`), or never inside them
(`blackout`). Bug-bounty programs that state testing windows
([bounty-programs.md](bounty-programs.md)) are evaluated as allow policies
that cannot be overridden. One evaluator decides for every caller: the claim,
the trigger, the scheduler, the closing-window controller and the API.

## Data

`scan_window_policies` (tenant-owned, at most 50 per organization):

| Column | |
|---|---|
| `kind` | `allow` or `blackout` |
| `min_tier` | lowest probe tier governed: 0 every tool, 1 active and intrusive (default), 2 intrusive |
| `selector` (jsonb) | `tags`, `asset_group_ids`, `asset_types`, `criticalities`, `business_unit_ids`, `scope_target_ids`, `scan_zone_ids`, `program_ids`; AND across dimensions, any-of within; `{}` selects every target |
| `timezone` | IANA zone of the weekly slots |
| `slots` (jsonb) | `[{"days":[1..7],"start":"HH:MM","end":"HH:MM"}]`, at most 14; an end not after the start runs past midnight; equal times are 24 hours |
| `one_offs` (jsonb) | `[{"starts_at","ends_at"}]`, at most 20, each at most 31 days |
| `grace_minutes` | 0–240 (default 15): how long a running chunk may continue after its window closes |
| `rate_limit_rps`, `max_concurrent` | allow policies only, optional caps inside the window |

`scan_window_overrides`: a time-boxed suspension of one policy (`policy_id`)
or of every policy of the organization (`NULL`), with `reason`, `starts_at`,
`ends_at` (at most 24 hours), `created_by`, `revoked_at`, `revoked_by`.

`commands` columns written by the window hold:

| Column | |
|---|---|
| `window_hold` (jsonb) | why a pending job waits: `next_open_at`, `never`, `blocking` (`source_id`, `name`, `kind`, `origin`), `checked_at`. Cleared when the job is handed out. |
| `window_closed_at` | when the closing-window controller first saw a running job outside its windows |
| `window_policy_ids` | the allow policies a handed-out job runs under (concurrency cap) |

Selector ids are checked against the organization's own groups, business
units, scope entries, zones and programs when a policy is saved; an unknown
id answers 422 whether or not it exists in another organization.

## Evaluator (`pkg/domain/scanwindow`)

Pure Go, no I/O.

- `Source`: kind, `MinTier`, slots (each with its `*time.Location`), one-offs,
  grace, caps, `Overridable`, origin (`policy` or `program`).
- `Decide(sources, tier, now) Decision`: the governing sources are those with
  `MinTier <= tier`. `Open` holds when every governing allow source has a
  window containing `now` and no governing blackout source does. The decision
  lists the blocking sources (each with when it stops blocking), the next
  opening (`NextOpen`), `Never` (no opening within 400 days), and while open
  `ClosesAt` and the caps of the governing allow sources.
- Windows are occurrences built from local dates with `time.Date`, so the
  open test and the next-opening search use the same intervals. Daylight
  saving: a slot inside the skipped hour starts at the first instant after
  it; a slot over the repeated hour lasts the longer real time.
- The tz database is embedded (`time/tzdata`). A source whose zone does not
  load fails closed (allow never open, blackout always active).

## Resolver (`internal/app/scanwindow`)

`Resolve(ctx, tenantID, targets, zoneID)` returns the sources governing each
target. Per call it reads the enabled policies and the active overrides of
the tenant (one query each); only when a policy uses those dimensions does it
read the assets matching the targets (one query: exact name of the target or
of its host, and IP assets inside a CIDR target, with their tags, groups,
units, type and criticality) and the scope authority (entries and programs
covering each target). Programs covering a target that state testing windows
become program sources. Every read is tenant-scoped; any read error is
returned and the caller fails closed.

## Enforcement

### Claim (`internal/app/command/window_hold.go`)

Poll, claim-N and claim-by-id run the hold after the scope re-check. For
each pending candidate of the tenant that is probing work (scan, validate,
retest, connector scan; tier from the dispatch gate, else the tool):

| Targets | Outcome |
|---|---|
| all open | handed out; the delivered `rate_limit` is capped by the governing allow sources; `window_policy_ids` recorded |
| none open | deferred: `scheduled_at` = next opening (at most 1 h ahead), `window_hold` written, `expires_at` pushed by the wait; the run's deadline moves to the opening plus its timeout |
| some open, job of a run step | split in one transaction: the job keeps the open targets and goes; a sibling job of the same step with the waiting targets is created deferred |
| some open, other jobs | deferred as a whole until every target is open |
| never opens | deferred 1 h at a time with `never: true`, expiry not pushed |
| concurrency cap reached | deferred 1 minute |
| lookup error | withheld for this poll |

Every write applies only while the job is still pending with the payload
that was read. Deferred jobs are not candidates (`scheduled_at` is in the
poll predicate), so they never crowd the claim window. The unclaimed-run
reaper skips runs with a job that has `window_hold`.

### Trigger (`internal/app/scan/windows.go`)

After targets are resolved and routed, every target is evaluated at the
scan's highest tier. Any target that never opens refuses the trigger with
`409 SCAN_WINDOW_NEVER_OPENS` (a blocked run naming targets and sources).
Otherwise the run is created and `window_waits` (targets, next openings,
sources) goes into the run context and the response. A manual run during a
blackout waits; it is not refused.

### Scheduler

Before an occurrence, the scan's targets are evaluated. When none may run
now, `next_run_at` moves to the earliest next opening
(`DeferScheduledRun`, compare-and-set; audit `scan_window.deferred`, metric
outcome `deferred_window`). Otherwise the run is created and waiting targets
wait at claim.

### Closing windows (`internal/infra/controller/scan_window_closing.go`)

Every minute, for organizations with policies or program windows, the
acknowledged and running probing jobs are evaluated. A job outside its
windows gets `window_closed_at`; once the smallest grace of its blocking
sources has passed (programs: 0) it is returned to pending, unpinned,
deferred to the next opening, without counting a dispatch attempt. The old
holder finds it in the heartbeat cancel list and its later reports fail the
lease fence. A job back inside its windows has `window_closed_at` cleared.

## Overrides

`POST /api/v1/scan-window-overrides` with `scans:windows:override` (owner and
admin), `reason`, `duration_minutes` (15–1440), optional `policy_id` and a
fresh TOTP code (`totp_code`, `VerifyFreshTOTP`; no authenticator:
`WINDOW_OVERRIDE_NEEDS_TOTP`, wrong code: `WINDOW_OVERRIDE_INVALID_CODE`).
Program sources are never suspended. Audit `scan_window.override_started`
(high) and `scan_window.override_revoked`; in-app notification to every owner
and admin, and the security-alert channel. Creating or revoking releases the
tenant's deferred jobs (`scheduled_at` cleared where `window_hold` is set) so
they are evaluated again on the next claim. There is no platform-level
switch.

## API

| Route | Permission |
|---|---|
| `GET /api/v1/scan-window-policies`, `GET /{id}` | `scans:read` |
| `POST /api/v1/scan-window-policies`, `PATCH /{id}`, `DELETE /{id}` | `scans:windows:manage` |
| `POST /api/v1/scan-window-policies/preview` | `scans:read` |
| `POST /api/v1/scan-windows/evaluate` | `scans:read` |
| `GET /api/v1/scan-window-overrides` | `scans:read` |
| `POST /api/v1/scan-window-overrides`, `DELETE /{id}` | `scans:windows:override` |

Policy writes are audited `scan_window_policy.created`, `.updated` (before
and after), `.deleted`; a policy change also releases deferred jobs.

## Console

- Settings › Policies › Scan windows: the policies, create and edit with a
  live preview (matching assets, next openings), the active overrides.
- Asset page: the effective window of the asset (open now or next opening,
  and the governing policies).
- New Scan and the scan preview: which targets will wait and until when; a
  target that never opens is named before saving.
- Run timeline: a job waiting for a window shows the policy and the opening.

## Tests

- Evaluator table tests: time zones, DST forward and back, overnight slots,
  one-offs, allow intersection, blackout precedence, tiers, empty
  intersection, unknown time zone.
- Resolver: every selector dimension, CIDR containment, URL hosts, programs.
- Database: policy and override repositories (tenant isolation), the claim
  hold (defer, split, cross-tenant), the closing-window requeue, deferral of
  scheduled runs, migration up/down/up on a restore of live data.
- HTTP: authz (permissions, step-up code, program windows not overridable),
  route classification.
