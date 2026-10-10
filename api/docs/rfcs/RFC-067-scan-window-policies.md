# RFC-067: Scan window policies

| | |
|---|---|
| Status | Accepted (delegated, 2026-10-09; decisions W1–W14 adopted as recommended, §11). P0 in implementation |
| Scope | api (`pkg/domain/scanwindow`, `internal/app/scanwindow`, command claim, scan trigger and scheduler, migrations), web (Settings › Scan windows, asset page, New Scan, run timeline) |
| Architecture | [scan-windows.md](../architecture/scan-windows.md) |
| Related | RFC-023 K3 (per-zone scan and blackout windows), RFC-030 (claim-time chunks, leases), RFC-046 (Scan → Run → Task), RFC-054 (scope tiers T0/T1/T2), RFC-065 §12 (program testing windows), [step-up-reauth.md](../architecture/step-up-reauth.md), [job-signing.md](../architecture/job-signing.md) |
| Replaces | Scan freeze windows (`scan_freeze_windows`, `/api/v1/scan-freeze-windows`, `scans:freeze:override`, `override_freeze`); the testing-window check inside program rules |

## 1. Summary

Organizations need to say **when** scans may touch which assets:

1. *"Production assets labelled `business-hours` may only be scanned Monday to
   Friday, 09:00–17:00 Europe/Berlin."* (an **allow** window for a label)
2. *"Nothing active runs during the change freeze from 20 to 27 December, or
   in zone DMZ every Sunday 02:00–06:00."* (a **blackout** window; today's
   freeze windows)
3. *"This bug-bounty program allows testing only on weekdays."* (a program's
   testing windows, RFC-065 §12; third-party terms)

Three real cases, one model: a **scan window policy** has a **selector**
(which targets it governs), a **kind** (allow or blackout), a **schedule**
(weekly slots and dated one-offs in an IANA time zone) and an **effect tier**
(all tools, or only active and intrusive ones). Program testing windows are a
**source** of policies, not a second mechanism. One evaluator in Go decides,
for a target at an instant, whether work may run, why not, and when it next
may. Dispatch applies it per target at claim time: targets inside their
windows go, the others wait; a run whose targets can never open is refused
when it is created.

## 2. Problem

Today three partial mechanisms exist and none covers case 1:

| Mechanism | What it does | Gap |
|---|---|---|
| Freeze windows (migration 001115) | blackout for the whole organization or one zone; claim-time SQL predicate; scheduled runs deferred; other triggers refused with 409 unless `override_freeze` | no allow windows; no selection by label, group, type, criticality, unit, scope entry; a manual run is refused instead of waiting; the per-run override has no time box or second factor |
| Program testing windows (RFC-065 §12) | allow windows inside program rules; the claim withholds jobs outside them | a scheduled run outside the window is **skipped** (not deferred); a withheld job stays at the head of the claim queue and is re-read on every poll, so 100 of them starve every other job of the tenant (the candidate window is at most 100); separate code and semantics from freezes |
| RFC-023 K3 | names per-zone scan and blackout windows | never designed |

## 3. Goals and non-goals

Goals:

- One model and one evaluator for allow and blackout windows, selected by any
  of: asset tags (labels), asset groups, asset types, asset criticality,
  business units, scope entries, scan zones, bug-bounty programs.
- Most restrictive wins, deterministically, with an explanation ("why can't
  this run now; next opening at …").
- Enforcement per target at dispatch, for every command path; waiting instead
  of refusing; scheduled runs deferred, never skipped; impossible runs refused
  at creation.
- A defined behaviour when a window closes under a running task.
- An emergency override that is narrow, time-boxed, audited, notified and
  needs a fresh second factor; program windows can never be overridden.

Non-goals (P0):

- Per-sensor windows (a sensor's own local policy already refuses jobs;
  RFC-040 §5.7).
- Calendar imports (iCal) and holiday calendars. A one-off blackout covers a
  holiday.
- Windows for collection, connector syncs, ingest and health checks: they
  send no traffic to targets and are never held.
- Platform-wide windows. There is deliberately **no** platform-admin switch
  (§8).

## 4. Model

### 4.1 Policy

`scan_window_policies` (tenant-owned):

| Field | Meaning |
|---|---|
| `name`, `description`, `enabled` | |
| `kind` | `allow`: matching targets may be scanned only inside the windows. `blackout`: matching targets are never scanned inside the windows. |
| `min_tier` | The lowest probe tier the policy governs (RFC-054): `0` every tool, `1` active and intrusive tools (default; passive and OSINT work runs any time), `2` intrusive tools only. |
| `selector` | §4.2. Empty: every target of the organization. |
| `timezone` | IANA name (`Europe/Berlin`); the weekly slots are wall-clock times there. |
| `slots` | Weekly slots: ISO days (1 Monday … 7 Sunday), `start`, `end` (`HH:MM`). An end not after the start runs past midnight (22:00–06:00); equal times mean 24 hours from the start. At most 14. |
| `one_offs` | Dated windows: `starts_at`, `ends_at` (instants), at most 31 days each, at most 20. |
| `grace_minutes` | When a window closes under running work (§6.4): how long the running chunk may continue. 0–240, default 15. |
| `rate_limit_rps` | Allow only, optional: request-rate cap delivered to jobs on matching targets while inside the window. |
| `max_concurrent` | Allow only, optional: at most this many jobs on matching targets run at once. |

A policy needs at least one slot or one-off. Caps: 50 policies per
organization.

### 4.2 Selector

Dimensions: `tags`, `asset_group_ids`, `asset_types`, `criticalities`,
`business_unit_ids`, `scope_target_ids`, `scan_zone_ids`, `program_ids`.
Within a dimension the values are alternatives (any of); across dimensions
all given dimensions must match (`tags: [prod]` and `criticalities:
[critical]` selects critical assets labelled prod). Every id must be one of
the organization's own objects when the policy is saved.

How a target (host, IP, CIDR, host:port, URL) meets a dimension:

| Dimension | Matches when |
|---|---|
| tags, groups, types, criticality, units | an asset of the organization, not deleted, is the target: same name (case-insensitive) as the target or as the host of a URL / host:port; or, for a CIDR target, an IP asset inside the range. A CIDR therefore carries the restrictions of every asset in it. A target that is no asset matches none of these dimensions. |
| scope entries | the entry covers the target (the scope matcher; `*.x` covers `x`; program exclusions apply to program entries) |
| scan zones | the job is routed to the zone (`commands.scan_zone_id`) |
| programs | an in-effect entry of the program covers the target |

### 4.3 Sources

The evaluator works on **sources**. A policy is a source. Each bug-bounty
program that covers a target and states testing windows is a source too:
kind `allow`, tier 0 (every tool, as RFC-065 §12 enforced it), its windows
each in its own time zone, grace 0, rate from the program's rules, and
**not overridable**. Program windows stay where they are edited (the
program's rules); only their evaluation moves.

### 4.4 Evaluation

For one target, one job tier and one instant, the governing sources are the
enabled sources that select the target and whose `min_tier` is at or below
the job's tier, minus those suspended by an active override (§8).

```
open(t) = for every governing allow source: t is inside one of its windows
          and no governing blackout source has a window containing t
```

Most restrictive wins: two allow policies intersect (both must be open), a
blackout subtracts from everything. For a job with several targets, the job
may run when every target may; dispatch splits jobs instead (§6.1).

**Next opening.** The earliest instant from now at which `open` holds:
the evaluator lists every window boundary of the governing sources within a
horizon of 400 days and tests each in order. None within the horizon:
**never opens** (an empty intersection, e.g. Monday-only and Saturday-only
allow policies on one asset, or a one-off allow window inside a longer
blackout).

**Explanation.** Every decision carries the blocking sources, each with its
kind, origin (policy or program), and when it stops blocking, plus the next
opening and, while open, when it closes. The console and the API show the
same structure.

**Time.** Windows are occurrences computed in their time zone from local
dates (`time.Date`), so the "is it open" test and the "next opening" search
use the same intervals. A wall-clock time the clocks skip is moved forward by
the gap (02:30 on the day clocks go forward reads as 03:30), so a slot over
the skipped hour is that much shorter; a time the clocks repeat reads as the
later pass, so a slot over the repeated hour lasts an hour longer. Time zones come
from the Go tz database embedded in the binary (`time/tzdata`), so evaluation
never depends on the host image. A source whose time zone cannot be loaded
fails closed: an allow source is never open and a blackout source is always
active.

### 4.5 Job tier

The tier a job is judged at: the tier recorded in its dispatch gate (the
stage's tier for workflow steps); else the tool's tier; `validate`,
`retest` and `connector_scan` jobs are active (tier 1) unless their tool is
passive; collection, syncs, health checks, content refresh and config jobs
are never held.

## 5. Where it is decided (one evaluator, in Go)

The freeze predicate decided in SQL so the console and dispatch could not
drift. Selection by labels, groups, units, scope entries and programs needs
lookups that do not belong in the claim statement, so the decision moves to
Go, and drift is prevented the same way: **one evaluator**
(`pkg/domain/scanwindow`) and **one resolver** (`internal/app/scanwindow`)
are called by the claim, the trigger, the scheduler, the closing-window
controller and every read API. Nothing else decides windows.

## 6. Enforcement

### 6.1 At claim (authoritative)

Poll, claim-N and claim-by-id (`Acknowledge`) run the window hold after the
scope re-check, for every candidate command of the tenant:

- **All targets open:** the job goes; its delivered copy carries the
  smallest rate cap of the governing open allow sources (with the program
  rules' cap), and the job records the policies it runs under (for the
  concurrency cap).
- **None open:** the job is **deferred**: `scheduled_at` moves to the next
  opening (at most 1 hour ahead, so policy and asset changes are picked up),
  `window_hold` records the blocking sources and the next opening for the
  console, and `expires_at` moves so waiting never counts against the job's
  time to live. A deferred job is not a candidate again until then, so held
  jobs can no longer crowd the claim window (the starvation in §2).
- **Some open:** a workflow chunk or a scan job (it belongs to a run step) is
  **split**: the stored job keeps the open targets and goes; a sibling job of
  the same step with the waiting targets is created deferred. The step
  settles when all its jobs have (the step already counts its chunks). Both
  writes happen in one transaction and only while the job is still pending
  with the payload that was read. Other jobs (a validation, a retest) are
  answered for as a whole and wait until every target is open.
- **Never opens** (a policy changed after the run was created): the job is
  deferred one hour at a time with `window_hold.never = true` and without
  extending its expiry, so it ends at its time to live unless someone fixes
  the policy; the run timeline says so.
- **Concurrency cap reached** for a governing allow source: the job waits one
  minute. The cap counts acknowledged and running jobs that recorded the
  policy; two sensors claiming at the same instant can exceed it by their
  batch (a soft cap, documented).
- **Lookup failure:** the job is withheld for this poll (fail closed), as the
  scope re-check does.

Deferral also moves the run's deadline to the next opening plus the run's own
timeout, and the unclaimed-run reaper ignores runs that have a job waiting
for a window. Neither may end a run for waiting where the organization told
it to wait.

### 6.2 At run creation (trigger)

After target resolution and zone routing, the trigger evaluates every target
at the scan's highest tier:

- a target that **never opens** refuses the trigger (`409
  SCAN_WINDOW_NEVER_OPENS`, naming the targets and the sources, recorded as a
  blocked run);
- otherwise the run is created; the response and the run context carry the
  waiting targets and their next openings (`window_waits`).

Manual runs are no longer refused because a blackout is active: they wait,
like program-window runs did. The New Scan dialog and the scan preview show
before saving which targets will wait and until when.

### 6.3 Scheduled runs (defer, never skip)

The scheduler evaluates the scan's targets before triggering an occurrence:

- **no target may run now:** `next_run_at` moves to the earliest next opening
  of any target (compare-and-set, as for freezes), audited as
  `scan_window.deferred`; occurrences inside one closed period become one
  run at the opening;
- **some or all may run:** the run is created; waiting targets wait (§6.1);
- **never opens:** the occurrence is recorded as a blocked run, and the
  schedule continues.

This fixes the gap where a scheduled run outside a program window was skipped.

### 6.4 When a window closes under running work

Decision W7: **stop dispatching new chunks at once; let the running chunk
finish within a bounded grace; then stop it and queue it again for the next
opening.**

The closing-window controller runs every minute over acknowledged and running
probing jobs of organizations that have policies or program windows. For a
job whose targets are no longer open it records when it first saw that
(`window_closed_at`). Once the smallest `grace_minutes` of the blocking
sources has passed (program sources: 0), it returns the job to pending under
a new lease epoch, deferred to the next opening (`window_hold` says why). The
sensor holding it is told to stop in its next heartbeat (the cancel list of
re-queued commands), and anything the old holder reports afterwards fails the
lease fence. The chunk runs again from the start at the next opening; a scan
chunk is idempotent. A job whose window opens again before the grace ends is
left alone.

Why not stop at once: tools that are killed mid-flight leave half-written
results and, for some, open connections; most chunks finish within minutes.
Why not let it run: a chunk can last hours, and "only during business hours"
must mean it.

## 7. Signing and the sensor

Windows decide **when** the platform hands out a job, not **what** the job
may do: the targets, tool, tier and configuration the signer signs are the
same inside and outside a window. The signer ledger therefore does not change
(decision W10). A rate cap from a window policy changes the delivered
`rate_limit` before signing, exactly as the program rate cap does, so the
signature covers it. A later phase may add a signed `not_after` (window close
plus grace) so a sensor stops a job on its own clock; that is defence in
depth and not needed for the guarantee, which the claim and the closing-window
controller give.

## 8. Overrides

An emergency override suspends policies for a short time:

- `POST /api/v1/scan-window-overrides` with `policy_id` (or none: every
  policy of the organization), `reason` (10–500 characters), `duration_minutes`
  (15–1440) and a fresh authenticator code (`totp_code`).
- Permission `scans:windows:override` (owner and admin by default; it
  replaces `scans:freeze:override`). The code must be a current TOTP of the
  caller (`VerifyFreshTOTP`): an account without an authenticator cannot
  override (`WINDOW_OVERRIDE_NEEDS_TOTP`); a wrong code counts toward lockout.
- **Never** suspends a program source: program windows are a third party's
  terms (decision W9).
- Audited `scan_window.override_started` (high) with the reason, the policies
  and the end; every owner and admin is notified in the app and on the
  security-alert channel. Revoking early (`DELETE …/{id}`, same permission, no
  code) is audited `scan_window.override_revoked`; expiry needs no action.
- Starting or ending an override releases the organization's deferred jobs for
  re-evaluation at once.
- There is **no platform-admin switch**: the platform cannot turn windows off
  for an organization. A platform operator who must stop scanning everywhere
  uses the existing sensor and dispatch controls, not this model.

The former per-run `override_freeze` flag and the `freeze_override` columns
are removed: an override is now a visible, time-boxed state of the
organization, not an invisible attribute of one run.

## 9. API

| Route | Permission | |
|---|---|---|
| `GET /api/v1/scan-window-policies` (`?enabled=`), `GET /{id}` | `scans:read` | each policy with `open_now`, `next_change_at` for its own windows |
| `POST /`, `PATCH /{id}`, `DELETE /{id}` | `scans:windows:manage` | audited `scan_window_policy.created/updated/deleted` |
| `POST /api/v1/scan-window-policies/preview` | `scans:read` | a draft policy: matching assets (count and the first 50) and the next 5 openings |
| `POST /api/v1/scan-windows/preview` | `scans:read` | `targets` and/or `asset_ids`, optional `tier` and `scan_zone_id`: per target the decision and explanation (§4.4); an asset outside the caller data scope is 404. Used by the asset page and the scan dialog. |
| `GET /api/v1/scan-window-overrides`, `POST /`, `DELETE /{id}` | `scans:read` / `scans:windows:override` | §8 |

The scan run's tasks carry `window_hold` (`reason`, `next_open_at`, blocking
sources, `never`), the run carries `window_waits` (the targets that waited
when it started), and the zone routing and workflow previews carry
`windows` (which targets would wait, which never open). Every route is tenant-scoped from the token; another
organization's policy, override or asset answers 404, and a selector id that
is not the organization's answers 422 without saying whether it exists
elsewhere.

## 10. Migration (one step, no compatibility layer)

- `scan_window_policies` and `scan_window_overrides` are created; every freeze
  window becomes a blackout policy (tier 1, selector empty or its zone, its
  time zone, its weekly slot or one-off, enabled as it was).
- `scan_freeze_windows`, `commands.freeze_override` and
  `scan_runs.freeze_override` are dropped; `commands.window_hold`,
  `commands.window_closed_at` and `commands.window_policy_ids` are added
  (nullable, no rewrite).
- `scans:freeze:override` becomes `scans:windows:override` in every role and
  API key that held it (migration 001761); `scans:windows:manage` is granted
  to owner and admin (001760).
- `/api/v1/scan-freeze-windows` and the `override_freeze` trigger field are
  removed; Settings › Scan freeze windows becomes Settings › Scan windows.
- Down migrations restore the freeze table from the blackout policies it can
  represent (no tags or other dimensions, one schedule entry) and the old
  permission.

## 11. Decisions

| # | Decision | Why |
|---|---|---|
| W1 | One policy model with allow and blackout kinds; freeze windows migrate into it and their API is removed | owner: no duplicate mechanism; young product, one-step upgrade |
| W2 | Program testing windows are a source, edited in the program | program terms belong to the program; one evaluator |
| W3 | Selector: AND across dimensions, any-of within | expresses "critical and prod" without a query language |
| W4 | Most restrictive wins: allow sources intersect, blackouts subtract | an organization's restriction is never loosened by another policy |
| W5 | Per-policy tier (all / active+intrusive / intrusive) | passive OSINT does not touch the target; some owners want even that limited |
| W6 | Decision in Go at claim; deferral by `scheduled_at` | selectors need lookups; deferral removes held jobs from the claim window |
| W7 | Window closes mid-task: no new chunks, running chunk gets the policy's grace (default 15 min, programs 0), then re-queued for the next opening | §6.4 |
| W8 | Manual runs wait instead of being refused; only never-opening targets refuse | owner: outside → job waits; one behaviour |
| W9 | Override: owner/admin permission, fresh TOTP, reason, 15 min–24 h, audited, notified; never for program windows; no platform switch | third-party terms; security first |
| W10 | No signer change | windows are dispatch time, not authorization (§7) |
| W11 | Scheduled runs defer to the next opening, coalesced | fixes the skip from RFC-065 §12 |
| W12 | Mixed jobs split per target at claim for run steps; other jobs wait whole | in-window targets go; validation and retest are tied to one job |
| W13 | Rate cap delivered like the program cap; concurrency cap is soft | simple, same delivery path |
| W14 | New permission `scans:windows:manage` (owner, admin) | windows govern the whole organization's scanning |

## 12. Threat model

| Threat | Control |
|---|---|
| A member scans outside a window by flag or crafted request | no client field affects windows; the claim decides for every path; the only bypass is an override (§8) |
| Cross-tenant reads or influence | policies, overrides and the resolver's lookups are tenant-scoped; a selector naming another organization's group, unit, entry, zone or program is refused on save; the claim never evaluates another tenant's command; tests cover each |
| A stolen session overrides windows | permission plus a fresh TOTP code per override, time box ≤ 24 h, high-severity audit and notifications to all owners and admins |
| Breaking a program's terms | program sources cannot be overridden, grace 0, `min_tier` 0 |
| Platform operator disables windows | no such switch exists |
| Dispatch starvation or a poll that never ends | deferral takes held jobs out of the claim window; caps on policies, slots and one-offs; evaluation per poll is bounded by the candidate window (≤ 100 jobs) |
| Evaluation failure lets work out | fail closed everywhere: lookups withhold, an unknown time zone blocks |
| A waiting run is reaped or times out | deadline moved with the deferral; unclaimed reaper skips window-held runs |

## 13. Phases

| Phase | Content |
|---|---|
| P0 | This RFC; model, evaluator, resolver, migration from freeze windows; claim hold with split and deferral; trigger refusal for never-opening targets; scheduler deferral; closing-window controller; overrides; API; Settings › Scan windows, asset page, New Scan and run timeline in the console (en, vi) |
| P1 | Signed `not_after` on delivered jobs; per-sensor windows from RFC-023 K3 if a real case appears; holiday calendars if asked |
