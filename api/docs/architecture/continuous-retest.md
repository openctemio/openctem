# Continuous retest (RFC-039)

> How OpenCTEM re-checks findings so their status stays true: a fixed issue is
> closed and a regression reopened without a person. Design and decisions:
> [RFC-039](../rfcs/RFC-039-continuous-retest.md). Related:
> [validation engine](validation-engine.md) (the `validate` command transport a
> retest reuses), [finding retest checks](finding-retest-checks.md) (a custom
> check a person attaches to a finding, run by its retest).

## What a retest is

A retest re-runs **the exact check that produced a finding** — in Phase 1 the
nuclei template (`findings.rule_id`) against the finding's own target (the
origin of its matched-at URL, see below) — plus a
**reachability probe** of the same target, and settles the finding:

A non-match is **not** proof of a fix ([RFC-057](../rfcs/RFC-057-finding-evidence-and-retest.md) R2).
The re-run's own evidence (the HTTP exchange it reports, `evidence_items`)
decides:

| Re-run | Attempt evidence | Outcome (`reason_code`) | Finding |
|---|---|---|---|
| matched | any | `still_vulnerable` (`matched`) | open: unchanged · `resolved` → `confirmed` (regression) · `fix_applied` → `in_progress`; validation `reproducible`, observation `present` |
| no match | request to the finding's endpoint, answered 1xx–4xx except 401/403/407/429, with no edge marker | `confirmed_fixed` (`not_matched`) | status unchanged, validation `not_reproducible` ("verified fixed — awaiting confirmation"); → `resolved` (`fixed` / `retest`) only with `settings.retest.auto_resolve`; `resolved` stays |
| no match | any answer carrying a CDN or WAF challenge or block marker (a vendor header or error page), or a throttle with a vendor marker | `inconclusive` (`edge_blocked`), never a fix | unchanged |
| no match | origin 401 / 403 (no edge marker), exposure-class platform template, second sighting (the previous completed retest, at least an hour earlier, was the same origin refusal) | `confirmed_fixed` (`access_denied`), "access now denied by the server" | as for any confirmed fix |
| no match | origin 401 / 403, exposure-class template, first sighting, or less than an hour after the first | `inconclusive` (`access_denied`) | unchanged |
| no match | origin 401 / 403, any other class | `inconclusive` (`access_denied`), "access denied: cannot confirm the fix" | unchanged |
| no match | answered 429 (no edge marker) | `inconclusive` (`blocked`) | unchanged |
| no match | answered 407, or a 3xx to another path (a login page) or with no recorded target, for a class other than exposure | `inconclusive` (`auth_changed`) | unchanged |
| no match | answered 5xx | `inconclusive` (`server_error`) | unchanged |
| no match | request to another URL (a sensor that reports no per-request results) | `inconclusive` (`endpoint_mismatch`) | unchanged |
| per-request results, the finding's endpoint matched | any | `still_vulnerable` (`matched`) | as above |
| per-request results, the endpoint did not match, another path matched | any | `still_exposed_elsewhere` (`matched_elsewhere`) | unchanged (never closed, never reopened); the other paths are named in the reason and kept on the retest activity (`other_paths`) |
| per-request results, nothing matched, the endpoint was not requested | any | `inconclusive` (`endpoint_mismatch`) | unchanged |
| per-request results, nothing matched, the endpoint answered | its own answer | the rows above for a non-match (`confirmed_fixed`, `edge_blocked`, `access_denied`, `blocked`, `auth_changed`, `server_error`, `unreachable`); the line's edge state (`challenged`, `blocked`, `rate_limited`, from the sensor's edge detector) is `edge_blocked`, and so is an edge marker the platform reads in the recorded exchange at the same endpoint when the line names none (sdk-go sensors send no edge state), and an origin 401/403 follows the access-denied rules of the finding's class | as above |
| no match | no response | `inconclusive` (`unreachable`) | unchanged |
| no match | none, target answered the probe | `not_reproduced` (`no_endpoint_proof`) | unchanged |
| no match | none, target did not answer | `inconclusive` (`unreachable`) | unchanged |
| error / no result / deadline passed | any | `inconclusive` (`error`, `no_result`) | unchanged |
| tool: check not in the sensor's template set | any | `inconclusive` (`template_not_found`) | unchanged |
| tool: check excluded by the sensor's safety policy | any | `inconclusive` (`excluded_by_policy`) | unchanged |
| tool: ended without judging the item | any | `inconclusive` (`no_verdict`) | unchanged |

**A sighting after the check.** A confirmed fix is applied only if no scan sighted the finding (`last_seen_at`) or reopened it after the check command completed; the settlement checks this under the finding's row lock. Otherwise the retest is recorded `inconclusive` (`template_changed`, "the finding was sighted again after the check ran") and the finding does not move.

**Edge answers and access denied.** The platform reads the recorded response
(status, headers, body) with the edge detector of ctis (`edgeprotect`).
A challenge or block page of a CDN or WAF says nothing about the service, so
it is `edge_blocked` (the message names the vendor and asks to allow the
scanner at the edge, see the edge-protection guidance) and is never a fix. A
bare 403 with no marker is the origin's own answer. For an exposure-class
platform template the class comes from the template's own tags (such as
`exposure`, `exposed-panel`, `swagger`, `config`, `backup`, `debug`,
`listing`, `disclosure`; any attacking tag such as `rce`, `sqli`, `xss`,
`lfi`, `bypass` or `default-login` wins), recorded by the scanner at the
finding's last sighting in `findings.template_exposure`. It is never read
from the finding's own tags, which a user can edit, and it is not recorded
for an organization's own rules or a custom retest check. A server that
refuses the request has then removed what was exposed: that is a fix once
seen twice, on two consecutive retests of the same check at least an hour
apart, both answered by the origin (an edge-marked answer in between is not a
refusal and resets the count; the reachability probe is not a second
sighting). The earlier refusal counts only when it is at most 14 days old and
the finding was neither sighted nor reopened since it. The hour is measured between the two checks' completion times, not to the moment the second is settled. Only a result of a
command the platform dispatched sets the class: an API, CTIS or CI upload
never does, whatever tags it carries. For every other class a refusal may only mean the check never
reached the vulnerable code, so it stays inconclusive. The classification
needs no new
data from the sensor: the evidence it already reports carries the response.

A tool that retests gives an unverifiable item a reason code (sdk-go
`tool.VerdictCode`: `template_not_found`, `excluded_by_policy`,
`target_unreachable`, `egress_refused`, `no_verdict`). The platform maps it to
the reason codes above (`target_unreachable` to `unreachable`, `egress_refused`
to `blocked`), and the finding card shows what it means and what to do next
(en and vi). The code only labels an inconclusive result: it never changes a
verdict, and an unknown or missing code (an older sensor) is a plain `error`.
A retest whose tool could not run the check (`error`, `template_not_found`,
`excluded_by_policy`, `no_verdict`) settles its run as blocked, not failed.

**Checks that probe several paths.** A template such as swagger tries many
paths and the tool keeps the exchange of only a few as evidence. Newer
sensors report one line per request (`requests`: URL without query values,
status, matched, failure class, CDN or WAF vendor and state; at most 64) in a
tool verdict (sdk-go `tool.RequestResult`) and in the validate result's
evidence. The platform then decides on the finding's own endpoint from those
lines, not on whichever exchange was kept. The lines are untrusted: bounded,
printable, and a verdict that says "still present" while no line matched is
`inconclusive`, never a fix. An older sensor reports none, and the settlement
reads the evidence as before. The platform does not open a finding for another
matching path (ingest does that on the next scan); it names the path. A finding
whose retest keeps ending `endpoint_mismatch` or `matched_elsewhere` can get a
retest check pinned to the exact URL (HTTP assertion, see
[finding retest checks](finding-retest-checks.md)); the console suggests it.

A retest run whose tool ran to the end and ended `inconclusive` (any code but
`no_result`, `unreachable` and the tool-unable codes) or `still_exposed_elsewhere`
is a **completed** run with a result (`result.kind`, `result.code` on the run
and its step, shown as "Completed, inconclusive"), not a failed one. A run
fails only when the sensor returned nothing (`no_result`), the target did not
answer (`unreachable`), or the platform could not settle it.

The endpoint is the finding's matched-at: scheme, host, port (default ports
dropped), path and the parameter names (values are not compared: a token
differs between runs and is masked). A conclusive outcome becomes
`inconclusive` (`template_changed`) when the template digest differs from the
last sighting's, or when a fix reports none. Reasons never carry secrets: URLs
show parameter names only and text goes through the evidence masker.

The probe exists because nuclei prints nothing and exits 0 when a host does not
answer, which the sensor reports as `not_detected`: without it a down host, a
firewall change or a sensor in the wrong zone would read as "fixed". It only
separates "unreachable" from "not reproduced"; it never proves a fix.

Eligible findings: `tool_name = nuclei` with a template id that passes the
template guard (no path, no `dos`/`fuzz`/`intrusive`/`brute-force` marker), in
`new`, `confirmed`, `in_progress`, `fix_applied` or `resolved`, on an `active`, network-addressable asset that passes the scope
gates. `false_positive`, `accepted`, `duplicate`, suppressed and pentest
findings are never retested.

## Flow

```
POST /api/v1/findings/{id}/retests            (findings:verify + data scope)
  └─ retest.Service.Request
       ├─ eligibility, scope gates (fail closed), limits, validate:nuclei sensor online
       ├─ INSERT finding_retests (pending)      ← one pending per finding (unique index)
       ├─ validate command: executor nuclei, template_id, retest_id   ┐ same queue, poll,
       ├─ validate command: executor safe-check, retest_id            ┘ lease, expiry as scans
       └─ activity retest_requested + audit finding.retest_requested

sensor completes / fails a command
  └─ CommandHandler.triggerValidationEvidence / Fail
       ├─ retest_id set → IngestAdvisory (evidence visible, NOT applied)
       └─ retest.Service.OnCommandFinished → both checks terminal?
            └─ FindingRetestRepository.Settle (one transaction):
                 lock retest (pending?) → lock finding, read status → NextStatus
                 → move finding → complete retest → activity retest_completed
                   (actor_type system, actor_name "system: retest")

RetestScheduler (controller, every minute, every replica)
  ├─ Sweep: settle retests whose checks ended or whose 30-min deadline passed
  └─ RunAutoTick: tenants with settings.retest.auto_enabled
       ├─ ClaimTenantTick: compare-and-set on finding_retest_cursors.next_run_at
       └─ winner queues min(daily budget left, in-flight room, per-pass cap)
          oldest-retested eligible findings, through the same Request path
```

## Target: the origin, never the matched-at URL

The re-run's input is the origin (`scheme://host[:port]`) of the finding's
matched-at URL when its host is the asset's host, else the asset name
(`retest.ResolveTarget`). A template appends its own path to the input
(`{{BaseURL}}/wp-admin/js/theme.js`); with the matched-at URL as the input the
re-run requested `/wp-admin/js/theme.js/wp-admin/js/theme.js`, got a 404 and
reported "did not match", which settled as `fixed`. Migration 001175 voided
those outcomes: each finding a path-target retest resolved, and that nothing
changed since, returns to its prior status and the retest reads `unknown`
with a `voided:` reason.

## Template digest drift

A retest proves something only when it re-ran the template content the
finding was last seen with. The sensor reports, per nuclei
finding, `properties.template_digest` (sha256 of the matching template file)
and `template_path`, and per report the template release in
`tool.properties.content` (`nuclei-templates`: version, archive digest).
Ingest keeps them on the finding as the last sighting's baseline (migration
001015: `findings.template_digest`, `template_path`, `templates_version`,
`templates_digest`, `template_seen_at`; sanitized: sha256 digests only, a
relative path without `..`, a short version token). A sighting without a
digest keeps the baseline; one with a new digest re-baselines.

When the retest settles (`retestdom.ApplyTemplateDrift`), a conclusive
outcome (`fixed` or `still_present`) becomes `unknown` (inconclusive, the
finding does not move) when the finding has a baseline digest and the
template re-run reported a different digest or none
(`evidence.template_digest`). A finding without a baseline (sighted before
provenance existed, or by another tool) is decided as before. A baseline that
cannot be read is inconclusive (fail closed).

The scan side is coverage auto-resolve: a covered nuclei run whose template
release differs from the release of a candidate's last sighting (or that
reported none) does not resolve that candidate; in enforce mode it is marked
stale ([finding-status-not-observed.md](finding-status-not-observed.md)).
A run whose reports disagree on the release counts as reporting none.

## Limits (server-side)

| | |
|---|---|
| pending retests per finding | 1 |
| cooldown per finding | 10 min |
| in flight per asset | 3 |
| in flight per tenant | 20 manual, 50 auto |
| auto daily cap per tenant | `settings.retest.daily_cap`, default 200, max 2000 |
| auto interval | `settings.retest.interval_hours`, default 24, 6–168 |
| auto queued per scheduler pass, all tenants | 100 |
| retest deadline | 30 min |
| resolved findings re-checked by auto | resolved in the last 90 days |

## Settings and API

| Route | Gate |
|---|---|
| `POST /api/v1/findings/{id}/retests` — Retest now (202) | `findings:verify` + data scope |
| `GET /api/v1/findings/{id}/retests` — history, newest first | `findings:read` + data scope |
| `GET/PUT /api/v1/organization/settings/retest` — `auto_enabled`, `interval_hours`, `daily_cap` (audited `tenant.retest_updated`) | team admin |

Auto-retest is **off** for every tenant until an admin turns it on (owner
ordering: until the scans redesign P1 lands).

## Regression reopen from scans

Independently of retests, ingest reopens every re-detected finding that was
closed as fixed (a scan or a person closed it) on the **same record**, never a
second row: `AutoReopenByFingerprintsBatch` locks the rows, reopens them and
returns what it cleared. The `auto_reopened` activity keeps `previous_status`,
`previous_resolution`, `previous_closure_reason`, `previous_verification`,
`previous_resolved_by`, `previous_resolved_at`, `scanner` and `scan_id`, so the
person who resolved it is never lost. Deliberate dispositions (false positive,
accepted risk within its end, duplicate) and a close recorded as mitigated are
never reopened by detection; an accepted risk whose end passed returns to
`confirmed` through the expiry, not as a regression.

What a re-detection of a closed finding is, in the order it is decided
(`reopenClassSQL`, `vulnerability.ReopenClass`):

| Class | When | Counts as a regression | Timeline wording |
|---|---|---|---|
| `verified_regression` | the close was verified (`verification` `retest` or `security_review`) | yes, announced as "Verified fix regressed" | "Seen again after a verified fix: the fix did not hold" |
| `seen_again` | an automatic close (no person), unverified, younger than `SeenAgainWindow` (7 days): the finding flaps between found and not found | no: no `is_regression`, no `reopen_count`, no new SLA clock, no announcement | "Seen again shortly after an automatic close: not counted as a regression" (reason `seen_again`) |
| `regression` | everything else: a person's close, or an automatic close that lasted the window | yes | "Seen again after it was closed as fixed" |

- **Reopen target (D8).** A finding that was ever triaged (it has an assignee, or its
  timeline shows a move to `confirmed`, `in_progress` or `fix_applied`) reopens as `confirmed`;
  one nobody touched reopens as `new`. A retest that still matches reopens to `confirmed`.
- **Counters and clock (D3).** A regression sets `is_regression`, adds one to `reopen_count`,
  sets `last_reopened_at`, and starts a new SLA clock (`sla_started_at`); `first_detected_at`
  is kept, so the age of the finding is unchanged. The trigger `mark_finding_regression` skips
  a person's move (`openctem.person_move`, so Undo is not a regression) and a flap
  (`openctem.seen_again`).
- **Not a coverage proof, no close.** A partial scan, a run that did not complete cleanly, or the
  full scan of another tool never auto-resolves a finding, so the next sighting is a plain
  sighting.
- **An older report does not reopen a fix.** A report is judged by when its source observed
  the findings (its timestamp, clamped into the command's window, else the arrival time). A
  finding resolved at or after that time stays resolved (`AutoReopenByFingerprintsBatch`
  compares `resolved_at` with it); a report observed after the fix reopens it.
- **A duplicate seen again** is a sighting of the finding it was folded into (`duplicate_of`,
  same asset): that finding is marked seen in the scan (it is not auto-resolved) and reopens if it
  was closed; the duplicate itself stays a duplicate.
- **Remediation tasks.** A finding of a `done` or `closed_unverified` task that reopens is moved
  into a new task `Regression: <title>` at the next recompute
  ([remediation-tasks.md](remediation-tasks.md)); the closed task keeps its state and history.
- **Identity.** A finding keeps its record across a scan only while its fingerprint matches
  ([deduplication.md](deduplication.md)): a SAST result that carries its code survives a moved line,
  a result with only a line, or a renamed rule or template id, is a new finding and the old one
  closes by the usual rules.

## Phase 2: what follows a status change (decisions D2–D4)

- **Fresh SLA on a regression (D2).** A finding closed as fixed that a scan or
  a retest sees again (a regression, not a flap) gets a new SLA deadline computed by the tenant's policy
  (priority class, then severity) from the reopen, `sla_status = on_track`, and
  an `sla_restarted` activity with the reason, the trigger (`scan`/`retest`) and
  the previous deadline (`sla.RegressionRestarter`,
  `postgres.FindingSLARestartRepository`).
- **Announcements.** A retest that resolves a finding (`finding_fixed`), a
  regression (`finding_reopened`) and a rejected fix (`fix_applied` still
  detected, `finding_reopened`) queue a notification and comment on the linked
  Jira issue — only when the tenant enabled outbound sync on its Jira
  integration (`jira.SyncService.CommentOnFinding`). Platform-written text only,
  free text capped at 300 characters, at most 50 announcements per scan
  (`retest.ChangeAnnouncer`, `retest.ScanRegressions`). A regression is also told
  in the app to the finding's assignee and to its watchers who can still read it
  (`VulnerabilityService.NotifyRegression`, a `finding_status_change` notice;
  see [participants-and-watchers.md](participants-and-watchers.md)).
- **Honest `/validate` (D3).** See [validation-engine.md](validation-engine.md):
  a safe-check never moves a finding; a nuclei miss without proof the target
  answered is unknown.
- **Proof of fix (D4).** Marking a finding `fix_applied` (or a Jira "Done")
  starts a `proof_of_fix` retest for a nuclei finding (`retest.ProofOfFix`),
  else the validation re-check. The whole-asset "Request verification scan"
  (`POST /findings/{id}/request-verification`) is removed, with its service,
  adapter and web button.

## Code

| Piece | Where |
|---|---|
| Outcome and transition rules (pure) | `pkg/domain/retest/retest.go` (`Decide`, `NextStatus`) |
| Service: request, gate preflight, limits, dispatch, settle, sweep | `internal/app/retest/service.go`; the gate: [active-probe-gate.md](active-probe-gate.md) |
| Auto-retest tick (claim once) | `internal/app/retest/auto.go` |
| Persistence + settle transaction + cursors | `internal/infra/postgres/finding_retest_repository.go`, migration `000281_finding_retests` |
| Completion hooks | `internal/infra/http/handler/command_handler.go` (`triggerValidationEvidence`, `triggerRetestSettle`) |
| Routes / handler | `internal/infra/http/routes/finding_retest.go`, `internal/infra/http/handler/finding_retest_handler.go` |
| Controller | `internal/infra/controller/retest_scheduler.go` |
| Tenant setting | `pkg/domain/tenant/retest_settings.go` |
| Web: Retest now + last retest | `web/src/features/findings/components/detail/finding-retest.tsx` |
| Fresh SLA on regression | `internal/app/sla/regression.go`, `internal/infra/postgres/finding_sla_restart_repository.go`, migration `000285_retest_phase2` |
| Announcements, scan regressions, proof of fix | `internal/app/retest/announce.go`, `internal/app/retest/proof_of_fix.go`, `internal/app/jira/sync_service.go` (`CommentOnFinding`) |

## Tests

- `pkg/domain/retest/retest_test.go` — outcome and transition tables.
- `internal/app/retest/service_db_test.go` — end to end against Postgres:
  fixed, unreachable → unknown, regression reopen, one in flight + cooldown,
  deadline sweep, ineligible findings, two scheduler replicas never double-fire,
  auto off by default.
- `internal/infra/http/routes/finding_retest_authz_db_test.go` —
  `findings:verify`, cross-tenant 404, data scope 404.
- `internal/infra/postgres/finding_reopen_regression_db_test.go` — a scan
  regression keeps the previous resolver.

## Run linkage

A retest attempt is a run of kind `retest`: `GET /findings/{id}/retests`
returns, per attempt, `run_kind: "retest"`, the `check_command_id` (and the
validate path's `reach_command_id`) and the `sensor_id` that claimed the
check (stored on the retest when it settles, migration 001242), so a runs
view can link finding, command and sensor.

## Evidence

A retest attempt's proof (what the re-run requested and what came back) is
stored as finding evidence with `origin = retest` and the retest id, masked,
and shown under the attempt ("View evidence"); see
[finding-evidence.md](finding-evidence.md).

## Tool retest

A finding whose tool has a retest handler on a tenant sensor (capability
`retest:<tool>`, sdk-go tool contract) is retested by **one `retest` command**
to that tool instead of the two `validate` commands. The tool answers a verdict
per finding: `still_present`, `fixed` or `unverifiable`, with the attempt's
`evidence` and the `template_digest` it ran. The retest service settles from
the verdict for its own finding: still vulnerable; a `fixed` verdict decided
from its evidence like a validate non-match (a bare `fixed` is
`not_reproduced`); inconclusive for anything else. The nuclei validate pair remains the fallback for nuclei
findings when no sensor offers `retest:nuclei`. The payload names the tool as
`scanner` and lists plain addresses, so it passes the same claim-time tool
predicate, active-probe gate, zone pinning and sensor-side local policy as a
scan. Design and threat model: [RFC-039 §12](../rfcs/RFC-039-continuous-retest.md).

## Retest checks in the console

A finding with no automatic retest (manual, pentest, bug bounty, DAST without
a template) can get a **retest check** from the finding drawer or the finding
page ("Retest check" section, next to "Retest"):

- **Editor:** two tabs. *HTTP assertion* is a form (method GET/HEAD/POST/OPTIONS,
  a path relative to the finding's target, headers, a body for POST, status /
  word / regex matchers combined with and/or). *Nuclei template* takes pasted
  YAML, an uploaded `.yaml`/`.yml` file (read in the browser, at most 256 KB) or a
  template picked from the organization's library (shown to users with
  `scans:templates:read`). **Validate** calls
  `POST /api/v1/findings/{id}/retest-check/test` and shows the errors per
  field, the tier with its reason and the template that would run; **Save**
  (`PUT …/retest-check`) is enabled only after a valid validation of exactly the
  current input; **Remove** (`DELETE …/retest-check`) detaches it and leaves the
  template in the library.
- **Saved state:** name, kind, short digest, tier badge, calibrated or not,
  approval state, a note with a link to the template library while the template
  awaits approval for the sensors, and the last verdict of a retest that ran the
  check. **Approve** (`POST …/retest-check/approve`, scope approval rights and a
  recent sign-in) appears only when the check needs approval and has none; a
  409 (the approver wrote this version, or no approval is needed) is explained.
- **Retest panel:** "Retest now" is offered for a finding with a check even when it
  has no tool rule; a retest that ran the check reads "Checked with custom check
  <name> (sha256:…12 hex)".
- **Permissions:** reading needs `findings:read`; adding, editing and removing need
  `findings:retest_checks:write`; the console only
  hides actions the API would refuse. Code:
  `web/src/features/findings/components/detail/finding-retest-check.tsx`,
  `retest-check-editor-dialog.tsx`, `web/src/features/findings/api/use-finding-retest-check.ts`.
