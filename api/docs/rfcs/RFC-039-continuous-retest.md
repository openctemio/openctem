# RFC-039 — Continuous retest with regression reopen

> Status: **Proposed — decisions approved** (owner, 2026-10-03; #866; Phase 1 implementation #867). Tool retest (§12): any tool with a retest handler on a tenant sensor.
> Scope: api (retest service, scheduler, ingest regression path, routes) + web
> (Retest now, last-retest status). No sensor or sdk-go change in Phase 1.
> Builds on [RFC-011](RFC-011-validation-engine-dispatch.md) /
> [RFC-011.2](RFC-011.2-validation-executor-downgrade-loop.md) (the `validate`
> command, the `validate:nuclei` single-template executor), the scans redesign
> (Scan → Run → Task), [RFC-030](RFC-030-scan-work-distribution.md) (fair share,
> leases), [RFC-036](RFC-036-easm.md) (only confirmed assets are actively
> checked, #835) and the claim-once scheduler pattern of #830 / #847.
>
> Goal: **all open and fixed** vulnerabilities are re-checked on a schedule
> (auto-retest), and every finding has a **Retest** action that sets *Fixed*
> when the issue is gone and keeps the original status when it is still there.

## 1. Answer in short

A **retest** re-runs the exact check that produced a finding — for Phase 1 the
nuclei template (`rule_id`) against the finding's own target — **plus a
reachability probe of the same target**, and moves the finding on the combined
result:

| Template re-run | Target reachable? | Retest outcome | Finding |
|---|---|---|---|
| matched | any | **still present** | open: unchanged · resolved: **reopened (regression)** · `fix_applied`: back to `in_progress` · `validated_fixed`: `confirmed` |
| no match | yes | **fixed** | open → `resolved` (`resolution_method = retest_verified`) · resolved: unchanged (re-confirmed) |
| no match | no / unknown | **unknown** | unchanged; the retest records *target unreachable* |
| inconclusive / error / no result | any | **unknown** | unchanged |

A tenant can turn on **auto-retest** (default **off**): a scheduler re-checks
the tenant's eligible open and recently-fixed findings once per interval
(default 24 h), within a per-tenant daily cap and an in-flight cap, claimed once
per tick so several API replicas never double-fire. A user with
`findings:verify` can press **Retest now** on one finding.

Every status change a retest makes is written to the finding's activity trail
with the actor **`system: retest`** (and, for a manual retest, who asked), and
every request is audit-logged.

Independently of retests, a **scan that re-detects** a finding a person had
resolved already reopens it on develop (the 2026-07 "human-fix regressions don't
auto-reopen" gap is closed at the SQL level). Phase 1 closes what is left of
that gap: the reopen now remembers **who resolved it and how**, and a scan that
re-detects a `validated_fixed` finding refutes the downgrade.

## 2. Current state (verified 2026-10-03, `develop` 2c3919d4, sensor `main` 9b65e57 = v0.7.0)

### 2.1 What happens when a scanner reports a resolved finding again

Ingest (`internal/app/ingest/processor_findings.go`, step 3b) calls
`AutoReopenByFingerprintsBatch` (`internal/infra/postgres/finding_repository.go`).

| Finding state when the scan sees it again | Result today |
|---|---|
| `resolved` by auto-resolve (`resolution = auto_fixed`) | reopened to `confirmed` |
| `resolved` by a person (any other `resolution`, or NULL) | reopened to `confirmed` (fixed before this RFC; DB test `finding_reopen_human_resolved_db_test.go`) |
| `verified` (pentest) | reopened to `confirmed` |
| `false_positive`, `accepted`, `duplicate`, `accepted_risk`, suppressed (`resolution = suppressed`) | never reopened (deliberate dispositions) |
| `fix_applied` | **stays `fix_applied`** — only enriched |
| `validated_fixed` | **stays `validated_fixed`** — only enriched |

Trigger `000199` sets `is_regression`, `reopen_count`, `last_reopened_at` on any
resolved/verified → open move. What is still wrong:

- **Who fixed it is lost.** The reopen sets `resolved_by`, `resolution`,
  `resolution_method` to NULL, and the activity row records only
  `{"reason": "finding_detected_again"}` — no previous status, no previous
  resolver, no scan.
- **`validated_fixed` is never reopened by a scan**, although a scan seeing the
  issue is exactly the evidence that refutes a validation downgrade.
- **`fix_applied` is never moved back** although `RequestVerificationScan` and the
  Jira rescan hook both promise "back to in_progress via the normal ingest
  pipeline". (Left for the owner: §10 D5 — a scan that *started* before the fix
  was claimed can legitimately still see it.)
- **No side effects on reopen:** no notification, no workflow event, no ticket
  comment, and the SLA clock is not restarted (the escalation job then marks a
  reopened finding overdue against its original deadline).

### 2.2 Retest / verify entry points that exist

| Route | Gate | What it really does |
|---|---|---|
| `POST /findings/{id}/request-verification` | `findings:write` | `QuickScan` of the **whole asset** with a scanner the user types. Requires `fix_applied`. Not linked back to the finding; nothing reads its `verification-scan` tag. An ad-hoc host scan has no branch, so report-level auto-resolve cannot close the finding, and coverage auto-resolve is `dry_run` by default. **The web offers it in the ⋯ menu for every status except `fix_applied`, where the API refuses it.** |
| `POST /findings/{id}/validate` | `findings:write` | RFC-011 validation: a `validate` command. `nuclei` single-template re-run when the finding has a template/CVE signature and a `validate:nuclei` sensor is online, else a TCP `safe-check`. Outcome applied by `applyOutcomeToFinding`. |
| `POST /findings/actions/fix-applied` | `findings:fix_apply` | marks `fix_applied` and auto-queues validation (proof of fix) |
| pentest `/retests` | pentest perms | manual pentest retest records |

### 2.3 How validation re-checks work, and two defects that matter here

`RunService.ValidateFinding` → `CommandDispatcher.Dispatch` (command type
`validate`, `required_capabilities: ["validate:nuclei"]` or `["validate"]`) → the
sensor (`sensor/internal/executor/validation.go`) runs
`nuclei -u <target> -id <template> -etags dos,fuzz,intrusive,… -rate-limit 20`
or a TCP probe → `Complete` → `triggerValidationEvidence` →
`EvidenceIngestService.Ingest` → `applyOutcomeToFinding`.

- **D-a. An unreachable target reads as "fixed".** nuclei emits nothing and
  exits 0 when the host does not answer, which the sensor reports as
  `not_detected`. `applyOutcomeToFinding` then downgrades an open finding to
  `validated_fixed` (or *resolves* a `fix_applied` one). A down host, a firewall
  change or a sensor in the wrong network zone looks exactly like a fix.
- **D-b. Safe-check answers a different question.** For a `fix_applied` finding,
  a TCP probe that connects ("reachable") is mapped to *"fix did not hold"* and a
  refused connection to *resolved*. Reachability is not the vulnerability.
- Status moves made by `applyOutcomeToFinding` use a nil actor and write **no**
  `finding_activities` row; `/validate` has no rate limit or concurrency cap; and
  validate commands do not carry `scan_zone_id`, so zone routing (RFC-023) does
  not apply to them.

### 2.4 Why a retest cannot be a plain scan Run today

A scan command's payload reaches the scanner through the SDK, which honours only
`allow_interactsh` and `exclude` from `config` (`sdk-go/pkg/core/command_poller.go`;
RFC-038 §3.1 found the same). There is **no way to send a template id in a scan
command**, so a "scan Run with only that template" would run the sensor's full
nuclei set against the asset. That is the cost of a scan for a one-template
question, and coverage auto-resolve (`decideCoverage`) would treat the run as full
coverage of the asset and could close the asset's *other* nuclei findings in
`enforce` mode. The `validate` command, on the other hand, is already a scoped,
single-template, rate-limited, tag-restricted, SSRF-guarded run on the sensor —
it is the deterministic re-check this RFC needs.

## 3. Goals and non-goals

**Goals**

1. Keep finding status true over time: a fixed issue becomes *Fixed* without a
   person, a regression reopens without a person.
2. Never call something fixed that was not observed fixed (unreachable ⇒
   *unknown*, never *fixed*).
3. Bounded load: a tenant cannot use retests to flood a target or to starve
   shared sensors.
4. Every status change attributable (`system: retest`, who asked, which
   template, which commands) and visible on the finding.
5. Reuse the existing transport (commands, leases, capability routing, evidence
   store); no new sensor protocol in Phase 1.

**Non-goals (Phase 1)**

- Retesting finding types without a deterministic single check (SAST/SCA/secrets,
  Tenable, pentest). Their source of truth stays the next full scan.
- A CVE→template resolver for non-nuclei findings (RFC-011.2 open question 1).
- Changing RFC-011.2's validation semantics — Phase 1 only stops its defects
  from touching retest commands (§6.4). Fixing D-a/D-b for `/validate` itself is
  §10 D3.

## 4. Model and states

### 4.1 Retest (one row per attempt, `finding_retests`)

```
            request (manual | auto)
                   │
                   ▼
   ┌────────── pending ──────────┐   two tasks: check (validate:nuclei) + reach (safe-check)
   │                             │
   │ both tasks terminal,        │ deadline passed (30 min) / dispatch failed
   │ or settle on completion     │
   ▼                             ▼
completed{fixed | still_present | unknown}
```

| Field | Meaning |
|---|---|
| `trigger` | `manual` (Retest now) or `auto` (scheduler) |
| `requested_by` | the user for `manual`, NULL for `auto` |
| `prior_status` / `result_status` | finding status before / after the retest |
| `check_command_id` / `reach_command_id` | the two `validate` commands |
| `template_id`, `target` | exactly what was re-run, against what |
| `outcome`, `reason` | `fixed` / `still_present` / `unknown`, with a human reason (`target unreachable`, `template not installed on the sensor`, `no sensor result before the deadline`, …) |
| `deadline_at` | when a still-pending retest is settled as `unknown` |

A partial unique index allows **one pending retest per finding**: the second
request is refused, a second scheduler cannot queue it again.

### 4.2 Outcome decision (pure function, `pkg/domain/retest`)

```
check = detected                         → still_present
check = not_detected  and reach = detected (reachable)
                                         → fixed
check = not_detected  and reach ≠ detected
                                         → unknown  ("target unreachable")
check ∈ {inconclusive, error, skipped} or no result
                                         → unknown  (summary of the check)
```

The reachability probe is the **guard against D-a**. It is not evidence of the
vulnerability; it only makes "no match" mean something.

### 4.3 Finding transition (pure function)

| Finding status before | fixed | still_present | unknown |
|---|---|---|---|
| `new`, `confirmed`, `in_progress` | → `resolved` | unchanged | unchanged |
| `fix_applied` | → `resolved` (proof of fix) | → `in_progress` | unchanged |
| `validated_fixed` | → `resolved` | → `confirmed` | unchanged |
| `resolved` | unchanged (re-confirmed fixed) | → `confirmed` (**regression**) | unchanged |
| `false_positive`, `accepted`, `duplicate`, pentest states | not eligible — never retested | | |

`resolved` by a retest sets `resolution = "retest: not detected (<template>)"`,
`resolution_method = retest_verified`, `resolved_by` = the requesting user for a
manual retest (they hold `findings:verify`, so this is their verification) and
NULL for an auto retest. A regression reopen goes through the normal transition
(resolved → confirmed), so trigger `000199` counts it.

The transition is decided from the finding's status **at settle time**, read
with the row locked in the same transaction that completes the retest and writes
the activity entry. A person who changed the finding while the retest ran is
therefore respected: a finding they marked `false_positive` is not touched; one
they moved to `fix_applied` gets the proof-of-fix transition. Nothing is
half-applied.

## 5. Which findings qualify

Phase 1 qualifies a finding only when a **deterministic single check** exists and
the platform can address it:

1. `tool_name = 'nuclei'` and `rule_id` is a template id that passes the existing
   template guard (`templateSignatureAllowed`: no path, no `dos`/`fuzz`/
   `intrusive`/`brute-force` marker; the sensor re-checks by tag).
2. status in the eligible set (§4.3); for **auto** retests a `resolved` finding
   qualifies only if it was resolved in the last 90 days.
3. the asset is `active`, network-addressable (domain, subdomain, IP, host,
   service, application, website, …) and passes the **target gate** (§7.2).
4. a `validate:nuclei` sensor is online for the tenant.

Target: the finding's matched-at URL (`file_path`) when its host is the asset's
host; otherwise the asset name. A finding cannot point a retest at a host that is
not its own asset.

Later phases add the other deterministic families, each as its own check kind on
the same model:

| Family | Check | Phase |
|---|---|---|
| nuclei template | `validate:nuclei` single template | **1** |
| open port / service | TCP connect / banner on the recorded port (naabu-style) | 2 |
| TLS / certificate | `tlsx`-style handshake: expiry, chain, protocol, cipher | 2 |
| DNS (dangling CNAME, SPF/DMARC, takeover) | the RFC-036 P1 DNS-only checks, run by the API | 2 |
| CVE from another scanner | CVE→nuclei-template resolver (RFC-011.2 Q1) | 3 |

## 6. Flows

### 6.1 Retest now (manual)

`POST /api/v1/findings/{id}/retest` — `findings:verify`, data-scoped (§8.3).

1. Load the finding **in the caller's tenant** (tenant from the token, never the
   body); check eligibility (§5) → `400` with the reason otherwise.
2. Limits (§8.1): one pending per finding (`409`), cooldown since the last retest
   of this finding, per-asset and per-tenant in-flight caps (`429`).
3. Insert the `pending` row (claims the per-finding slot), then enqueue the two
   `validate` commands carrying `retest_id`. If enqueueing fails the row is
   settled `unknown` (`dispatch failed`) at once.
4. Audit `finding.retest_requested` (user, finding, template, target) and a
   `retest_requested` activity. Respond `202` with the retest.

### 6.2 Result handling

The sensor completes each command as today. In `triggerValidationEvidence`, a
command whose payload carries `retest_id`:

- records its evidence **advisory only** (`IngestAdvisory`: visible in the
  finding's evidence, never applied by `applyOutcomeToFinding` — so D-a/D-b
  cannot touch a retest), then
- asks the retest service to **settle**: when both commands are terminal it
  decides the outcome (§4.2), moves the finding (§4.3), writes a
  `retest_completed` activity with actor `system: retest`, and completes the row.
  Settling is a compare-and-set on `status = 'pending'`, so two replicas that
  receive the two completions at the same moment settle it once.

A failed, expired or never-picked-up command is settled by the scheduler's
sweep: any pending retest whose commands are all terminal, or whose
`deadline_at` passed, is settled (missing results ⇒ `unknown`).

### 6.3 Auto-retest (scheduler)

`RetestScheduler` (controller, every minute, on every replica):

1. **Sweep** stale pending retests (§6.2).
2. For tenants with `settings.retest.auto_enabled = true`, ordered by their
   cursor: **claim** the tenant's tick with a compare-and-set on
   `finding_retest_cursors.next_run_at` (`UPDATE … WHERE tenant_id = $1 AND
   next_run_at IS NOT DISTINCT FROM $seen`, the #847 pattern; a first claim is
   `INSERT … ON CONFLICT DO NOTHING`). Only the replica that wins queues work.
3. Queue up to `min(daily budget left, in-flight room, per-tick global cap)`
   eligible findings whose last retest is older than the interval (default 24 h),
   oldest-retested first, at most 3 in flight per asset. Each goes through the
   same request path as a manual retest (`trigger = auto`).

Cadence is therefore "every eligible finding about once per interval", bounded
by sensor capacity: when the tenant's in-flight cap is full, the tick queues
nothing and the backlog drains on later ticks; findings whose last retest is
oldest go first, so nothing starves.

### 6.4 Reusing the scan pipeline

In the Scan → Run → Task vocabulary a retest is a **Run with two Tasks**:

- the *Run* is the `finding_retests` row (its own lifecycle, deadline, outcome);
- the *Tasks* are ordinary `commands` rows — the same queue, poll, lease
  (RFC-030 D5 free slots), capability routing (`validate:nuclei`), expiry and
  audit as every scan task.

It deliberately is **not** a `scans`/`pipeline_runs` row in Phase 1 (§2.4: no
template selector on scan commands; coverage auto-resolve hazard). Phase 3, once
RFC-038 delivers typed tool settings (a template list is then a declared, typed
option) and the scans redesign P1 (HA claims, leases) lands, moves retests onto
`pipeline_runs` with `kind = retest`, so they show on the Runs tab, get scan-zone
routing and share `MaxConcurrentRunsPerTenant`. That run must be created with
coverage `partial` so it can never auto-resolve other findings.

### 6.5 Regression reopen from any scan

`AutoReopenByFingerprintsBatch` now:

- also reopens `validated_fixed` → `confirmed` (the scan refutes the downgrade);
- returns, per reopened finding, the **previous status, resolution, resolution
  method and resolver**, read with `FOR UPDATE` in the same statement;
- the `auto_reopened` activity records them (`reason: regression_detected_again`,
  `previous_status`, `previous_resolution`, `previous_resolution_method`,
  `previous_resolved_by`, `scanner`, `scan_id`), so "who fixed it and how" is
  never lost when the row's resolution fields are cleared.

## 7. Interactions

### 7.1 Suppressions, accepted risk, false positives

Never retested, never reopened: `false_positive`, `accepted`, `accepted_risk`,
`duplicate` and findings a suppression rule matched (since research 18 F7 they
are `false_positive` / `accepted` with `resolution = suppressed`; older rows may
still be `resolved` with it) are outside the
eligible set and excluded by the reopen SQL. An expired acceptance re-enters the
eligible set through its existing reopen path.

### 7.2 Scope and ownership (#835)

A retest is an active check, so it passes the same gates as a scan, **failing
closed**:

- the asset must be `active`;
- **scope exclusions** (`scope.Service.ExcludedTargets`, the fail-closed variant
  the scan path uses) — an excluded asset is never retested;
- **attribution** (#835, RFC-036): an asset whose state is not `confirmed` (or
  unset) is not retested (direct quick-scan targets are deliberately ungated in
  #835; retests are not, because the target comes from inventory);
- **scan zones**: a private target outside every zone is refused, and a zoned
  target's commands are pinned to its zone.

These are the shared active-probe gate (`scan.Service.ResolveDispatchTargets`),
which every validate command passes in `validation.CommandDispatcher`; the
retest service runs it once more as a preflight before it records the retest.
A refusal is `validation.ErrTargetRefused`, not `ErrNotEligible`, so
proof-of-fix stops instead of falling back to a plain re-check of the same
target. See [architecture/active-probe-gate.md](../architecture/active-probe-gate.md).
- the sensor's own SSRF guard still applies (`validateScannerTarget`).

### 7.3 SLA clocks

- **fixed** → `resolved`: the SLA stops like any resolve.
- **regression** reopen (scan or retest): **a fresh deadline from the reopen**
  (owner decision D2, Phase 2a), computed by the tenant's SLA policy, with an
  `sla_restarted` activity carrying the reason and the previous deadline. Phase 1
  kept the original deadline, so a regression was overdue the moment it came
  back.
- **unknown** does not touch SLA.

### 7.4 Tickets

Phase 1 writes the activity trail only. Phase 2a comments on the linked Jira
issue on a *fix*, a *regression* and a *rejected fix*, only when the tenant
enabled outbound sync on its integration (the same opt-in as status sync).
Comments are platform-written text with the free-text part capped; they never
carry the evidence body.

### 7.5 Notifications

Phase 2a: a regression and a rejected fix queue the existing `finding_reopened`
event; a retest that resolves a finding queues `finding_fixed`. The tenant's
notification integrations route them by their event filters. One scan reopening
many findings announces at most 50 of them (the SLA restart still covers all).

## 8. Threat model

| # | Threat | Control |
|---|---|---|
| T1 | A tenant forces retests to **DoS a target** (button mashing, a script on the API, auto-retest of thousands of findings on one host) | one pending retest per finding (DB unique index); cooldown per finding (10 min since the last request); at most **3 in flight per asset**; the sensor runs one template at `-rate-limit 20` with `-etags dos,fuzz,intrusive,…`; auto daily cap per tenant (default 200, max 2000) |
| T2 | A tenant **exhausts shared sensors** | per-tenant in-flight cap (**20 manual, 50 auto**); per-tick global cap (100) across tenants, tenants served oldest-cursor first (round-robin); commands carry `required_capabilities` and are claimed through RFC-030 free slots, so a sensor never takes more than it has; tenant sensors only — retests are tenant commands, never platform jobs |
| T3 | Retest **hits something out of scope** | only inventory assets (never a free-form target); target host must equal the asset host; `active` assets only; fail-closed scope exclusions; #835 attribution gate; sensor-side SSRF guard |
| T4 | **Destructive template** via a crafted `rule_id` (findings can be created through the API by `findings:write`) | API template guard (no path, no destructive marker) + sensor tag exclusion and post-match tag check (a mis-tagged destructive match is discarded as inconclusive) |
| T5 | **Unauthorised Retest now / cross-tenant** | `findings:verify` (the same segregation-of-duties permission as resolving) + Layer-2 data scope (`DataScopeGuard` on `/api/v1/findings/{uuid}/…` → 404 out of scope) + tenant taken from the token and every query `WHERE tenant_id = $n`; a finding id from another tenant is "not found" |
| T6 | A **compromised sensor** reports a fake result to close or reopen findings | the result only counts for the command the platform issued to that sensor (existing command ownership); retest evidence is ingested advisory-only; the tenant comes from the command, not the sensor; a fake *fixed* needs both commands, and the reach probe alone cannot close anything |
| T7 | **False "fixed"** from a down host / wrong zone | reach probe guard (§4.2): unreachable ⇒ `unknown` |
| T8 | **Race** with a person changing the finding mid-retest | the transition is decided under the finding's row lock from its status at settle time (§4.3); an ineligible status is never moved |
| T9 | **Double-fire** with several API replicas | tenant tick claimed by compare-and-set; per-finding pending unique index; settle CAS on `pending` |
| T11 | **Ticket / notification injection or flooding** (Phase 2a: a sensor summary flows into the retest reason, which is announced) | announcements are platform-written; the free-text part is flattened to one line of plain text without control characters and capped at 300 characters; ticket comments only when the tenant enabled outbound sync; at most 50 announcements per scan |
| T10 | **Repudiation** | `finding.retest_requested` audit event (who, what, target); `retest_completed` activity with actor `system: retest`, `trigger`, `requested_by`, commands, template; reopen activity keeps the previous resolver |

### 8.1 Limits (Phase 1 constants, all server-side)

| Limit | Value |
|---|---|
| pending retests per finding | 1 |
| cooldown per finding | 10 min since the last request |
| in flight per asset | 3 |
| in flight per tenant, manual | 20 |
| in flight per tenant, auto | 50 |
| auto daily cap per tenant | setting, default 200, 1–2000 |
| auto interval | setting, default 24 h, 6–168 h |
| global auto queue per tick | 100 |
| retest deadline | 30 min |
| resolved-finding lookback (auto) | 90 days |

### 8.2 Default off

`settings.retest.auto_enabled` defaults to **false** for every tenant until the
scans redesign P1 (HA scheduler claims, leases) lands, per the owner's ordering.
Manual Retest now is available whenever a `validate:nuclei` sensor is online.

### 8.3 Authorization summary

| Action | Gate |
|---|---|
| `POST /findings/{id}/retest` | `findings:verify` + data scope |
| `GET /findings/{id}/retests` | `findings:read` + data scope |
| `GET/PUT /organization/settings/retest` (tenant from the token) | team admin (owner/admin), audited |

## 9. Phased plan

| Phase | Content |
|---|---|
| **P1 (#867)** | `finding_retests` + cursors (migration 000327); domain decision/transition; retest service (eligibility, gates, limits, dispatch, settle, sweep); Retest now + list routes; settings `retest` (default off) + endpoint; `RetestScheduler` with claim-once; advisory ingest of retest evidence; scan regression reopen keeps the previous resolver and reopens `validated_fixed`; web: Retest now button and last-retest status on the finding page and drawer |
| **P2a (#881, owner decisions D2–D4)** | fresh SLA on every regression, scan or retest, with an `sla_restarted` activity (reason, previous deadline; migration 000336); `/validate` verdict rule acts only on exploitability-grade evidence (safe-check never moves a finding, a nuclei miss needs `reachable`); proof of fix on `fix_applied` (and on Jira "Done") is a `proof_of_fix` retest, else the validation re-check; "Request verification scan" retired (route, service, adapter, web); ticket comment (opt-in Jira outbound) + `finding_fixed` / `finding_reopened` notification on a fix, regression or rejected fix, capped at 50 per scan |
| P2b | port/service, TLS and DNS check kinds; web settings page for auto-retest and an auto-retest column/filter |
| P3 | retests as `pipeline_runs(kind = retest)` with scan-zone routing and coverage `partial`, once RFC-038 typed settings and scans P1 land; CVE→template resolver; asset-group-scoped auto-retest policies |

## 10. Owner decisions — approved 2026-10-03

| # | Question | Decision |
|---|---|---|
| D1 | Clean retest of an open finding | **Resolves it** (`resolution_method = retest_verified`). Shipped in P1 (#867). |
| D2 | SLA on a regression | **Fresh SLA deadline** from the reopen, computed by the tenant's SLA policy; the reason and the previous deadline are recorded on the finding's activity. Phase 2. |
| D3 | `/validate` defects D-a / D-b | **Fix them**: an unreachable host is unknown, never fixed; a safe-check (reachability) result never moves a finding. Phase 2. |
| D4 | "Request verification scan" | **Retired** in favour of Retest now. Phase 2. |
| D5 | `fix_applied` re-detected by a scan | **Left to retest and proof of fix** (no change to ingest). |
| D6 | Auto-retest default | **Off** for every tenant; turned on for new tenants after scans P1 (HA claims, leases) lands. |
| D7 | Limits | **Kept as in §8.1**: 1 pending per finding, 10 min cooldown, 3 per asset, 20 manual / 50 auto per tenant. |

Phase 2 also adds the ticket comment and the notification on a regression or a
fix (§7.4, §7.5).

## 11. Alternatives considered

- **Scoped scan Run** (QuickScan of the asset with nuclei): runs the full
  template set (no template selector on scan commands), costs a scan per
  question, and coverage auto-resolve could close unrelated findings. Rejected
  for P1; P3 once typed settings exist.
- **Reuse `/validate` as is:** unreachable ⇒ "fixed" (D-a), safe-check semantics
  (D-b), no limits, no actor. Rejected; retest reuses its transport, not its
  verdict rule.
- **A new sensor command `retest`:** cleaner wire, but needs an sdk-go release
  and a sensor bump for every tenant, while `validate:nuclei` already ships in
  sensor v0.7.0. Rejected for P1.

## 12. Tool retest: any tool with a retest handler

A retest is no longer limited to nuclei templates. The sensor SDK's tool contract
has a **retest** kind (sdk-go `tool.Retester`). A tool that declares it gets known
items (a finding and the address it is on) and answers one verdict per item:
`still_present`, `fixed` or `unverifiable`. A sensor that serves retests for tool
`<tool>` reports capability `retest:<tool>`.

### 12.1 Method choice

| Finding | Sensor online for the tenant | Method |
|---|---|---|
| any tool, eligible rule id | one with `retest:<tool>` | **tool**: one `retest` command |
| nuclei, template that passes the guard | none with `retest:nuclei`, one with `validate:nuclei` | **validate**: the template re-run plus the reachability probe (§4–§6, unchanged) |
| otherwise | — | refused, "no sensor that can retest this finding" |

Eligibility (§5) becomes: an eligible status, a tool name and a rule id (non-empty,
printable, at most 255 bytes, no whitespace), the nuclei template guard when the
tool is nuclei, and the same asset gates (active, network-addressable, the
active-probe gate). Limits (§8.1), the per-finding pending slot, settle CAS,
activities (now with `method: tool | validate`), SLA restart and announcements
are the same for both methods.

### 12.2 The command

`type = retest`. Migration 001135 adds the type to `chk_command_type`; the
constraint is added `NOT VALID` and then validated, so no long lock is held on a
populated table.

```json
{"scanner": "<tool>", "retest_id": "<uuid>", "timeout_seconds": 120,
 "targets": ["<the §5 address of the finding>"],
 "items": [{"ref": "<finding id>", "target": "<the same address>", "kind": "finding",
            "rule_id": "<rule id>", "fingerprint": "<fingerprint>"}],
 "required_capabilities": ["retest:<tool>"]}
```

It names the tool as `scanner` and lists plain addresses, as a scan does. As a
result, the claim-time tool predicate, the sensor's admission of every target
against its local policy, and per-host scheduling all apply unchanged. The command
is produced only by `CommandDispatcher.DispatchToolRetest`, after the same
active-probe gate as every validate command (exclusions, private ranges,
attribution, scan-zone pinning). There is one finding per command, matching one
`finding_retests` row: `check_command_id` is the retest command, and
`reach_command_id` is NULL.

### 12.3 Settling

The sensor completes the command with the verdicts at `metadata.retest.verdicts`
(top-level `retest.verdicts` is accepted too). The verdict whose `ref` is the
retest's finding decides:

| Verdict | Outcome |
|---|---|
| `still_present` | still present |
| `fixed` | fixed |
| `unverifiable`, an unknown word, no verdict for this finding (a verdict for any other ref is ignored), unreadable result, failed / expired / canceled command, deadline | unknown |

"Fixed" is earned on the sensor. The SDK runtime downgrades `fixed` to
`unverifiable` unless the item's target was reported done and the task finished.
For nuclei, the tool connects to the address before it runs the template, so an
unreachable host is never "fixed". The platform still fails closed on anything
unclear. The nuclei template-drift rule (§6.2) applies only to the validate method.

### 12.4 Threat model additions

| Threat | Control |
|---|---|
| A compromised sensor fakes "fixed" | Only the command the platform issued to that sensor counts (command ownership), and the tenant comes from the command. Only a verdict for the finding id that was sent is read; anything else is unknown. RFC-039 limits are unchanged. |
| Scope widening through a retest | Targets come only from inventory, through the active-probe gate. The sensor refuses an item whose address is not one of the command's targets, and admits every target against its local policy (a policy that lists check types must list `retest`). |
| Destructive or noisy checks | The tool's own retest handler. For nuclei: one signed template, destructive tag classes excluded, the re-verification rate ceiling. |
| Cross-tenant request | Tenant from the token; a finding of another tenant is not found and nothing is queued (DB test). |

## 13. Sources

- nuclei rate limiting and template tags: <https://docs.projectdiscovery.io/tools/nuclei/running>
- OpenCTEM code at the commits named in §2.
