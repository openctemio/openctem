# OASM vs OpenCTEM — comparison and adoption plan

> Living doc. Created 2026-07-27 from a source-level study of
> [oasm-platform/open-asm](https://github.com/oasm-platform/open-asm): their
> `console`, `core-api`, `worker` and `grpc-client`, plus 15 product
> screenshots. Every claim below was checked against both codebases; anything
> unverified is marked as such.
>
> **Status key:** ✅ have · 🟡 partial / built-but-unwired · ❌ missing · 🚫 deliberately not doing

---

## 1. Context before any comparison

| | OASM | OpenCTEM |
|---|---|---|
| Screens | 47 routes | **173 routes** |
| Tables | ~45 + 3 views | **178 + 4 views** |
| Tools | 5 built-in + 1 provider | tool subsystem ~13,200 LOC |
| Tenancy | workspace, reached by 3-hop join | `tenant_id` FK on every table |
| Scope | attack-surface discovery | full CTEM loop (5 stages) |

**We are the larger product on almost every axis, and this document does not
argue otherwise.** It exists because their model is better *factored* in a few
specific places, and because looking at ours through theirs exposed a set of
things we built and never connected.

### The vocabulary difference, since it comes up

They call scan compute **workers** because they had already spent the word
*agent* on their LLM assistant (`agent_conversations`, `agent_llm_configs`,
`agents/providers-connect`). We call ours **agents** and that is correct — a
worker is a queue consumer on your own infrastructure; an agent is a delegate
installed in someone else's, connecting outbound only because customer networks
are firewalled.

Two consequences worth deciding on before we add more tables:

1. We use one word for two things: a *tenant agent* (customer infra) and a
   *platform agent* (our infra, shared across tenants). The second is, in their
   vocabulary, a worker.
2. If we build an AI assistant, we hit the same collision they resolved by
   renaming. Pick the vocabulary first.

---

## 2. Feature comparison

### 2.1 Where we are ahead — do not spend time here

SLA policies · compliance frameworks · threat modelling (ATT&CK) · CTEM cycles ·
remediation campaigns · exception/approval workflow · business units · crown
jewels · attacker profiles · SBOM/components · EPSS + KEV **as data** (they copy
scores off a scanner) · risk snapshots (18 metrics/day incl. MTTR and SLA
compliance) · **asset relationship graph** (they have none) · DAG pipelines with
conditions/retries/timeouts · RBAC + groups + permission sets · i18n/RTL ·
per-tenant tool config · capacity-aware scan rotation · timezone-aware scheduling.

### 2.2 Screen-by-screen

| Their screen | What it does that ours doesn't | Ours | Status |
|---|---|---|---|
| Dashboard | KPI card = number + delta + **sparkline of that metric**; clicking navigates to a pre-filtered list. Single headline **Score**. **TLS expiry breakdown**. **Asset-IP world map**. | `quick-stat.tsx` is static text | ❌ |
| Assets list | One row carries: redirect badge `308 → 200`, **screenshot thumbnail**, tech chips **with vendor logos**, `SSL 58d` countdown, issuer, SANs | plain text cells; **no `<img>` anywhere in `ui/src`** | ❌ |
| Assets — filter bar | Add-filter chips (`+ IP`, `+ Port`, `+ Technology`, `+ Status Code`, `+ Host`, `+ TLS Host`, `+ Date`) shared across **7 pivot tabs**; switching tab keeps filters | sub-type is a **route**, so switching discards filter state | ❌ |
| Assets — Technologies tab | logo + **category chip** + real description + "N services" | no Technologies screen at all (we have 20+ other asset sub-routes) | ❌ |
| Asset detail sheet | Structured sections + **Certificate Age / Expires On / SSL Valid** + inline **`+ Add tag`** + **"View Full Page"** | sheet exists; **no link to the detail page** (verified: 0 matches) | 🟡 |
| Vulnerabilities list | **Tags column** with `+N` · **Scanned-by** (tool logo) · per-row **Analyze** button | tags stored, column absent; no per-row analyze | 🟡 |
| Vulnerability detail | Right rail with **decomposed CVSS table** (AV/AC/PR/UI/S/C/I/A) | raw vector as mono text — while we own the full metric dictionary in `cvss-calculator.tsx`, used only for pentest authoring | 🟡 |
| Jobs Registry — run detail | **Pipeline strip** (tool logos chained, per-tool status) + one row per **(tool × target)** with **duration** + error dialog + per-row cancel | **no run-detail route**; `scans/[id]` renders `pipeline_id` as a raw UUID | ❌ |
| Tools grid | live **worker count per tool** ("3 workers" / "Offline") + Install button | `is_available` exists but is only a **silent filter**; the grid never says a tool is unrunnable | 🟡 |
| Workers | card shows **which tools that worker supports** (logos) | not shown | ❌ |
| Integrations | catalogue with **Applications / Connected** tabs, search + category filter, **"Coming soon"** badges, multiple named instances per provider ("Slack 1") | bespoke page per provider (ticketing 890 LOC, security 826, scm 554, notifications 727) | 🟡 |
| Integrations — connect form | **JSON-Schema driven**: adding a provider costs **zero frontend code** | bespoke form per provider | ❌ |
| MCP Connect | copy-paste client JSON | ✅ `/settings/integrations/mcp`, with tests (RFC-016) | ✅ |
| Settings | own shell with **grouped secondary nav** (Workspace / Account / Integration / System) | ~27 leaves in the **primary sidebar**; both settings layouts are literal pass-throughs | ❌ |
| Brand name & logo | white-label | nothing | ❌ |
| Global search | header search → `/search`, results grouped by entity, saved history | ⌘K maps `sidebarData.navGroups` only — **finds menu items, not data**. `buildSearchEndpoint` has no callers; **no search route on the API** | ❌ |
| AI assistant | agentic chat: model picker, **Todo checklist**, **Tool Calls panel**, tables in answers | per-finding AI triage (real, WebSocket, ~1,664 LOC) but no chat; `AIMode`/`monthlyTokenLimit`/`tokensUsedThisMonth` mapped with **no UI reading them** | 🟡 |

### 2.3 Built here, never connected

The most actionable category — no new capability required, only wiring.

| Thing | Evidence |
|---|---|
| `tool_executions` | table + repository + service (`Record`/`Complete`/`Fail`/`Timeout`/`List`) + tests + FKs to `pipeline_run_id`/`step_run_id` — **zero production callers** |
| Suppression rules | full approval workflow; `FindMatchingRules` and `RecordSuppression` have **no callers**. An approved suppression changes nothing |
| `exposure_events` | per-tenant fingerprint dedup, first/last seen, state, history child; 21 types in the CHECK constraint but **only `credential_leaked` is produced automatically** — every other type needs a client to POST it, so no scan ever emits one. (Corrected: an earlier draft of this row said "no producer", which was wrong — there are 3 INSERT paths and 16 live rows.) |
| `useScanChannel` | typed WebSocket `scan_progress` events, fully built — **zero consumers**; we poll at a fixed 10s/30s instead |
| Orphan settings pages | `/settings/sla-policies` (262 LOC), `/settings/access-control/permission-sets` (723), `/settings/general` (325), `/settings/notifications` (249), `/sla` (430) — **no sidebar entry** |
| Geo/ASN | `country`, `city`, `asn`, `asn_org`, geolocation persisted at ingest — **rendered nowhere** |
| Certificate data | richer than theirs (SANs, issuer, not_before, fingerprint) — but the only index is a `jsonb_path_ops` GIN, which **cannot serve a range predicate** |
| `asset_services` | better schema than theirs (protocol, product, version, banner, CPE, TLS, state, last_seen, risk_score) — **no ingest path writes it**; only the REST handler does |

### 2.4 Correctness problems found along the way

Independent of OASM; worth fixing regardless.

| Problem | Evidence |
|---|---|
| Pipeline chain arrows are decoration | `run.go:305` passes the same frozen `run.Context` to step 1 and step 7; `step_runs.output` is written and **never read**. In *Full Reconnaissance*, `httpx` gets the seed domain `subfinder` got — never the subdomains it found |
| 8 of 12 preset tools unregistered | `amass, nmap, dalfox, sqlmap, ffuf, gowitness, wappalyzer, tlsx` have no `tools` row → 5 of 6 preset pipelines cannot complete |
| Three dispatch paths | `scan.triggerWorkflow` ignores `depends_on` and never evaluates conditions, so conditions silently do not apply to scheduled scans |
| Cancel button 404s | UI calls `POST /scan-sessions/{id}/stop`, which does not exist; the working `POST /pipeline-runs/{id}/cancel` is unwired |
| Run history unfiltered | `/scans/{id}` calls `useScanSessions({per_page:10})` with no scan filter → shows the tenant's last 10 runs regardless of which scan you opened |
| Durations always 0 | nothing calls `StepRun.Start()`, so `started_at` is never written |
| Failure detail discarded | on failure the agent posts only `error_message`, dropping `DurationMs`/`ExitCode`/`Metadata`; `error_code` is the constant `"COMMAND_FAILED"` |
| Fake agent metrics | the monitoring card derives CPU/memory/active-jobs from a **hash of the agent ID** while the table beside it shows real values |

---

## 3. Plan

Phases are ordered so each one is shippable on its own and unblocks the next.
Nothing here is started until it has an entry in the tracking table at the end.

### The ordering was wrong, and verification is what showed it

This plan originally ranked work by *"what OASM has that we don't"*. That is the
wrong axis. The right one is **"what does the product claim that isn't true"** —
and the top of that list is not a missing feature. It is that a scan which
succeeds is reported to the user as a failure.

Everything in Phase P0 below was proven against the live database and the source,
not inferred. Two of this document's own earlier claims were **disproved** in the
process and are corrected in place. Read Phase P0 before scheduling anything else:
several later phases polish surfaces that render a falsehood until it lands.

### Phase P0 — the scan loop is open *(do this first)*

Four defects, one root: **the scan path creates work but never closes the loop
over it.**

**P0.1 — nothing completes a run on the scan path.**
`run.Complete()` has exactly one caller in the whole API:
`internal/app/workflow/executor.go:644`, which belongs to the *automation
workflow* engine — a different subsystem. A scan creates a run, creates a
command, the agent executes it, and then nothing marks the run complete. The run
stays `running` until `scan_timeout` overwrites it with
`"scan exceeded configured timeout"`.

Live evidence matches exactly: **8 commands `completed`** — the work did run —
while **all 5 scan-triggered runs ended `timeout` with `completed_steps = 0`**.

**P0.2 — the timeout reaper cannot see runs that belong to no scan.**
`PipelineRunRepository.MarkTimedOutRuns` (`pipeline_run_repository.go:456`) is
`UPDATE pipeline_runs pr ... FROM scans s WHERE pr.scan_id = s.id` — an inner
join. `Run.ScanID` is `*shared.ID`, so a run triggered straight from a pipeline
has `scan_id IS NULL` and is structurally unreachable. `scan_timeout.go` is the
only controller that touches `pipeline_runs` (`job_recovery.go` handles commands
only), so nothing else reaps them. Live: **2 runs stuck `running` for 11 days.**

**P0.3 — `step_runs` is empty by design on the single-scanner path.**
`scan/trigger.go:243` sets `SetTotalSteps(1)` and creates a command directly,
without creating a step run. So step progress is structurally `0/1` forever.

> This **disproves item 3 of the old Phase 0** ("write `step_runs.started_at`;
> `StepRun.Start()` has no call site"). On the scan path there is no step run to
> start. Decide P0.3 before touching `started_at` — otherwise the fix lands in a
> code path the scan never executes.

**P0.4 — multi-step pipelines dispatch every step with no target at all.**
`queueStepForExecutionWithSettings` (`run.go:283`) is the only pipeline-step
command builder, and its payload has no `target`/`targets` key — just
`step_config`, `preferred_tool`, and the frozen `run.Context`. The agent reads
only top-level keys (`agent/internal/executor/recon.go:662-698`,
`reconPayload{Tool, Scanner, Target, Targets, ...}`) and never looks inside
`context`. `scan/trigger.go:305` lifts `targets` to the top level, but
`scheduleWorkflowSteps` calls that path **only for `StepOrder == 1`**.

Consequence for the shipped `Full Reconnaissance` preset
(`migrations/000061_preset_pipeline_templates.up.sql:172`): triggered from
`POST /pipelines/runs`, *no* step gets a target — subfinder included. Triggered
as a workflow scan, only step 1 gets the seed; `httpx` then runs with an empty
target list. `depends_on` is purely a scheduling edge
(`template.GetRunnableSteps`), never a data edge.

`step_runs.output` is not merely unread — it is never populated. The API expects
`result.Output` (`command_handler.go:628`) but the wire contract has no such key
(`sdk-go/pkg/core/command_poller.go:34`; the recon executor returns data under
`Metadata`), so `Complete(n, nil)` leaves it `{}` on every row.
`Service.CompleteStepRun` (`run.go:853`), the one function that could write a
real output, has no callers and no route.

*Fix direction (server-side re-query is preferred over a wire-contract change):*
resolve targets from the DB at dispatch time in
`queueStepForExecutionWithSettings` and lift them to `payload["targets"]`,
filtered by the step tool's `supported_targets` (reuse `scan/filtering.go`).
Prerequisite: ingest must link newly-discovered assets to the originating
scan/run — `AssetGroupRepository.AddAssets` has only manual/UI callers today.
**Two things must land with it, not after:** server-side scope/SSRF validation of
the injected targets (`SecurityValidator.ValidateCommandPayload` does not check a
`targets` key, so today only the agent's `targetguard` would), and a cap or
batching, since pipelines have no equivalent of the scan path's
`targets_per_job`.

### Phase P1 — features that report success without doing the work

| Thing | What is actually true | What the user sees |
|---|---|---|
| Suppression rules | `CheckSuppression`/`ApplySuppression` (`pkg/domain/suppression/service.go:279,284`) have zero callers, and the findings query never joins `finding_suppressions` | A rule can be authored, approved, and shown ACTIVE while every matching finding keeps its original status |
| `asset_services` | CTIS already ships `Services []ServiceInfo` and `Ports []PortInfo`; the ingest processor reads neither. `UpsertBatch` has no callers — only the REST handler writes | Services view empty and `/services/stats` reports zeros, though every recon scan already carried the data |
| `tool_executions` | Never written, but **is read** by `GetToolStats`/`GetTenantToolStats`, which are routed | `/tenant-tools/stats` always reports zero executions and zero success rate. Natural call site: `run.go:854 CompleteStepRun` |
| `exposure_events` | Only `credential_leaked` is produced automatically (`integration/credential_import.go:197`); the other 20 types are reachable only if a client POSTs them | Attack-surface *change* is invisible: a newly-open port or an expiring certificate produces no event |

> **Correction.** Section 2.3 previously said `exposure_events` has *no* producer.
> That is wrong — there are three INSERT paths and 16 live rows across 8 types.
> The accurate claim is the narrower one above.

### Phase P2 — fix the silent-failure class, not the instances

`scan/trigger.go:180` demotes a failed `stepRunRepo.Create` to `logger.Warn` and
continues; `:188` does the same for `runRepo.Update`. This is the same class as
the ~30 save-drop defects already fixed elsewhere. Worth a CI gate that flags a
`logger.Warn` on the error branch of a repository write, the way
`scripts/check-sql-schema.sh` closed the schema-drift class in one move.

### Phase P3 — real-time instead of polling *(after P0)*

`useScanChannel` is fully built with zero consumers — and the server never emits
`scan_progress` either (zero hits across the API), so it is half-built on both
ends. The UI polls at 10s (`scans/[id]`) and 30s (`scans`, pipeline overview).
Cheap to finish, but pointless until P0 makes run status mean something.

### Phase 0 — repair the run-history surface *(days — re-scoped)*
Cancel the open run · filter run history to the open scan · write
`step_runs.started_at` · name a run `"<template> — <target>"`.

*Why first:* three of the four are prerequisites for anything that displays run
progress.

**This phase was mis-scoped in the first draft.** It called the first two
"one-line" fixes, assuming the run history was already the right entity and
needed only a filter and a URL. Verification says otherwise:

- The scan-detail page lists **agent scan sessions**, a different entity.
  `scan_sessions` has **no `scan_id` and no `pipeline_run_id`** (checked against
  the live schema), so that list can never be narrowed to the scan you opened —
  it shows the tenant's last 10 sessions whichever scan you are on.
- Its Cancel button posts to `/scan-sessions/{id}/stop`. The `scan-sessions`
  route group has no `/stop` — only GET stats/list/{id} and DELETE.
- The right entity is **pipeline runs**: they carry `scan_id`, and
  `POST /pipeline-runs/{id}/cancel` exists. `GET /scans/{id}/runs` already
  returns them.
- But that endpoint served the domain entity directly, and `pipeline.Run` has no
  json tags — so it emitted PascalCase against a snake_case API. That is why it
  had zero consumers despite the UI already having a URL builder for it.

So items 1 and 2 are not two one-liners; they are one change — switch the page to
pipeline runs and rebuild the table columns for that shape — gated on an API fix.
`step_runs.started_at` is not a one-liner either: `StepRun.Start()` sets it but
**nothing calls it**, so it needs a call site in the command lifecycle.

*Status:* API contract fixed in api#366. The UI switch, the `started_at` call
site, and the run display name remain.

### Phase 1 — surface what we already store *(days)*
Tags + scanned-by columns on findings · worker count and unrunnable state on the
tools grid · supported tools on the worker card · `View Full Page` from the asset
sheet · `/settings/ai` reading the AI fields already mapped · geo/ASN columns and
a country rollup · decomposed CVSS panel.

*Why:* no new storage, no new capability — the data is already persisted and the
components mostly exist. This is the highest value-to-effort work available.

### Phase 2 — the cert-expiry surface *(days)*
Partial btree on `((properties->'certificate'->>'not_after'))` where
`asset_type='certificate'` — all writers emit RFC3339 UTC, so lexical order is
chronological and we avoid a non-IMMUTABLE cast. Then `?expiring_within=30d`,
sort-by-expiry, dashboard tiles, and the `SSL 58d` badge on rows.

*Why here:* one migration unlocks a whole product surface, and it is the
precondition for the `certificate_expiring` producer in Phase 4.

### Phase 3 — run observability *(1–2 weeks)*
Run-detail route (pipeline strip + per-step rows + error panel) · expose
`step_runs.output` in the DTO · stop discarding failure detail · activate
`tool_executions` at dispatch and on result · then **fan out one execution row
per (step × asset)**.

*Why the fan-out matters:* our unit of execution is one row per **step**; theirs
is one row per **(tool × target)**. Until we match that, no amount of UI work can
show "naabu on host-17: 4s, failed" — there is nothing to render.

### Phase 4 — the change feed *(1–2 weeks)*
Producers for `exposure_events`: a diff pass at ingest (old properties vs new)
and a scheduled scan over `not_after`. Record recon deltas in
`asset_state_history` rather than building a probe-history table.

*Why:* "what changed on my attack surface" is what makes an ASM product feel
alive. **OASM does not have this either** — they keep append-only probe history
and never diff it. Zero migration required on our side.

### Phase 5 — settings shell *(1 week)*
A real `settings/layout.tsx` with grouped secondary nav from a
`config/settings-nav.ts`, reusing the existing permission/module gating.
Collapses ~27 leaves out of the primary sidebar and gives the orphaned settings
pages a home.

### Phase 6 — pipelines that are actually pipelines *(2+ weeks)*
Feed step N's output into step N+1 by resolving targets from the asset graph
filtered by the step tool's `supported_targets`, instead of replaying the frozen
`run.Context` · register the 8 missing preset tools or trim the presets ·
collapse the three dispatch paths into one.

### Phase 7 — new surfaces *(scoped separately)*
Global search (needs an API route — we have none) · asset screenshots · shared
filter bar over asset pivots · technology catalogue · JSON-Schema integration
forms · white-label.

### Explicitly not doing 🚫

Tenancy by join · globally-unique vulnerability fingerprints with no tenant
column · live geo lookup per page load · `http_responses.body TEXT` per probe ·
linear-only chains · a six-value cron enum · their workflow builder and YAML
studio (both orphaned in their repo) · gRPC bidirectional workers · shell-command
tool templates.

---

## 4. Tracking

Update this table as items land. **An item is not started until it appears here.**

| # | Item | Phase | PR | Status |
|---|---|---|---|---|
| P0.1 | Scan runs never complete → every scan reports timeout | P0 | — | not started |
| P0.2 | Timeout reaper blind to `scan_id IS NULL` runs | P0 | — | not started |
| P0.3 | Decide the step-run model for the single-scanner path | P0 | — | not started |
| P0.4 | Pipeline steps dispatched with no target (presets inert) | P0 | — | not started |
| P1.1 | Suppression rules suppress nothing | P1 | — | not started |
| P1.2 | Ingest drops CTIS ports/services → `asset_services` | P1 | — | not started |
| P1.3 | `tool_executions` never written → tool stats always zero | P1 | — | not started |
| P1.4 | Exposure events only for `credential_leaked` | P1 | — | not started |
| P2.1 | CI gate: `logger.Warn` on a repo-write error branch | P2 | — | not started |
| P3.1 | Emit + consume `scan_progress`, drop the 10s/30s polling | P3 | — | not started |
| 0 | `GET /scans/{id}/runs` snake_case contract | 0 | api#366 | merged |
| 1+2 | Run history + Cancel on the scan detail page | 0 | ui#335 | in review |
| 3 | `step_runs.started_at` | 0 | — | **blocked on P0.3** |
| 4 | Run display name | 0 | — | not started |
| 5 | Findings: tags + scanned-by columns | 1 | — | not started |
| 6 | Tools grid: worker count + unrunnable | 1 | — | not started |
| 7 | Worker card: supported tools | 1 | — | not started |
| 8 | Asset sheet → View Full Page | 1 | — | not started |
| 9 | `/settings/ai` | 1 | — | not started |
| 10 | Geo/ASN columns + country rollup | 1 | — | not started |
| 11 | CVSS decomposition panel | 1 | — | not started |
| 12 | `not_after` index + expiry surface | 2 | — | not started |
| 13 | Run-detail route | 3 | — | not started |
| 14 | Preserve failure detail | 3 | — | not started |
| 15 | Activate `tool_executions` | 3 | — | not started |
| 16 | Fan out per (step × asset) | 3 | — | not started |
| 17 | `exposure_events` producers | 4 | — | not started |
| 18 | Recon deltas → `asset_state_history` | 4 | — | not started |
| 19 | Settings shell | 5 | — | not started |
| 20 | Step output → next step | 6 | — | not started |
| 21 | Register/trim preset tools | 6 | — | not started |
| 22 | Collapse dispatch paths | 6 | — | not started |
| 23 | Global search (API + UI) | 7 | — | not started |
| 24 | Asset screenshots | 7 | — | not started |
| 25 | Shared filter bar over pivots | 7 | — | not started |
| 26 | Technology catalogue | 7 | — | not started |
| 27 | JSON-Schema integration forms | 7 | — | not started |
| 28 | White-label brand | 7 | — | not started |

### Separately tracked — correctness, not features

| Item | Status |
|---|---|
| Suppression rules never suppress | not started |
| Fake agent metrics in the monitoring card | not started |
| Orphan settings pages unreachable | folded into Phase 5 |

---

## 5. Method and limits

Neither system was executed; findings come from source and from their published
screenshots. Claims about our own code were re-verified directly against this
repository. Statements about query plans ("cannot serve a range predicate") are
read from index definitions, not from `EXPLAIN` against a populated database.

Their source was read at a commit fetched on 2026-07-27; they are actively
developing, so re-check before treating any specific line reference as current.
