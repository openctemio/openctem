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
| `exposure_events` | per-tenant fingerprint dedup, first/last seen, state, history child; `certificate_expiring`/`port_open`/`service_changed` already in the CHECK constraint — **no producer** |
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
| 0 | `GET /scans/{id}/runs` snake_case contract | 0 | api#366 | **merged?** |
| 1 | Cancel button → real endpoint *(same change as #2)* | 0 | — | unblocked by #0 |
| 2 | Run history filtered by scan *(switch to pipeline runs)* | 0 | — | unblocked by #0 |
| 3 | `step_runs.started_at` | 0 | — | not started |
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
