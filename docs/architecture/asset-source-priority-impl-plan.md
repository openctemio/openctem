# Asset Source Priority — Implementation Plan

> **Companion to**: [RFC-003 Asset Source Priority](./asset-source-priority.md)
>
> **Status**: Draft — pending customer sign-off on 8 open questions
>
> **Target release**: v0.3.0 (~2.5 weeks dev time + review)

## TL;DR

6 phases, each independently shippable. Backward-compatible at every step — tenants that do not opt in keep today's exact behavior. No data migration is destructive; no feature flag is required because opt-in is implicit (empty priority list = status quo).

| Phase | Name | Duration | Shippable alone? |
|---|---|---|---|
| 1a | Core backend foundation | 2 days | Yes — no behavior change yet |
| 1b | Ingest priority gate | 2 days | Yes — honors settings if present |
| 1c | Source-creation UX (trust level dropdown) | 2 days | Yes — populates backend |
| 1d | Field attribution & skip-audit API | 2 days | Yes — read-only additions |
| 1e | Settings page drag-to-reorder | 1.5 days | Yes — power-user flow |
| 1f | Tests, observability, docs | 2 days | Closes Phase 1 |
| — | Buffer / review cycles | 1.5 days | — |
| **Total** | | **~13 working days** | |

## Pre-flight checklist (before Phase 1a)

Must complete **before** writing code. These are blocking — skipping any of them risks Phase 1b rewriting Phase 1a.

- [ ] **Customer review of RFC-003** — the six original open questions answered
- [ ] **Decision on trust-level vocabulary** — proposed: `Primary | High | Medium | Low` (see Open question 7 below)
- [ ] **Decision on bucket tie-breaker** — last-write-wins inside a bucket vs explicit sub-order (Open question 8)
- [ ] **Design review sync** — 30-min call with ingest + UI leads; decision log committed to the RFC
- [ ] **Migration rehearsal** — `000163_asset_source_priority.up.sql` dry-run against a dev snapshot; confirm the partial index does not block inserts on `asset_sources`

Exit gate: RFC-003 status moves from `Draft` to `Accepted`, with a decision log at the bottom.

## Architectural constraints (non-negotiable)

These hold across every phase. If any is violated, the design is wrong — stop and redesign.

1. **Empty priority list = today's behavior.** A tenant with no configured priority must see exactly the same merge outcome after the release as before. Regression test covers this.
2. **Fail open.** Any error in the priority gate (DB error, cache miss, deleted source UUID) defaults to allowing the write. Losing data is worse than wrong precedence for a few seconds.
3. **No destructive migration.** `assets.properties` is never rewritten. Attribution starts at the first post-opt-in write; pre-existing fields are treated as "unattributed" and can be overwritten by any source, by design.
4. **Single domain model, three UX surfaces.** Agent creation, integration creation, and CSV import dialog all write to the same `tenant.settings.asset_source.priority` list. Do not duplicate state.
5. **Every phase is reversible in < 5 min.** Clearing the priority list or disabling `TrackFieldAttribution` returns to previous behavior within one Redis TTL cycle. Verified at end of Phase 1b.

## Phase 1a — Core Backend Foundation

**Goal**: domain types + settings API + migration. **Zero behavior change** in the hot path. This phase unblocks Phases 1b and 1c running in parallel.

**Deliverables**

- `pkg/domain/tenant/settings.go` — add `AssetSourceSettings` with `Priority []shared.ID`, `TrustLevelBuckets map[shared.ID]TrustLevel`, `TrackFieldAttribution bool`
- `pkg/domain/tenant/trust_level.go` — new file: `TrustLevel` enum with `Primary / High / Medium / Low` constants + validation
- `migrations/000163_asset_source_priority.up.sql` (+ `down`) — index only, no data rewrite
- `internal/app/tenant/settings.go` — extend `UpdateSettings` path; add `UpdateAssetSourceSettings(ctx, tenantID, input)` with UUID-exists validation
- `internal/infra/http/handler/tenant_handler.go` — extend `GET /settings` response; add `PUT /settings/asset-source`
- `internal/infra/http/routes/tenant.go` — register new route behind `permission.TeamUpdate`
- `tests/unit/tenant/asset_source_settings_test.go` — validation cases
- `tests/integration/settings_asset_source_test.go` — round-trip through HTTP

**Exit criteria**

- Admin can `curl -X PUT /api/v1/tenants/{id}/settings/asset-source` and read it back.
- Ingest merge logic is **unchanged** — Phase 1a does not touch `processor_assets.go`.
- CI green; migration applies + rolls back cleanly against dev DB.

**Risks**

- Settings JSON schema drift — mitigate with a `SchemaVersion int` field on `AssetSourceSettings`, default 1.
- Validation edge cases (duplicate UUIDs, UUID belonging to another tenant) — explicit test matrix.

## Phase 1b — Ingest Priority Gate

**Goal**: the priority config is actually enforced. Depends on 1a's types but not the settings API (tests use in-memory settings).

**Deliverables**

- `internal/app/ingest/priority_gate.go` — `PriorityGate` interface + Postgres impl; reads tenant settings, ranks incoming source against the last writer per field
- `internal/app/ingest/processor_assets.go` — call `gate.CanWrite` inside `mergePropertiesDeep`; batch lookups for bulk CTIS to one call per `(tenant, asset, source)`
- `internal/infra/postgres/asset_source_repo.go` — extend `UpsertAssetSource` to set `last_seen_at`, `is_primary`, `confidence`
- `internal/app/ingest/priority_gate_cache.go` — Redis-backed cache (5-min TTL) keyed by `priority_gate:{tenant}` to avoid re-reading settings on every field
- `tests/unit/ingest/priority_gate_test.go` — the core matrix:
  - Ordered priority → higher bucket wins
  - Two sources in the same bucket → today's behavior (last-write-wins)
  - Unlisted source vs listed → listed wins always
  - Missing source UUID (deleted) → treated as lowest, log once per batch
  - Empty priority → today's behavior (regression guard)
- `tests/integration/asset_source_priority_test.go` — two CTIS payloads in sequence, same asset, different sources; assert correct field wins

**Exit criteria**

- Regression test: tenant with empty priority → bit-for-bit identical merge output as before.
- A staging run with 2 scanners + 1 priority setting shows the expected field wins.
- Gate lookup P95 < 10ms (covered by cache).

**Risks**

- Cache staleness when admin changes settings — invalidate on `PUT /settings/asset-source` via existing SWR/WebSocket pattern.
- Batch merge complexity — keep the single-field path as the reference implementation; batch is an optimization with its own unit test parity check.

## Phase 1c — Source-Creation UX (the user's original ask)

**Goal**: capture trust-level intent at the moment the user creates a source, not hidden in Settings. This phase is **UI-only** — writes to the backend from Phase 1a.

**Deliverables (UI repo, new branch off develop)**

- `src/features/agents/components/agent-create-dialog.tsx` — add `TrustLevel` dropdown (`Primary | High | Medium | Low`), default `Medium`
- `src/features/integrations/components/integration-create-dialog.tsx` — same dropdown
- `src/features/assets/components/csv-import-dialog.tsx` — same dropdown, scoped to the import batch (ephemeral data source record)
- `src/features/shared/components/trust-level-select.tsx` — reusable select + tooltip explaining each level
- `src/features/organization/api/use-asset-source-settings.ts` — SWR hook for read + PATCH
- Submission path: on agent/integration/CSV-import creation, after the entity is created, issue `PATCH /settings/asset-source` appending the new source at the correct bucket position
- `src/components/__tests__/trust-level-select.test.tsx` — accessibility + keyboard nav
- `src/features/agents/__tests__/agent-create-dialog.test.tsx` — stubbed network assertion that trust level is propagated

**Exit criteria**

- Creating an agent with `Primary` trust writes to settings in one user action — verified by reading `GET /settings/asset-source` after.
- Dropdown default is `Medium` (neutral — preserves today's behavior for operators who don't care).
- Tooltip copy reviewed by product/docs lead.

**Risks**

- Race: user creates agent, then writes settings — if settings write fails, agent exists but is unranked. Mitigation: write settings first as a pending entry (optimistic), commit on agent-create success; roll back on failure.
- 3 dialogs × same dropdown → code drift. Mitigation: shared `TrustLevelSelect` component + shared submission hook.

## Phase 1d — Field Attribution & Skip-Audit API

**Goal**: explainability. User can see why their data looks the way it does.

**Deliverables**

- `internal/app/ingest/processor_assets.go` — when `TrackFieldAttribution=true`, populate `asset_sources.contributed_data.fields` (value_hash + timestamp) on every successful write
- Same path — when the gate rejects a write, append to `asset_sources.contributed_data.skipped` (capped at 500 entries; oldest dropped)
- `internal/infra/http/handler/asset_handler.go` — extend `GET /assets/{id}?include=field_sources`
- `internal/infra/http/handler/asset_handler.go` — new `GET /assets/{id}/source-skips?limit=20`
- Migration 000169 (optional) — if storage growth is worrying after Phase 1b staging, add a background job `asset_source_attrition_pruner` that trims `contributed_data` for cold assets

**Exit criteria**

- `GET /assets/{id}?include=field_sources` returns per-field source info for a tenant with `TrackFieldAttribution=true`.
- Skip-audit endpoint lists recent blocked writes.
- Storage growth on a seeded 10K-asset tenant with attribution on is < 15MB (reasonable ceiling).

**Risks**

- `contributed_data` JSONB bloat — mitigated by 500-entry cap + optional pruner.
- Privacy: `value_hash` (sha256) not raw value — explicitly documented. Never store the raw value in attribution.

## Phase 1e — Settings Page Drag-to-Reorder

**Goal**: power-user flow. Admins who want to fine-tune ordering (beyond the 4 buckets) can do so.

**Deliverables**

- `src/app/(dashboard)/settings/asset-sources/page.tsx` — new page under Settings → Organization
- `src/features/asset-sources/components/priority-list.tsx` — drag-to-reorder using existing `@dnd-kit` already in deps
- Source-type badges inline: `(agent) | (integration) | (manual) | (import)` alongside source name
- "Advanced" collapsible: numeric rank override, `TrackFieldAttribution` toggle
- Warning banner when priority list does not include any `scanner`-type source (would block all scanner data)
- `src/config/sidebar-data.ts` — add entry under Settings → Organization → "Asset Sources"
- `src/config/route-permissions.ts` — `/settings/asset-sources` requires `TeamUpdate`

**Exit criteria**

- Admin can reorder, save, reload — ordering persists.
- Sidebar-route consistency test still passes (from the previous fix).
- UI Playwright: two-scanner scenario → correct badge post-ingest.

**Risks**

- None material — pure UI on top of Phase 1a's API.

## Phase 1f — Tests, Observability, Docs

**Goal**: production readiness. Not optional; Phase 1 is not "done" until this ships.

**Deliverables**

- **Observability**
  - Prometheus counter `asset_source_priority_skipped_total{tenant, source, reason}`
  - Info log (sampled 1:100): `priority_gate_skipped field=X source=Y reason=lower_priority`
  - Grafana panel: skipped-writes per tenant per day, shipped as JSON in `docs/dashboards/`
- **Load test**
  - Generate 10K-asset tenant with 3 sources at different priorities; measure ingest throughput vs main
  - Acceptance: < 5% throughput regression vs pre-feature baseline
- **Docs**
  - Update `docs/architecture/asset-source-priority.md` — move `Draft` → `Accepted`, append decision log
  - New `docs/operations/asset-source-priority-admin.md` — how to configure, examples, FAQ
  - Update `api/CLAUDE.md` Recent Changes with migration number
  - Customer-facing changelog entry
- **Runbook**
  - "Customer reports wrong field value" — grep logs for `priority_gate_skipped`, check `contributed_data.skipped` on the asset
  - "Tenant wants to reset priority" — single-line API call documented

**Exit criteria**

- All unit + integration + contract + E2E tests pass.
- Load test meets the < 5% regression bar.
- Runbook reviewed by one SRE / ops person.

## Rollout order (suggested PRs)

One PR per phase, merged in order. No phase can skip its exit criteria.

```
PR #1  (api)      feat(tenant): asset-source settings domain + migration + API    ← Phase 1a
PR #2  (api)      feat(ingest): priority gate + attribution writes (opt-in)        ← Phase 1b + 1d backend
PR #3  (ui)       feat(sources): trust-level dropdown in 3 creation dialogs        ← Phase 1c
PR #4  (ui)       feat(settings): asset-sources drag-to-reorder page               ← Phase 1e
PR #5  (api+ui)   feat(attribution): field-source API + UI badges + skip panel    ← Phase 1d UI
PR #6  (api+docs) test+obs+runbook                                                  ← Phase 1f
```

Each PR should be < 800 lines diff to stay reviewable. Phase 1b is the largest risk — split PR #2 into two (gate + attribution) if it grows too big.

## Feature interactions to watch

Do not assume these integrate cleanly — each needs a test.

1. **Asset identity resolution (RFC-001)** — when IP correlation merges two previously-separate assets into one, which asset's attribution survives? Proposal: union both, de-dupe by `(source_id, field)`; explicit test case.
2. **Finding ingest** — findings reference assets but are not themselves subject to source priority (for now). Phase 1 does not touch finding ingest; Phase 2 may extend.
3. **Runtime telemetry (migration 000155)** — telemetry events populate some asset fields (ports, last_seen). Proposal: telemetry source is always `Medium` trust by default; operators can re-rank.
4. **CSV re-import** — same CSV imported twice should not create two "CSV import" entries in the priority list. Mitigate by hashing the import config and reusing an existing `data_sources` row.
5. **Integration token rotation** — does not create a new `data_sources` row; priority stays stable. Regression test guards this.

## What is explicitly NOT in Phase 1

Promised-to-stakeholders-but-not-this-phase. Scope discipline.

- **Per-field priority** — "Nessus for CVE, osquery for OS" — Phase 2.
- **Policy engine** — declarative rules like `severity: highest-wins`, `tags: union` — Phase 2.
- **Reprocessing endpoint** — re-apply priority to historic assets — Phase 2, requires `source_id` on finding history (doesn't exist today).
- **Cross-tenant defaults** — a platform-level default priority list — not in scope until multi-tenant customer demand appears.
- **UI: per-asset override** — "This one asset's OS is manually set, ignore all agents" — good idea but needs separate design (one-off suppression flag on the asset, not on the source).
- **SDK client support** — agents currently report source via API key; SDK would need to know its own trust level. Phase 2 or Phase 3.

## Decision checkpoints

Three checkpoints where we pause and make a go/no-go call.

1. **After Phase 1a** — is the settings API shape right? Run it past the UI team before they commit to dialog work.
2. **After Phase 1b** — does a real staging tenant with 3 sources produce the expected ordering? If not, the gate algorithm needs tuning before Phase 1c–1e depend on it.
3. **After Phase 1c + 1e** — is the UX actually easier than the original "Settings only" design? Dogfood internally for 2 days before release.

## Open questions (added beyond RFC-003)

7. **Trust-level vocabulary** — `Primary | High | Medium | Low`? Or numeric 1–10? Or customer-named levels? Proposal: hardcoded 4 buckets for v1, customer-named in Phase 2.

8. **Same-bucket tie-break** — last-write-wins, or implicit ordering by `data_sources.created_at`? Proposal: last-write-wins, matches today's feel; add explicit sub-order in Phase 2 if customers complain.

9. **Default trust level for existing sources** — at migration time, all existing `data_sources` start at `Medium`. Is this right, or should we default to `Primary` for manual entries and `Medium` for the rest? Proposal: `Manual → Primary, everything else → Medium` at migration; admin can rebalance.

## References

- [RFC-003 — Asset Source Priority & Field Attribution](./asset-source-priority.md)
- [RFC-001 — Asset Identity Resolution](./asset-identity-resolution.md)
- [Data Sources architecture](./data-sources.md)
- Tenant settings pattern: `pkg/domain/tenant/settings.go`
- Existing merge logic: `internal/app/ingest/processor_assets.go:mergeCTISIntoAsset`
