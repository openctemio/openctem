# Asset Source Priority & Field Attribution

> **Status**: Draft — pending customer review | **Origin**: RFC-003 (2026-04-23)
>
> **Target release**: v0.3.0 (Phase 1)
>
> **Authors**: Platform team
>
> **Reviewers**: Customer success, ingest owners, UI lead

## Problem

A single real-world asset is observed by multiple data sources — Nessus scan, internal agent, cloud API, manual entry. Each source reports overlapping but conflicting information (OS, severity, owner, tags). Today every re-ingest deep-merges the new payload into `assets.properties`: on duplicate keys **the last writer wins**. Customers with a trusted source (e.g. CMDB or Nessus) want that source to be the authoritative answer for fields they care about — a lower-trust source that happens to run afterwards must not clobber it.

Concrete customer ask:

> "We have four sources feeding assets. Nessus is our source of truth for CVE data. When a weekly cloud-discovery run sends a thinner record, it shouldn't overwrite what Nessus just said."

## Goals

1. **Per-tenant source priority** — admin picks an ordered list of trusted sources.
2. **Field-level attribution** — know which source wrote which field, visible in UI and API.
3. **Backward compatible** — tenants without a priority list keep today's behavior (last-write-wins).
4. **No data loss** — a skipped override is recorded, not silently dropped.

## Non-goals

- Per-field priority lists (Phase 2).
- Policy engine with rules like `severity: highest-wins` (Phase 2).
- Historic reprocessing of assets ingested before this RFC ships (Phase 2; current data has no lineage to replay).
- Cross-tenant global defaults.

## Current state (as of 2026-04-23)

What exists:

| Capability | Where | Gap |
|---|---|---|
| `asset_sources` table with `source_type`, `source_id`, `is_primary`, `confidence`, `contributed_data JSONB` | `migrations/000014_data_sources.up.sql` | `is_primary` + `contributed_data` never populated by ingest |
| `SourceType` enum: `integration \| collector \| scanner \| manual` | `pkg/domain/datasource/value_objects.go` | No canonical registry for tool names (nessus/burp/nmap are free strings) |
| Typed `tenant.Settings` with JSONB persistence | `pkg/domain/tenant/settings.go` | No `AssetSourcePriority` field yet |
| Field-level deep merge of `properties` | `internal/app/ingest/processor_assets.go:mergePropertiesDeep` | Last-write-wins on conflict; no source check |
| IP correlation for asset dedup (RFC-001) | `internal/app/ingest/correlator.go` | Orthogonal — already merged into same asset, just can't tell sources apart |
| Alias history (max 10) when asset renamed | `pkg/domain/asset/entity.go:UpdateName` | Only name — no per-field alias |

**What's missing**: config knob, priority check in merge, field-level lineage, UI surface.

## Design

### High-level flow

```
                ┌────────────────────────┐
   Scanner A ──▶│   Ingest processor      │
   Scanner B ──▶│  (processor_assets.go) │──▶ assets.properties (merged)
   Manual   ──▶│                         │──▶ asset_sources.contributed_data
   Cloud    ──▶│   Source-priority gate  │    (who wrote what, when)
                └────────────────────────┘              │
                           ▲                             ▼
                           │              ┌──────────────────────────┐
                           └──────────────│ tenants.settings         │
                                          │  .asset_source_priority  │
                                          └──────────────────────────┘
```

Mental model: when incoming source wants to set field F, look up the source that last wrote F. If the incoming source is ranked **equal or higher**, write. Otherwise skip and record the attempt.

### Data model

#### New settings field

```go
// pkg/domain/tenant/settings.go
type Settings struct {
    // ... existing fields ...
    AssetSource AssetSourceSettings `json:"asset_source"`
}

type AssetSourceSettings struct {
    // Priority order — highest priority first.
    // Entries are data_sources.id (UUIDs). Sources not listed are
    // ranked below all listed sources, relative to each other by
    // insertion order (preserves today's last-write-wins for them).
    Priority []shared.ID `json:"priority"`

    // When true, ingest populates asset_sources.contributed_data
    // with every field it writes. Off by default to keep storage
    // cost predictable; on for tenants that enable the feature.
    TrackFieldAttribution bool `json:"track_field_attribution"`
}
```

Why UUIDs not tool names: `data_sources` is the canonical registry — a tenant may have two Nessus instances, and the existing registry already distinguishes them.

#### `asset_sources.contributed_data` shape

Currently unused. Populated only when `TrackFieldAttribution=true`:

```json
{
  "fields": {
    "os": { "value_hash": "sha256:...", "at": "2026-04-23T10:12:00Z" },
    "severity": { "value_hash": "sha256:...", "at": "2026-04-23T10:12:00Z" }
  },
  "skipped": [
    { "field": "owner", "at": "2026-04-23T10:15:00Z",
      "reason": "lower_priority_than_nessus" }
  ]
}
```

- `value_hash` not raw value — keeps JSONB small and avoids leaking whole payloads into every source record.
- `skipped` gives the audit trail customers ask for ("why didn't my cloud run update this field?").

#### No new tables, no destructive migrations

Migration `000163_asset_source_priority.up.sql`:

```sql
-- Settings JSONB already exists on tenants; add a CHECK for shape
-- only if we decide to lint the JSON. Default behaviour (null/empty
-- priority) = today's last-write-wins, no backfill needed.

-- Add functional index for quick lookup of the primary source per
-- asset. Cheap — asset_sources is typically <10 rows per asset.
CREATE INDEX IF NOT EXISTS idx_asset_sources_asset_primary
  ON asset_sources (asset_id)
  WHERE is_primary = true;
```

No rewrite of existing data. Tenants opting in start getting new attribution on the next ingest; pre-existing fields are treated as "unattributed" and can be overwritten by any source (documented behavior — Phase 2 may change this).

### Ingest flow changes

`processor_assets.go:mergeCTISIntoAsset` gains a `PriorityGate` dependency:

```go
type PriorityGate interface {
    // CanWrite returns true if incoming source may override the
    // field, based on tenant's configured priority. Sources not in
    // the priority list are ranked below listed ones but equal to
    // each other (last-write-wins among them).
    CanWrite(ctx context.Context, tenantID shared.ID,
             assetID shared.ID, field string,
             incomingSourceID shared.ID) (bool, error)
}
```

Pseudocode for the merge step:

```go
for field, incomingValue := range newProperties {
    canWrite, err := gate.CanWrite(ctx, tenantID, asset.ID(), field, sourceID)
    if err != nil {
        // Fail open on config lookup error — keep today's behavior.
        canWrite = true
        log.Warn("priority gate error, allowing write", "err", err)
    }
    if !canWrite {
        recordSkipped(asset.ID(), sourceID, field, "lower_priority")
        continue
    }
    asset.SetProperty(field, incomingValue)
    recordWritten(asset.ID(), sourceID, field, incomingValue)
}
```

Implementation notes:

- **Fail open, not closed**: any error in the gate (DB blip, cache miss) defaults to allowing the write. Losing data is worse than a short period of wrong precedence.
- **Transaction boundary**: write attribution in the same tx as `asset_sources.last_seen_at` so they can't diverge.
- **Batch**: for bulk CTIS (1000s of fields), call `CanWrite` once per `(tenantID, assetID, sourceID)` with the full field set — the gate returns a set of allowed fields.
- **No per-field overrides**: this phase treats all fields equally. Phase 2 may carve out exceptions (e.g. tags always union).

### API changes

#### Settings endpoints (extend existing)

```
GET  /api/v1/tenants/{id}/settings
→ adds "asset_source": { "priority": ["uuid-1", "uuid-2"], "track_field_attribution": true }

PUT  /api/v1/tenants/{id}/settings/asset-source
  body: { "priority": [...], "track_field_attribution": bool }
→ validates every UUID exists + belongs to the tenant; rejects duplicates
```

Follows the pattern of `UpdateAssetIdentitySettings` in `tenant_service.go`.

#### Asset response (opt-in via query param)

```
GET /api/v1/assets/{id}?include=field_sources
→ standard response + "field_sources": {
    "os":       { "source_id": "nessus-prod",   "source_name": "Nessus (prod)",     "last_updated": "..." },
    "severity": { "source_id": "nessus-prod",   "source_name": "Nessus (prod)",     "last_updated": "..." },
    "owner":    { "source_id": "manual",        "source_name": "Manual entry",      "last_updated": "..." }
  }
```

Opt-in to avoid fattening the hot-path asset list. UI uses it only in the asset detail drawer.

#### New: skipped-writes audit

```
GET /api/v1/assets/{id}/source-skips?limit=20
→ [{ "field": "owner", "source_id": "cloud-discovery",
     "source_name": "AWS Discovery", "at": "...", "reason": "lower_priority" }, ...]
```

Powers a "why didn't this field update?" panel in the UI.

### UI changes

1. **Settings → Organization → Asset Sources**
   - Drag-to-reorder list of the tenant's `data_sources`.
   - Toggle: "Track field-level attribution".
   - Warning banner if reorder affects > N existing assets (best-effort count).

2. **Asset detail drawer**
   - Small badge next to each property: "from Nessus · 2h ago".
   - "View source history" → modal listing writes + skipped writes.

3. **Empty-state guidance**
   - Dashboard card: "You have 4 active sources but no priority set — conflicts will use last-write-wins." Links to the settings page.

### Migration / rollout

1. Ship migration 000163 (index only, no data rewrite).
2. Ship code with feature disabled by default — `TrackFieldAttribution=false`, empty `Priority`.
3. Tenants opt in via Settings UI. First write after opt-in starts the attribution log.
4. Document explicitly: pre-existing fields carry no lineage; first write by *any* source records its source.
5. Customers can flip priority at any time. Future writes respect it; past writes are not rewritten.

**Safety net**: `AssetSource` settings update is reversible. If a tenant sets a bad priority that blocks legitimate updates, clearing the list returns to last-write-wins within one cache cycle (see `user_perms:*` pattern — 5-min Redis TTL).

### Failure modes & mitigations

| Failure | Symptom | Mitigation |
|---|---|---|
| Priority gate lookup fails | Wrong source might win a field | Fail open — write goes through, log warning |
| `contributed_data` JSONB bloats | Slow asset reads | Cap per asset at 500 field-writes; rotate oldest |
| Customer sets priority that excludes all scanners | No findings get through | Settings UI warns when priority list doesn't include any `scanner`-type source |
| Source registry UUID stale (source deleted) | Merge can't look up rank | Treat missing source as lowest priority, log once per ingest batch |
| Field attribution enabled mid-flight | Asset has mixed attributed + unattributed fields | Documented; UI shows "unattributed (pre-$date)" label |

### Testing strategy

1. **Unit** (`tests/unit/ingest/priority_gate_test.go`):
   - Ordered priority → higher source overrides lower.
   - Unlisted source → last-write-wins among unlisted.
   - Missing source UUID → treated as lowest.
   - Empty priority → today's behavior (regression guard).

2. **Integration** (`tests/integration/asset_source_priority_test.go`):
   - Two CTIS payloads in sequence, same asset, different sources; assert correct field wins.
   - Toggle `TrackFieldAttribution` mid-run; assert only new writes get lineage.
   - Skipped-writes endpoint returns the right shape.

3. **Contract test** (`tests/integration/settings_api_test.go`):
   - `PUT /settings/asset-source` rejects UUIDs not in the tenant's `data_sources`.
   - Duplicates in priority list rejected.

4. **UI** (vitest + Playwright):
   - Settings page reorders persist across reload.
   - Asset drawer shows field source badges.
   - Playwright: two-scanner scenario → correct badge post-ingest.

### Observability

- Prometheus counter: `asset_source_priority_skipped_total{tenant, source, reason}`.
- Log line at `info`: `priority_gate_skipped field=X source=Y reason=lower_priority` — sampled.
- Dashboard panel: skipped-writes per tenant per day.

## Alternatives considered

### A. Global priority list (simplest)

Same structure, but one priority list applies to all fields equally. Chosen — this is what the RFC proposes.

### B. Per-field priority map

`{ "severity": ["nessus"], "os": ["osquery"], "tags": "union" }`. More power, but customer must enumerate every field and we must decide what to do with unknown fields. **Deferred to Phase 2** — revisit once we have real customer asks for specific fields.

### C. Policy engine

Declarative rules: `severity: highest-wins`, `last_seen: most_recent`, `tags: union`. Most flexible but a small DSL and evaluator. Over-engineered for the current ask; revisit if Phase 2 feedback demands it.

### D. Source weights / confidence scoring

Every source contributes with a confidence score; merge picks the highest. Requires sources to know their confidence — no source reports this today, so we'd invent numbers. Rejected as premature.

### E. Do nothing — teach customers to disable sources

"If you don't want cloud discovery to override Nessus, don't run cloud discovery." Rejected — customers legitimately want both sources, just want one to win.

## Open questions (for customer review)

1. **Tags**: should tags always union across sources, or respect priority like other fields? Current proposal: respect priority. Customer may want union as a special case.

2. **Priority gaps**: if priority is `[Nessus, Manual]` and a third unlisted source reports a field first, then Nessus reports it later — should Nessus always win? Current proposal: yes, listed sources outrank unlisted always.

3. **First-write wins for unlisted?**: when two unlisted sources fight over a field, current proposal is last-write-wins (today's behavior). Alternative: first-write-wins among unlisted. Cleaner but changes existing behavior.

4. **Attribution storage**: is per-field lineage in `asset_sources.contributed_data` acceptable, or does the customer want a separate `asset_field_history` table for long-term audit?

5. **Revocation**: when a `data_source` is deleted, should its attributions be stripped from `asset_sources` or orphaned? Current proposal: orphan with flag `source_deleted=true` — safer for audit.

6. **Multi-tenant defaults**: any sensible default priority shipping with the product (e.g., `manual > scanner > integration > collector`)?

## Timeline

| Phase | Work | Target |
|---|---|---|
| **1a** | Domain + settings + migration + ingest gate | 3 dev-days |
| **1b** | Attribution persistence + API additions | 2 dev-days |
| **1c** | UI settings page + asset drawer badges | 3 dev-days |
| **1d** | Tests + docs + observability | 2 dev-days |
| **Total Phase 1** | | **~10 dev-days / ~2 weeks** |
| **Phase 2 (later)** | Per-field overrides, reprocessing endpoint, policy engine (if demand) | TBD after customer feedback |

## References

- RFC-001 — Asset Identity Resolution: `docs/architecture/asset-identity-resolution.md`
- Data sources architecture: `docs/architecture/data-sources.md`
- Tenant settings pattern: `pkg/domain/tenant/settings.go`
- Existing merge logic: `internal/app/ingest/processor_assets.go:mergeCTISIntoAsset`
- Asset-source junction: `migrations/000014_data_sources.up.sql`
