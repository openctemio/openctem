# RFC-001 Review: Multi-Perspective Assessment & Final Implementation Plan

> **Status**: Implemented — Feature doc: [docs/architecture/asset-identity-resolution.md](../architecture/asset-identity-resolution.md)

---

## Part 1: PM / Tech Lead / BA Assessment

### 1.1 Gaps in the current RFC

| # | Gap | Severity | Detail |
|---|---|---|---|
| G1 | **Missing acceptance criteria** | HIGH | The RFC has a design but no definition of done for each phase |
| G2 | **Phase 1 migration too risky** | HIGH | Normalize + merge existing data in 1 migration; on error → data loss. Must be split: normalize first, merge later (manual approval) |
| G3 | **SDK-Go normalization duplicate logic** | MEDIUM | The RFC proposes normalization in both SDK-Go and the API → the same logic maintained in 2 places. The API is already authoritative → SDK-Go only needs a lightweight version (trim + lowercase), not the full logic |
| G4 | **Missing monitoring/metrics** | MEDIUM | No metric tracks how many assets are merged, how many renamed, how many correlation misses |
| G5 | **Missing backward compatibility test** | MEDIUM | Existing API consumers send old (not yet normalized) names — must verify that an API response returning the new name does not break clients |
| G6 | **findByIPs returns multiple results** | HIGH | The RFC says "1 query per batch" but `FindByIPs` returns `map[string]*Asset` — the same IP can match several assets (the very problem being solved). It must return `map[string][]*Asset` |
| G7 | **Merge logic lacks FK cascade** | HIGH | `mergeAsset()` must move references from 12+ tables (findings, asset_services, asset_relationships, compliance_mappings, suppressions...). The RFC only mentions findings |
| G8 | **Phase estimate too optimistic** | MEDIUM | Phase 1 is "2 days" but includes a migration that normalizes + merges existing data → realistically 4-5 days including testing |

### 1.2 Risk assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Migration merges the wrong asset | Medium | HIGH (data loss) | Dry-run + manual approval before merge |
| Performance regression during ingest | Low | HIGH | Benchmark before/after, feature flag |
| Breaking API contract (name changes) | Medium | MEDIUM | Version the API, document the breaking change |
| Race condition in correlation | Low | LOW | Accept eventual consistency |

---

## Part 2: Security Expert Assessment

### 2.1 Security issues in the RFC

| # | Issue | Severity | Detail |
|---|---|---|---|
| S1 | **ReDoS in URL normalize** | HIGH | `url.Parse()` is safe, but adding a regex for path normalization → ReDoS risk. The RFC uses `strings` functions → OK |
| S2 | **Homoglyph/IDN attack** | MEDIUM | The RFC mentions punycode but leaves it to Phase 3. Attack: `exаmple.com` (Cyrillic 'а') creates an asset distinct from `example.com`. An attacker can create a spoofed asset to hide findings |
| S3 | **Merge log exposes tenant data** | LOW | `asset_merge_log` has `kept_asset_name`, `merged_asset_name` — if an admin endpoint queries across tenants → info leak. Must filter by tenant_id |
| S4 | **FindByIPs query timing attack** | LOW | The `?|` operator on a JSONB array can be slower for large arrays → potential DoS if an attacker sends an asset with 10000 IPs |
| S5 | **IP correlation bypass** | MEDIUM | An attacker sends an asset "malicious-server" with the victim asset's IP → forced merge → hijacked findings. Mitigation: only merge the same asset_type, verify provider trust |
| S6 | **Normalization bypass** | LOW | If normalization is bypassed (a bug), 2 assets with the same canonical name but different raw names can coexist. The DB unique constraint is on the raw name → still allowed. Mitigation: normalize in the entity constructor (single chokepoint) |

### 2.2 Recommendations

1. **S5 is the most important**: add a `provider trust level` — merge only when both sources are trusted, or the incoming source's trust >= the existing one
2. **Limit the ip_addresses array**: max 20 IPs per asset. Reject if exceeded
3. **Rate limit on correlation**: if 1 batch has >100 assets needing correlation → log a warning; correlation may be skipped for that batch

---

## Part 3: UX Assessment

### 3.1 User impact

| Scenario | User sees | Good/Bad |
|---|---|---|
| Asset renamed (IP → hostname) | Asset name changes in the dashboard | **Confusing** if not announced |
| 2 assets merged into 1 | Finding count rises, the old asset disappears | **Confusing** if the user is tracking the old asset |
| Search by the old name | Not found (the name was normalized) | **Bad** — search must also cover old names |
| Create an asset with a duplicate name (different case) | "Asset already exists" error | **Good** — clear feedback |

### 3.2 UX improvements to add

1. **Search by alias**: when normalization renames an asset, store the old name in `properties.aliases[]` → search also matches aliases
2. **Merge notification**: when a merge happens, show a banner "X assets were merged due to duplicate detection"
3. **Asset history**: Show timeline "Renamed from 192.0.2.10 → web-server-01 (correlated by IP)"
4. **Preview normalization**: in the create-asset form, show the preview "Will be saved as: example.com" when the user types "Example.COM"

---

## Part 4: Database Query Performance Assessment

### 4.1 Current query analysis

| Operation | Current Queries | With RFC | Change |
|---|---|---|---|
| Ingest batch (100 assets) | 1 (GetByNames) + 1 (UpsertBatch) = **2** | 2 + 1 (FindByIPs) = **3** | +1 query |
| Ingest batch (100 assets, 50 new hosts) | 2 | 3 + potential rename updates = **3-5** | +1-3 queries |
| Single asset create (API) | 1 INSERT | 1 SELECT (check exist) + 1 INSERT = **2** | +1 query |

### 4.2 Performance concerns

| Concern | Severity | Analysis |
|---|---|---|
| `FindByIPs` with `?|` operator | MEDIUM | A GIN index on `ip_addresses` helps, but `?|` on an array of 200 IPs will be slow. Benchmark required |
| Multiple `OR` conditions in `FindByIPs` | MEDIUM | 4 `OR` branches (name, ip, ip_address.address, ip_addresses) → Postgres may not use indexes efficiently → needs `EXPLAIN ANALYZE` |
| Migration normalize 100K+ assets | HIGH | UPDATE 100K rows → table lock. Needs batched updates (1000 rows/batch) |
| Correlation per asset (not batched) | HIGH | RFC Section 5.3 calls the correlator per asset in a loop → N queries without batching. Section 5.4 has a batch solution but it is not wired into 5.3 |

### 4.3 Query optimization recommendations

1. **Split FindByIPs into 2 queries**: Query 1 checks `ip_addresses ?| array` (GIN index), Query 2 checks `properties->>'ip' = ANY()` (btree index). Postgres handles 2 indexed queries faster than 1 query with 4 OR branches
2. **Batch correlation**: collect all IPs to correlate → 1 query instead of N queries
3. **Migration chunked**: UPDATE ... WHERE id IN (SELECT id FROM assets LIMIT 1000) — batch 1000 rows
4. **Add composite index**: `CREATE INDEX idx_assets_tenant_type_name ON assets(tenant_id, asset_type, LOWER(name))` for case-insensitive lookup

---

## Part 5: Final Implementation Plan (Revised)

### Changes from the original RFC

1. **Split Phase 1 into 1a + 1b**: normalize code (safe) and data migration (risky) separately
2. **Add Phase 0**: set up monitoring + metrics first
3. **Batch correlation instead of per-asset**: wire the FindByIPs batch into the flow
4. **Aliases support**: keep the old name on rename
5. **Limit ip_addresses**: max 20 IPs/asset
6. **Trust-based merge**: merge only when both sources are trusted

### Revised Phases

```
Phase 0: Foundation (1 day)
  ├── Feature flags + config
  ├── asset_merge_log table
  └── Metrics instrumentation

Phase 1a: Name Normalization - Code (3 days)
  ├── normalize.go + 170 edge case tests
  ├── Wire into entity constructor
  ├── Wire into ingest + import + handler
  ├── Aliases support (store old name)
  └── Search by alias

Phase 1b: Name Normalization - Data Migration (2 days)
  ├── Dry-run: report how many assets affected
  ├── Chunked UPDATE (1000 rows/batch)
  ├── Duplicate detection (report only, no auto-merge)
  └── Admin endpoint to review + approve merges

Phase 2: Host IP Correlation (4 days)
  ├── correlator.go with batch FindByIPs
  ├── Staleness check (30 days)
  ├── Name quality scoring + rename logic
  ├── Provider trust verification
  ├── Max 20 IPs/asset guard
  ├── ip_addresses normalization
  └── Integration tests (multi-source scenarios)

Phase 3: Extended Correlation (3 days)
  ├── Repository: integration URL correlation
  ├── Cloud/IAM: external_id correlation
  ├── Certificate: fingerprint correlation
  └── Agent parsers normalization (SDK-Go shared lib)

Phase 4: Admin Tools + UX (2 days)
  ├── Duplicate detection admin endpoint
  ├── Merge history UI (asset timeline)
  ├── UI form normalize preview
  └── Merge notification banner
```

### Phase 0: Foundation (1 day)

**Goal**: set up infrastructure before changing logic.

```go
// config/config.go
type AssetIdentityConfig struct {
    // Phase 1: Name normalization
    EnableNormalization bool `env:"ASSET_NORMALIZE" envDefault:"true"`
    
    // Phase 2: IP correlation
    EnableIPCorrelation bool `env:"ASSET_IP_CORRELATION" envDefault:"false"`
    StaleAssetDays      int  `env:"ASSET_STALE_DAYS" envDefault:"30"`
    MaxIPsPerAsset      int  `env:"ASSET_MAX_IPS" envDefault:"20"`
    
    // Phase 3: Extended correlation
    EnableExtCorrelation bool `env:"ASSET_EXT_CORRELATION" envDefault:"false"`
}
```

**Migration: asset_merge_log**
```sql
CREATE TABLE IF NOT EXISTS asset_merge_log ( ... ); -- as in RFC
```

**Metrics (Prometheus)**:
```go
assetNormalizeTotal   = prometheus.NewCounterVec(...)  // count by asset_type, action (normalize/skip)
assetCorrelateTotal   = prometheus.NewCounterVec(...)  // count by correlation_type (ip/hostname/none)
assetMergeTotal       = prometheus.NewCounterVec(...)  // count by action (rename/merge)
assetCorrelateLatency = prometheus.NewHistogramVec(...) // correlation query duration
```

**Files:**
- `migrations/000XXX_asset_merge_log.up.sql` (NEW)
- `internal/config/config.go` (add AssetIdentityConfig)

**Acceptance criteria:**
- [ ] `asset_merge_log` table created
- [ ] Feature flags in config
- [ ] Metrics registered (noop counters OK — will be incremented in later phases)

---

### Phase 1a: Name Normalization - Code (3 days)

**Goal**: All new assets get normalized names. No existing data changed yet.

**Step 1: Core normalization library**

```
pkg/domain/asset/normalize.go (NEW)
├── NormalizeName(name, assetType, subType) string     // Main entry point
├── normalizeDNSName(name) string                      // domain, subdomain
├── normalizeHostName(name) string                     // host (DNS or IP)
├── normalizeIPAddress(name) string                    // ip_address
├── normalizeRepoName(name) string                     // repository
├── normalizeURL(name) string                          // application, service/http
├── normalizeServiceName(name, subType) string         // service variants
├── normalizeCertName(name) string                     // certificate
├── normalizeDatabaseName(name) string                 // database
├── normalizeNetworkName(name, subType) string         // network, subnet
├── normalizeStorageName(name, subType) string         // storage, s3_bucket
├── commonNormalize(name) string                       // trim, null bytes, zero-width
└── stripProtocol(name) string                         // helper
```

**Step 2: Tests — cover ALL 170 edge cases**

```
pkg/domain/asset/normalize_test.go (NEW)
├── TestNormalizeDNSName          // 12 cases (D1-D12)
├── TestNormalizeSubdomain        // 10 cases (S1-S10)
├── TestNormalizeCertificate      // 10 cases (C1-C10)
├── TestNormalizeIPAddress        // 12 cases (I1-I12)
├── TestNormalizeHost             // 21 cases (H1-H21)
├── TestNormalizeService          // 20 cases (SP1-SP7, SH1-SH7, SU1-SU6)
├── TestNormalizeApplication      // 12 cases (A1-A6, AA1-AA3, AM1-AM3)
├── TestNormalizeRepository       // 15 cases (R1-R15)
├── TestNormalizeCloudAccount     // 8 cases (CA1-CA8)
├── TestNormalizeStorage          // 10 cases (ST1-ST5, SR1-SR5)
├── TestNormalizeContainer        // 7 cases (CT1-CT7)
├── TestNormalizeKubernetes       // 7 cases (K1-K4, KN1-KN3)
├── TestNormalizeDatabase         // 9 cases (DB1-DB9)
├── TestNormalizeNetwork          // 8 cases (N1-N6, NF1-NF2)
├── TestNormalizeIdentity         // 8 cases (ID1-ID8)
├── TestNormalizeUnclassified     // 3 cases (U1-U3)
├── TestCrossCutting              // 8 cases (X1-X8)
└── TestNormalizeIdempotent       // normalize(normalize(x)) == normalize(x) for all types
```

**Step 3: Wire into code**

```go
// entity.go — NewAsset constructor (SINGLE CHOKEPOINT)
func NewAsset(name string, assetType AssetType, criticality Criticality) (*Asset, error) {
    name = strings.ReplaceAll(name, "\x00", "")
    name = NormalizeName(name, assetType, "")  // ← ADD THIS
    if name == "" {
        return nil, fmt.Errorf("%w: name is required", shared.ErrValidation)
    }
    // ... rest unchanged
}

// entity.go — UpdateName
func (a *Asset) UpdateName(name string) error {
    name = NormalizeName(name, a.assetType, a.SubType())  // ← ADD THIS
    if name == "" {
        return fmt.Errorf("%w: name is required", shared.ErrValidation)
    }
    // Store old name as alias
    a.addAlias(a.name)  // ← ADD THIS
    a.name = name
    a.updatedAt = time.Now().UTC()
    return nil
}
```

**Step 4: Aliases support**

```go
// entity.go — store old names for search
func (a *Asset) addAlias(oldName string) {
    aliases, _ := a.properties["aliases"].([]any)
    // Check duplicate
    for _, alias := range aliases {
        if alias == oldName { return }
    }
    aliases = append(aliases, oldName)
    // Max 10 aliases
    if len(aliases) > 10 {
        aliases = aliases[len(aliases)-10:]
    }
    a.properties["aliases"] = aliases
}
```

Repository search update:
```sql
-- Add to search query (buildWhereClause)
OR a.properties->'aliases' ? $N  -- JSONB contains check
```

**Files changed:**
- `pkg/domain/asset/normalize.go` (NEW)
- `pkg/domain/asset/normalize_test.go` (NEW)
- `pkg/domain/asset/entity.go` (modify NewAsset, UpdateName, add addAlias)
- `internal/app/ingest/processor_assets.go` (NormalizeName already applied via NewAsset constructor)
- `internal/app/asset_import_service.go` (NormalizeName already applied via NewAsset constructor)
- `internal/infra/postgres/asset_repository.go` (add alias search)

**Acceptance criteria:**
- [ ] 170+ unit tests pass
- [ ] `normalize(normalize(x)) == normalize(x)` for all types (idempotency)
- [ ] New assets created via API/ingest/import all get normalized names
- [ ] Existing assets untouched (no migration yet)
- [ ] Old name stored in aliases when rename occurs
- [ ] Search finds assets by old name (alias search)

---

### Phase 1b: Data Migration (2 days)

**Goal**: Normalize existing asset names. Merge duplicates with admin approval.

**Step 1: Dry-run report (no data change)**

```sql
-- Script: report_normalization_impact.sql
-- Run manually to preview impact BEFORE migration

WITH normalized AS (
    SELECT
        id, tenant_id, name, asset_type,
        -- Apply normalization rules per type
        CASE
            WHEN asset_type IN ('domain', 'subdomain')
                THEN LOWER(RTRIM(LTRIM(TRIM(name), '.'), '.'))
            WHEN asset_type = 'host'
                THEN CASE
                    WHEN name ~ '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' THEN TRIM(name)
                    ELSE LOWER(RTRIM(TRIM(name), '.'))
                END
            WHEN asset_type IN ('repository', 'code_repo')
                THEN LOWER(RTRIM(
                    REGEXP_REPLACE(
                        REGEXP_REPLACE(
                            REGEXP_REPLACE(TRIM(name), '^https?://', ''),
                            '^git@([^:]+):', '\1/'
                        ),
                        '\.git$', ''
                    ),
                    '/'
                ))
            ELSE TRIM(name)
        END AS normalized_name
    FROM assets
),
changes AS (
    SELECT * FROM normalized WHERE name != normalized_name
),
duplicates AS (
    SELECT
        tenant_id, asset_type, normalized_name,
        array_agg(id ORDER BY finding_count DESC) AS ids,
        array_agg(name) AS names,
        COUNT(*) AS cnt
    FROM normalized
    GROUP BY tenant_id, asset_type, normalized_name
    HAVING COUNT(*) > 1
)
SELECT
    (SELECT COUNT(*) FROM changes) AS assets_to_rename,
    (SELECT COUNT(*) FROM duplicates) AS duplicate_groups,
    (SELECT SUM(cnt - 1) FROM duplicates) AS assets_to_merge;
```

**Step 2: Chunked normalization migration**

```sql
-- Migration: 000XXX_normalize_asset_names.up.sql

-- Phase 1: Rename only (no merge) — safe, reversible via aliases
-- Process in chunks of 1000 to avoid table lock

DO $$
DECLARE
    batch_size INT := 1000;
    updated INT := 0;
    total INT := 0;
BEGIN
    -- Domain/Subdomain: lowercase + trim dots
    LOOP
        WITH batch AS (
            SELECT id, name
            FROM assets
            WHERE asset_type IN ('domain', 'subdomain')
              AND (name != LOWER(RTRIM(LTRIM(name, '.'), '.'))
                   OR name LIKE '%.') 
            LIMIT batch_size
            FOR UPDATE SKIP LOCKED
        )
        UPDATE assets a
        SET
            name = LOWER(RTRIM(LTRIM(a.name, '.'), '.')),
            properties = jsonb_set(
                COALESCE(properties, '{}'),
                '{aliases}',
                COALESCE(properties->'aliases', '[]') || to_jsonb(a.name)
            ),
            updated_at = NOW()
        FROM batch
        WHERE a.id = batch.id
        RETURNING 1 INTO updated;

        EXIT WHEN updated = 0;
        total := total + updated;
        RAISE NOTICE 'Normalized % domain/subdomain assets', total;
    END LOOP;

    -- Repository: normalize format
    -- ... similar pattern ...

    -- Host: lowercase hostnames (skip IPs)
    -- ... similar pattern ...
END $$;
```

**Step 3: Duplicate detection (report only)**

```sql
-- DO NOT auto-merge in migration
-- Instead: populate a review table for admin

CREATE TABLE IF NOT EXISTS asset_dedup_review (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    normalized_name VARCHAR(1024),
    asset_type VARCHAR(50),
    keep_asset_id UUID NOT NULL,
    merge_asset_ids UUID[] NOT NULL,
    keep_finding_count INT,
    merge_finding_count INT,
    status VARCHAR(20) DEFAULT 'pending', -- pending, approved, rejected, merged
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

**Acceptance criteria:**
- [ ] Dry-run report shows impact before migration runs
- [ ] Migration normalizes names in chunks (no table lock)
- [ ] Old names stored in aliases
- [ ] Duplicates detected and recorded in `asset_dedup_review`
- [ ] No auto-merge — admin must approve each merge group
- [ ] Admin endpoint: `GET /api/v1/admin/assets/dedup-review` (list pending)
- [ ] Admin endpoint: `POST /api/v1/admin/assets/dedup-review/{id}/approve` (execute merge)

---

### Phase 2: Host IP Correlation (4 days)

**Goal**: Same host with different names but same IP → 1 asset.

**Step 1: Batch IP correlation query**

```go
// asset_repository.go

// FindByIPs returns all assets that have ANY of the given IPs.
// Returns map[ip][]Asset (an IP can match multiple assets — that's the problem we're solving).
func (r *AssetRepository) FindByIPs(
    ctx context.Context,
    tenantID shared.ID,
    ips []string,
) (map[string][]*asset.Asset, error) {
    if len(ips) == 0 {
        return make(map[string][]*asset.Asset), nil
    }

    // Split into 2 efficient queries instead of 1 with 4 OR branches
    
    // Query 1: Check ip_addresses JSONB array (GIN index)
    q1 := r.selectQuery() + `
        WHERE a.tenant_id = $1
        AND a.asset_type IN ('host', 'ip_address')
        AND a.properties->'ip_addresses' ?| $2`
    
    // Query 2: Check legacy ip fields + name (btree indexes)
    q2 := r.selectQuery() + `
        WHERE a.tenant_id = $1
        AND a.asset_type IN ('host', 'ip_address')
        AND (a.name = ANY($2)
             OR a.properties->>'ip' = ANY($2)
             OR a.properties->'ip_address'->>'address' = ANY($2))
        AND NOT (a.properties->'ip_addresses' ?| $2)` // Avoid duplicates with Q1

    // Execute both, deduplicate results
}
```

**Step 2: Correlator with safeguards**

```go
// correlator.go

type CorrelateConfig struct {
    StaleAssetDays int  // Don't merge if existing asset stale > N days
    MaxIPsPerAsset int  // Reject assets with > N IPs
    RequireSameType bool // Only merge same asset_type
}

func (c *AssetCorrelator) CorrelateHost(
    ctx context.Context,
    tenantID shared.ID,
    incomingName string,
    properties map[string]any,
    cfg CorrelateConfig,
) (*CorrelationResult, error) {
    ips := extractAllIPs(properties, incomingName)
    
    // Guard: too many IPs → suspicious, skip correlation
    if len(ips) > cfg.MaxIPsPerAsset {
        c.logger.Warn("asset has too many IPs, skipping correlation",
            "name", incomingName, "ip_count", len(ips))
        return &CorrelationResult{}, nil
    }

    // Guard: no IPs → can't correlate
    if len(ips) == 0 {
        return &CorrelationResult{}, nil
    }

    matched, err := c.repo.FindByIPs(ctx, tenantID, ips)
    if err != nil {
        return nil, err
    }

    // Collect all unique matched assets
    seen := make(map[string]*asset.Asset)
    for _, assets := range matched {
        for _, a := range assets {
            // Guard: staleness check
            if !shouldCorrelateByIP(a, incomingName, cfg.StaleAssetDays) {
                continue
            }
            seen[a.ID().String()] = a
        }
    }

    if len(seen) == 0 {
        return &CorrelationResult{}, nil
    }

    // Convert to slice, pick primary
    assets := make([]*asset.Asset, 0, len(seen))
    for _, a := range seen {
        assets = append(assets, a)
    }

    // Sort: most findings first, then oldest
    sort.Slice(assets, func(i, j int) bool {
        if assets[i].FindingCount() != assets[j].FindingCount() {
            return assets[i].FindingCount() > assets[j].FindingCount()
        }
        return assets[i].CreatedAt().Before(assets[j].CreatedAt())
    })

    primary := assets[0]
    result := &CorrelationResult{
        Matched:         primary,
        CorrelationType: "ip",
        MergeTargets:    assets[1:], // Others to merge into primary
    }

    // Should rename? Only if incoming has better name quality
    if nameQuality(incomingName) > nameQuality(primary.Name()) {
        result.ShouldRename = true
        result.NewName = incomingName
    }

    return result, nil
}
```

**Step 3: Wire into ProcessBatch**

```go
// processor_assets.go — ProcessBatch modification

// After GetByNames, before UpsertBatch:

// Collect IPs from unmatched hosts for batch correlation
unmatchedHostIPs := make(map[string][]string) // name → [ips]
for _, ctisAsset := range unmatched {
    if ctisAsset.Type != "host" { continue }
    ips := extractIPsFromCTIS(ctisAsset)
    if len(ips) > 0 {
        unmatchedHostIPs[getAssetName(ctisAsset)] = ips
    }
}

// Single batch query for all IPs
allIPs := flattenIPs(unmatchedHostIPs)
if len(allIPs) > 0 && cfg.EnableIPCorrelation {
    ipMatches, err := p.repo.FindByIPs(ctx, tenantID, allIPs)
    // Process results...
}
```

**Query count**: Base 2 + 2 (split FindByIPs) = **4 queries total per batch** (not per asset).

**Acceptance criteria:**
- [ ] `FindByIPs` batch query uses 2 indexed queries (GIN + btree)
- [ ] Staleness check prevents merging assets >30 days stale
- [ ] Max 20 IPs/asset guard
- [ ] Name quality scoring correct: FQDN > hostname > IP
- [ ] Rename stores old name in aliases
- [ ] Merge moves findings, services, relationships, compliance_mappings
- [ ] Merge logged in `asset_merge_log`
- [ ] Feature flag `ASSET_IP_CORRELATION=false` disables entire phase
- [ ] Integration tests: Splunk-then-Qualys, Nessus-FQDN-override, DHCP-reuse

---

### Phase 3: Extended Correlation (3 days)

**Goal**: Correlation for repos, cloud, IAM, certificates.

| Type | Correlation Method | Query |
|---|---|---|
| Repository | Integration URL prefix | `GetByName(ctx, tid, integrationHost + "/" + name)` |
| Cloud Account | external_id | `FindByExternalID(ctx, tid, externalID)` |
| IAM | external_id (ARN) | `FindByExternalID(ctx, tid, arn)` |
| Certificate | fingerprint | `FindByPropertyValue(ctx, tid, "fingerprint", fp)` |

**Agent normalization**: Wire `NormalizeName()` into 5 recon parsers + vulnscan.

```go
// SDK-Go: lightweight normalize (shared)
// sdk-go/pkg/ctis/normalize.go

func NormalizeAssetName(assetType string, name string) string {
    name = strings.TrimSpace(name)
    switch assetType {
    case "domain", "subdomain":
        return strings.ToLower(strings.TrimRight(name, "."))
    case "ip_address":
        if ip := net.ParseIP(name); ip != nil {
            return ip.String()
        }
        return name
    case "repository":
        // Lightweight: lowercase + trim .git + trim protocol
        // Full normalization happens at API
        name = strings.TrimPrefix(name, "https://")
        name = strings.TrimPrefix(name, "http://")
        name = strings.TrimSuffix(name, ".git")
        return strings.ToLower(name)
    default:
        return name
    }
}
```

**Acceptance criteria:**
- [ ] Repository correlation via integration URL works
- [ ] Cloud account dedup by account ID
- [ ] Certificate dedup by fingerprint
- [ ] Agent normalizes names before sending to API
- [ ] SDK-Go has lightweight normalize (defense in depth)

---

### Phase 4: Admin Tools + UX (2 days)

**Goal**: Clean up historical duplicates, improve UX.

**Admin endpoints:**
```
GET  /api/v1/admin/assets/dedup-review          — list pending dedup groups
POST /api/v1/admin/assets/dedup-review/{id}/approve  — approve + execute merge
POST /api/v1/admin/assets/dedup-review/{id}/reject   — reject (keep separate)
GET  /api/v1/admin/assets/merge-log              — view merge history
POST /api/v1/admin/assets/scan-duplicates        — trigger new scan
```

**UI changes:**
- Asset detail sheet: show "Also known as" section if aliases exist
- Asset timeline: show merge/rename events from `asset_merge_log`
- Create asset form: show "Will be saved as: normalized_name" preview
- Dashboard: banner "X duplicate groups detected" with link to review page

**Acceptance criteria:**
- [ ] Admin can review and approve/reject each merge group
- [ ] Merge history visible in admin panel
- [ ] Asset aliases shown in detail view
- [ ] Form shows normalization preview

---

## Total Effort Summary

| Phase | Days | Risk | Status |
|---|---|---|---|
| Phase 0: Foundation | 1 | None | COMPLETE |
| Phase 1a: Normalize Code | 3 | Low | COMPLETE — 158 test cases |
| Phase 1b: Data Migration | 2 | Medium | COMPLETE |
| Phase 2: IP Correlation | 4 | Medium | COMPLETE — wired into ProcessBatch + per-tenant config |
| Phase 3: Extended Correlation | 3 | Low | COMPLETE — repo/cloud/IAM/cert + Agent 5 parsers |
| Phase 4: Admin + UX | 2 | None | COMPLETE — endpoints + merge history + form preview |
| **Post-impl** | - | - | COMPLETE — CI fix, test expectations updated, pushed all 4 repos |
| **Total** | **15 days** | | |

Buffer: +3 days for unexpected issues = **18 days total**.

### Dependencies

```
Phase 0 ──→ Phase 1a ──→ Phase 1b ──→ Phase 2 ──→ Phase 3
                                                      │
                                                      └──→ Phase 4
```

Phases 3 and 4 can run in parallel with 2 developers.

---

## Checklist before starting

- [ ] Back up the production database before Phase 1b
- [ ] Dry-run migration report reviewed by team
- [ ] Feature flags documented in deployment guide
- [ ] Monitoring dashboard for asset normalization metrics ready
- [ ] Rollback procedure tested in staging
