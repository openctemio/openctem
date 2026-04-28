# Findings — 3-Level Data Model

**Status:** Proposal · Phase A prototype on `feat/findings-3level-phase-a`
**Authors:** Internal architecture review, 2026-04-28
**Supersedes:** ad-hoc fingerprint dedup in `findings` table
**Related audits:**
- [`audits/2026-04-multi-role-adversarial-audit.md`](../audits/2026-04-multi-role-adversarial-audit.md)
- Workspace `docs/audits/2026-04-painpoint-vs-ctem-reality-check.md`

---

## 1. Why this exists

The current `findings` table conflates three distinct concerns into one row:

1. **What rule fired** — the static knowledge ("Apache Log4j RCE", CVE links, fix advice, references). Lives in scanner documentation today, hardcoded into each `findings.title` / `findings.description` / `findings.references` per row.
2. **The vulnerability instance** — the durable fact "Asset X has plugin Y triggered". This is what operators interact with. Has lifecycle (open → in_progress → resolved), owner, SLA.
3. **Detection events** — every scan that observed this instance. Used for "first seen", "last seen", evidence, audit trail.

In a single-table model, every (asset × rule) instance carries the full rule metadata duplicated across rows, and every rescan either creates a new row (if fingerprint changes) or updates in place (losing scan history). At scale (≥10M findings) this leads to:

- **Storage waste** — a 2KB rule description × 1M instances = 2GB of duplicated text
- **Index bloat** — the same long titles/descriptions force wider table tuples
- **Lost history** — `last_seen_at` is a single timestamp; we can't answer "was this finding observed in scan #1234?"
- **Operational pain** — a typo fix in rule description requires `UPDATE findings WHERE rule_id=X` across millions of rows
- **UX collapse** — operators see 1M flat findings instead of "this CVE on these 50 hosts"

Industry-standard solution (Tenable plugin model, Qualys QID, Wiz issue catalog, CrowdStrike Spotlight) is to **split into three normalized tiers**.

## 2. The three levels

```
┌─────────────────────────────────────────────────────────────┐
│  LEVEL 1 — DETECTION RULES (catalog, global, immutable)     │
│  ─ ~50K-500K rows total cluster-wide                        │
│  ─ Updated rarely, fed from NVD / OSV / GHSA / scanner DBs  │
│  ─ NOT tenant-scoped                                        │
│  ─ Identity: (scanner, scanner_rule_id)                     │
│  Examples:                                                  │
│    "tenable:156032" → "Apache Log4j RCE (Log4Shell)"        │
│    "trivy:CVE-2021-44228" → "Vulnerable log4j-core"         │
│    "semgrep:javascript.detect-xss" → "DOM XSS via innerHTML" │
└─────────────────────────────────────────────────────────────┘
                           ▲ rule_id (FK)
                           │
┌─────────────────────────────────────────────────────────────┐
│  LEVEL 2 — VULNERABILITY INSTANCES (per-tenant, mutable)    │
│  ─ ~1M-100M rows per cluster                                │
│  ─ Operator-facing — status, owner, SLA, suppression        │
│  ─ Partitioned by HASH(tenant_id) at ≥50M rows              │
│  ─ Identity: (tenant_id, asset_id, rule_id) UNIQUE          │
│  Replaces: most of current `findings` table                 │
│  Compression: 5× smaller than current findings              │
└─────────────────────────────────────────────────────────────┘
                           ▲ instance_id (FK)
                           │
┌─────────────────────────────────────────────────────────────┐
│  LEVEL 3 — DETECTION EVENTS (per-tenant, append-only)       │
│  ─ ~100M-10B rows per cluster                               │
│  ─ Time-series, partition by month                          │
│  ─ Aggressive retention (default 90 days hot, archive cold) │
│  ─ One row per scan observation                             │
│  Replaces: scan-time fields scattered in findings/activities│
│  Cold archive: Parquet on S3 via logical replication        │
└─────────────────────────────────────────────────────────────┘
```

## 3. Schema (target end-state)

### 3.1 Level 1 — `detection_rules`

```sql
CREATE TABLE detection_rules (
    rule_id          TEXT PRIMARY KEY,
        -- Composite: "<scanner>:<scanner_rule_id>"
        -- e.g., "tenable:156032", "trivy:CVE-2021-44228"
    scanner          TEXT NOT NULL,
        -- Discriminator: 'tenable', 'qualys', 'trivy', 'nuclei',
        -- 'semgrep', 'gitleaks', 'sarif', 'cspm', etc.
    scanner_rule_id  TEXT NOT NULL,
        -- Native ID inside that scanner's namespace.
    category         TEXT NOT NULL CHECK (category IN
        ('sca','sast','dast','misconfig','secret','cspm','runtime','manual')),
    title            TEXT NOT NULL,
    description      TEXT,
    severity_native  TEXT,
        -- Severity as the scanner declared. CVSS, CRITICAL/HIGH, etc.
    cvss_score       NUMERIC(3,1),
    cvss_vector      TEXT,
    cwe_ids          TEXT[],
    owasp_ids        TEXT[],
    cve_ids          TEXT[],
        -- A single rule can address multiple CVEs (Log4Shell -> 5 CVEs).
        -- Use array, not separate junction table — read pattern is
        -- "show me all CVEs this rule covers", written rarely.
    references       JSONB DEFAULT '[]'::jsonb,
    remediation      TEXT,
    fix_versions     TEXT[],
    metadata         JSONB DEFAULT '{}'::jsonb,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (scanner, scanner_rule_id)
);

CREATE INDEX idx_detection_rules_scanner_category
    ON detection_rules (scanner, category);
CREATE INDEX idx_detection_rules_cve_ids_gin
    ON detection_rules USING GIN (cve_ids);
```

### 3.2 Level 2 — `vulnerability_instances`

```sql
CREATE TABLE vulnerability_instances (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id       UUID NOT NULL,
    asset_id        UUID NOT NULL,
    rule_id         TEXT NOT NULL REFERENCES detection_rules(rule_id),

    -- Lifecycle state (operator-mutable)
    status          finding_status NOT NULL DEFAULT 'open',
    severity        severity_level NOT NULL,
        -- May differ from rule's severity_native if operator
        -- overrides via priority engine (CIA + reachability factors).
    priority_class  TEXT,                    -- 'P0'/'P1'/'P2'/'P3'
    cvss_score      NUMERIC(3,1),            -- contextualised, not rule's native
    owner_id        UUID,
    sla_deadline    TIMESTAMPTZ,
    suppressed_by   UUID,                    -- FK suppression_rules

    -- Component / location (when applicable, e.g., SCA findings)
    component_id    UUID REFERENCES components(id),
    file_path       TEXT,
    line_number     INTEGER,

    -- Provenance
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_event_id   UUID,                    -- FK detection_events

    -- Operator notes (lightweight, not full evidence)
    evidence_summary TEXT,                   -- ≤2KB sanitised snippet
    metadata        JSONB DEFAULT '{}'::jsonb,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, asset_id, rule_id, COALESCE(file_path, ''), COALESCE(line_number, -1))
)
PARTITION BY HASH (tenant_id);

-- Create 32 hash partitions
DO $$
BEGIN
    FOR i IN 0..31 LOOP
        EXECUTE format('CREATE TABLE vulnerability_instances_p%s
            PARTITION OF vulnerability_instances
            FOR VALUES WITH (modulus 32, remainder %s)', i, i);
    END LOOP;
END $$;

CREATE INDEX idx_vi_tenant_status
    ON vulnerability_instances (tenant_id, status)
    WHERE status NOT IN ('resolved','closed','false_positive');
CREATE INDEX idx_vi_tenant_severity_status
    ON vulnerability_instances (tenant_id, severity, status);
CREATE INDEX idx_vi_tenant_asset
    ON vulnerability_instances (tenant_id, asset_id);
CREATE INDEX idx_vi_tenant_owner
    ON vulnerability_instances (tenant_id, owner_id);
CREATE INDEX idx_vi_tenant_sla
    ON vulnerability_instances (tenant_id, sla_deadline)
    WHERE sla_deadline IS NOT NULL AND status NOT IN ('resolved','closed');
```

### 3.3 Level 3 — `detection_events`

```sql
CREATE TABLE detection_events (
    id              UUID DEFAULT uuid_generate_v7(),
    tenant_id       UUID NOT NULL,
    instance_id     UUID NOT NULL,            -- FK vulnerability_instances
    scan_session_id UUID,                     -- which scan observed this
    rule_id         TEXT NOT NULL,            -- denormalised for partition pruning

    observed_at     TIMESTAMPTZ NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_date      DATE NOT NULL DEFAULT CURRENT_DATE,

    -- Full scan output (heavy)
    evidence        JSONB,                    -- raw scanner blob
    scanner         TEXT NOT NULL,
    scanner_version TEXT,
    fingerprint     TEXT NOT NULL,            -- per-event dedup within session

    PRIMARY KEY (id, event_date),
    UNIQUE (instance_id, scan_session_id, fingerprint, event_date)
)
PARTITION BY RANGE (event_date);

-- Auto-create monthly partitions via partman or manual cron
CREATE TABLE detection_events_2026_05
    PARTITION OF detection_events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

CREATE INDEX idx_de_instance_observed
    ON detection_events (instance_id, observed_at DESC);
CREATE INDEX idx_de_tenant_observed
    ON detection_events (tenant_id, observed_at DESC);
```

## 4. Cardinality and storage benchmarks

For one cluster serving 10 enterprise tenants, each with 50K assets and ~30M findings annually:

| Table | Rows | Avg row size | Total | Hot vs cold |
|---|---|---|---|---|
| `detection_rules` | 200K | 4KB | **800 MB** | Hot — fits RAM, no partitioning |
| `vulnerability_instances` | 100M | 200B | **20 GB** | Hot — partitioned 32×, each partition 600MB |
| `detection_events` (last 90 days) | 1B | 2KB | **2 TB** | Hot 90 days, cold archive monthly partitions to S3 |

Compare current single-table `findings` (if it survived to billion scale):
- 1B rows × 5KB (with bloat from rule duplication) = **5 TB single table**
- Single index 80GB, doesn't fit RAM
- Vacuum impossible

**Compression ratio: ~2.5× on raw size, ~5× on operator-hot working set.**

## 5. Migration plan — phases A through E

### Phase A: Add catalog without breaking (1 week)

**Goal:** introduce `detection_rules` table, populate it, add `findings.rule_id` FK column, dual-write on every ingest.

**Scope:**
- [ ] Migration `000167_detection_rules_catalog.up.sql`:
    - Create `detection_rules` table
    - Add column `findings.rule_id TEXT REFERENCES detection_rules(rule_id)` nullable initially
    - Add index on `findings(rule_id)` for future-proofing
- [ ] Backfill controller: scan existing findings, derive `(scanner, scanner_rule_id)` from `findings.source` + `findings.rule_id`, upsert into `detection_rules` and update FK on findings
- [ ] Ingest path change: every `processor_findings.go` insert path must
    1. UPSERT a `detection_rules` row (idempotent on conflict)
    2. Populate `findings.rule_id` FK
- [ ] No read-path changes — UI still queries `findings`

**Acceptance:**
- 100% of existing findings have non-null `rule_id`
- `detection_rules` populated with current scanner output
- Ingest p99 latency increase ≤10%
- Rollback: drop column + table

**Risk:** Low. Pure addition, no read disturbance.

### Phase B: Materialised instance view (2 weeks)

**Goal:** prove that operator-facing queries can run on instance-shaped data without committing to a real table yet.

**Scope:**
- [ ] `CREATE MATERIALIZED VIEW vulnerability_instances_mv AS
       SELECT (tenant_id, asset_id, rule_id) keys + state aggregates FROM findings`
- [ ] Refresh every 5 min via controller
- [ ] UI dashboard switches to query the MV (read-only)
- [ ] Validate metric parity: counts, severity buckets, MTTR same as before
- [ ] A/B test by querying both, log discrepancies

**Acceptance:**
- Dashboard load <1s on 10M findings vs current ~5s
- Zero metric divergence over 1-week canary

**Risk:** Medium. View staleness at refresh boundary; mitigated by 5-minute refresh.

### Phase C: Convert to real table + dual-write (2 weeks)

**Goal:** transition from view to authoritative table.

**Scope:**
- [ ] Migration creates real `vulnerability_instances` table (schema §3.2)
- [ ] One-shot backfill from materialised view → table
- [ ] Drop materialised view
- [ ] Ingest path dual-writes: insert into `findings` (legacy) + upsert into `vulnerability_instances`
- [ ] Read path: dashboards + finding-list UI now query `vulnerability_instances`
- [ ] Finding mutations (status change, suppress, assign) write to BOTH

**Acceptance:**
- All read endpoints serve from `vulnerability_instances`
- Mutation tests verify both tables update on each operation
- Dual-write monitor alerts on divergence

**Risk:** Medium-high. Dual-write bug = data drift. Mitigated by automated reconciliation cron.

### Phase D: Add event log + cutover (2 weeks)

**Goal:** introduce `detection_events`, migrate ingest to write events first, derive instance state from latest event.

**Scope:**
- [ ] Migration creates `detection_events` partitioned table
- [ ] Ingest path: write event → upsert instance with last_event_id pointer
- [ ] Backfill: synthesise events for last 30 days of findings (best-effort from scan_session links if available)
- [ ] Audit/timeline UI switches to query `detection_events` for history
- [ ] Drop `findings` legacy reads on routes that don't need backward compat
- [ ] Keep `findings` table for 30 days as fallback

**Acceptance:**
- New scans land in events first, instances derive from events
- "First seen" / "last seen" timestamps now sourced from events, not finding row
- Old finding-list endpoints continue to work via instance table

**Risk:** Medium. Event ingest path is high-throughput; partition pre-creation must keep up with calendar.

### Phase E: Cleanup (1 week)

**Goal:** remove dead code, document the model, lock down.

**Scope:**
- [ ] Drop `findings` table (after 30-day grace)
- [ ] Drop dual-write paths
- [ ] Update API documentation
- [ ] Update CLAUDE.md schema notes
- [ ] Re-run multi-role audit to confirm no regressions
- [ ] Mark migration complete in ROADMAP.md

**Acceptance:**
- 0 references to `findings` in codebase except deprecation docs
- All E2E tests green on instance/event model

## 6. Rule catalog feed — sourcing strategy

Rule catalog must be populated from authoritative external sources, not handcrafted. The architecture borrows from `threat_intel_refresher` controller (currently dead per audit F-15).

| Source | Type | Cardinality | Update cadence | Authority |
|---|---|---|---|---|
| **NVD CVE feed** | CVE catalogue (rule = 1 CVE) | ~250K | Daily (when NVD is up) | High (despite NVD backlog issues) |
| **OSV.dev** | CVE + ecosystem-specific | ~200K | Hourly | High (Google-maintained) |
| **GitHub Security Advisories** | CVE + GHSA-IDs | ~50K | Daily | High (curated for OSS ecosystem) |
| **CISA KEV** | Known-exploited CVEs subset | 1.5K | Daily | Critical for prioritisation |
| **Trivy vulnerabilities-db** | Pre-resolved per ecosystem | ~200K | 6h | High |
| **Nuclei templates** | Active scanner rules | ~7K templates | Weekly | Medium-high (community) |
| **Semgrep registry** | SAST rule definitions | ~3K | Weekly | High (Semgrep team) |
| **Gitleaks rules** | Secret patterns | ~150 | Rarely | High |

**Implementation sketch:**

```go
// internal/infra/controller/rule_catalog_refresher.go
//
// Refreshes detection_rules by polling each source on its own
// cadence. Each source has a normaliser that maps source-format
// to the catalog row shape. Conflicts (same scanner + scanner_rule_id
// from two feeds) resolved by source priority: vendor-direct >
// trivy-resolved > NVD-derived.
```

Rule rows are also created on-demand at ingest time when an unknown rule appears in scan output — this guarantees the catalog never "blocks" ingest. Asynchronous enrichment fills in metadata after the fact.

## 6.5. The CVE identity problem — why we need a fourth level

The 3-level model handles **scanner-rule** identity. It does **not** handle **vulnerability** identity. These are different things, and conflating them produces a class of edge cases that breaks operator UX.

### The canonical edge case

Tenable plugin **156032** detects Log4Shell. So does Nuclei template **log4shell-detect**. Same CVE-2021-44228, same host:

```
detection_rules:
  tenable:156032          → cve_ids = ['CVE-2021-44228', 'CVE-2021-45046', ...]
  nuclei:log4shell-detect → cve_ids = ['CVE-2021-44228']

vulnerability_instances:                 -- per (asset, rule)
  (host_42, tenable:156032)         status=open
  (host_42, nuclei:log4shell-detect) status=open

UI without dedup:
  host_42 has 2 findings ← WRONG. Operator sees the same problem twice.
```

This is exactly what Tenable, Qualys, and CrowdStrike solve with a **CVE-level identity layer** above the rule layer.

### Resolution: 4-level model with CVE roll-up

```
LEVEL 0 — VULNERABILITIES (CVE / GHSA / vendor advisory ID)
  Already exists from PR #62 — `vulnerabilities` table.
  Identity: cve_id (e.g., CVE-2021-44228)
  ──────────────────────────────────────────
                ▲ N:M (junction table)
LEVEL 1 — DETECTION RULES (scanner-specific signature)
  Identity: scanner:scanner_rule_id (e.g., tenable:156032)
  Cross-references CVEs via cve_ids[] array OR junction table
  ──────────────────────────────────────────
                ▲ 1:N
LEVEL 2 — VULNERABILITY INSTANCES (per-asset state)
  Identity: (tenant, asset, rule_id) — one row per scanner detection
  Both `vulnerability_id` AND `rule_id` FKs — instance knows BOTH
  the canonical CVE and the rule that flagged it
  ──────────────────────────────────────────
                ▲ 1:N
LEVEL 3 — DETECTION EVENTS (scan observation log)
```

### Two viable strategies for the multi-scanner-same-CVE case

**Strategy A — Keep both instances, dedup at UI layer (Tenable/Qualys approach)**

- Both `(host_42, tenable:156032)` and `(host_42, nuclei:log4shell-detect)` rows exist
- Each carries `vulnerability_id = <CVE-2021-44228 row>` FK
- Operator UI groups by `vulnerability_id` per asset:
  - "host_42 — CVE-2021-44228 (Log4Shell)" — single card
  - Drill-down shows: "Detected by 2 scanners: Tenable plugin 156032, Nuclei log4shell-detect"
- Status / owner / SLA are operator-facing concerns — stored on the GROUPED CVE level via a separate `(asset, vulnerability_id)` aggregate row, OR derived as MAX(severity), MIN(due_date), etc. across the constituent rule-instances

**Strategy B — Single instance per (asset, CVE), rules listed inside (Snyk approach)**

- Only ONE row in `vulnerability_instances` per `(asset, cve_id)`
- The row has a `triggered_by_rules[]` array listing all detection_rules that flagged it
- Simpler UI, but loses fidelity: "rule X on this asset has different evidence than rule Y" is harder to express

### Recommendation: Strategy A (rule-level instances + CVE-level grouping)

Why Strategy A wins for our context:

| Factor | A (per-rule instance) | B (per-CVE instance) |
|---|---|---|
| Per-rule evidence preserved (Tenable plugin output ≠ Nuclei response) | ✅ Native | ❌ Loses one or merges blob |
| First-seen timestamp per detection method | ✅ Per-instance | ❌ Earliest only |
| Suppress single scanner without hiding the CVE entirely (e.g., known false positive in Nuclei but Tenable verified) | ✅ Per-instance suppression | ❌ Suppresses everything |
| Storage overhead | 2× per CVE (small) | 1× |
| UI complexity | Group-by-CVE in query | Trivial |
| Audit trail integrity (who saw what at scan time) | ✅ Per-instance event log | ❌ Lossy |

The 2× storage overhead is real but manageable: typical assets have <5 scanners scanning the same CVE → 5× factor at worst, applied to the operator-hot working set (~1M instances) = ~5M rows. Still fits comfortably within the 100M-per-cluster ceiling we set in §4.

### Schema impact

Add to `vulnerability_instances` (already partially in place from PR #62):

```sql
ALTER TABLE vulnerability_instances
    ADD COLUMN vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE SET NULL;

CREATE INDEX idx_vi_tenant_vulnerability
    ON vulnerability_instances (tenant_id, vulnerability_id, status)
    WHERE vulnerability_id IS NOT NULL;
```

Population logic (Phase B trigger or app-side):
1. On instance insert, look up `vulnerability_id` from `detection_rules.cve_ids[0]` → resolve to `vulnerabilities` table
2. If multiple CVEs in array, link instance to each via a `vulnerability_instance_cves` junction table

For the simpler "1 rule = 1 primary CVE" case (90%+ of SCA findings), the array's first element wins. The junction table is only needed when chained CVEs matter for reporting.

## 6.6. Edge case catalogue

Each entry: scenario → why it matters → handling strategy.

### EC-01 — Two scanners detect same CVE on same host

Already handled above (§6.5). Strategy A.

### EC-02 — Same SAST rule fires at multiple file:line locations

**Scenario:** Semgrep rule `detect-xss` flags lines 42, 87, 131 in `app.js` of asset `repo-X`.

**Why it matters:** Each location is a separate fix. Treating them as one instance loses fix-tracking granularity.

**Handling:** Unique key includes `file_path` and `line_number` — three separate `vulnerability_instances` rows. UI groups by `(asset, rule_id)` showing "3 occurrences". Suppression can target individual lines (false positive in test fixture) or the whole rule (rare).

**Schema:** `UNIQUE (tenant_id, asset_id, rule_id, COALESCE(file_path, ''), COALESCE(line_number, -1))` — already in §3.2.

### EC-03 — Scanner renames or removes a rule

**Scenario:** Tenable retires plugin 12345 (vuln superseded by 99999). Older findings reference rule_id `tenable:12345`. New scans never emit it again.

**Why it matters:** FK integrity. If we DELETE the catalog row, instances orphan.

**Handling:** Never delete. Set `detection_rules.status = 'deprecated'`. Instances retain FK; UI can show "this rule is no longer maintained" notice on stale findings.

**Schema:** `status` column already includes `'deprecated'` value. Catalog refresh controller sets it when source feed indicates retirement.

### EC-04 — Scanner reuses a rule_id with different meaning

**Scenario:** Trivy v0.50 plugin "X" detects CVE-A. Trivy v0.55 plugin "X" detects CVE-B (rare but happens with rule renumbering).

**Why it matters:** detection_rules row's metadata (CVE ids, fix advice) becomes wrong for instances created under the old meaning.

**Handling (defensive):** include `scanner_version` in trigger logic — if scanner_version drift detected on the same scanner_rule_id, log a warning and update catalog with newest-wins. Old instances pointing to it will display the newer meaning, which is wrong but rare. Better to log to ops than fail ingest.

**Long-term mitigation:** include version in rule_id namespace: `tenable@v202404:156032`. Adds storage overhead but makes the catalog immutable per version. Defer to v2.

### EC-05 — Multiple CVEs covered by one rule (Log4Shell pattern)

**Scenario:** Tenable plugin 156032 covers CVE-2021-44228, 45046, 45105, 44832 — four CVEs.

**Why it matters:** When operator clicks "show me CVE-2021-45046", we need to find the rule via array containment.

**Handling:** `detection_rules.cve_ids` is `TEXT[]` with GIN index. Query: `WHERE 'CVE-2021-45046' = ANY(cve_ids)`. UI displays first as primary, others as "also covers".

**Schema:** GIN index on `cve_ids` already in §3.1.

### EC-06 — Ingest sees rule_id with no associated CVE (SAST, CSPM)

**Scenario:** Semgrep rule `detect-xss` is a SAST rule with no CVE; CSPM "S3 bucket public" same.

**Why it matters:** `cve_ids` empty → cannot roll up by CVE. UI must group differently for non-CVE rules.

**Handling:** UI's group-by toggle: by-CVE for SCA, by-rule for SAST/CSPM, by-asset for any. The data model accommodates all — `cve_ids` empty array is the signal that CVE roll-up doesn't apply.

### EC-07 — Tool name normalisation

**Scenario:** Same scanner reported as "Trivy", "trivy", "trivy-aqua", "TrivyScan".

**Why it matters:** Different `tool_name` values → different `detection_rules` rows for the same logical scanner.

**Handling:** Lowercase + canonical-name table during ingest. Maintain `scanner_aliases` config (ingest-side, not DB):

```go
var scannerCanonical = map[string]string{
    "trivy": "trivy",       "trivyscan": "trivy",       "trivy-aqua": "trivy",
    "nuclei": "nuclei",     "nuclei-scan": "nuclei",
    "semgrep": "semgrep",
    "tenable.io": "tenable", "nessus": "tenable",
}
```

Apply at ingest before composing rule_id. Document the canonical list in CLAUDE.md.

### EC-08 — Pentest / manual finding without scanner

**Scenario:** Manual pentest writes a finding with `tool_name = ''` and `rule_id = ''`.

**Why it matters:** Trigger skips → `detection_rule_id` stays NULL. Phase E goal is NOT NULL constraint.

**Handling:** Synthesise rule_id at ingest for manual sources:
- `manual:pentest-<campaign_id>:<finding_index>` — campaign-scoped
- `manual:bug_bounty:<report_id>` — bug bounty per report
- `manual:redteam:<exercise_id>:<finding_index>`

Detection_rules row created on-demand with `category='manual'`. Each pentest finding becomes its own catalog entry — slightly polluting the catalog, but enables uniform querying. Acceptable.

### EC-09 — Rescan creates instances for missing assets (asset moved tenants)

**Scenario:** Asset moves from tenant A to tenant B (corporate restructure). Old instances under tenant A. New scan in tenant B creates new instances. Old instances orphan in tenant A.

**Why it matters:** Compliance / audit trail breaks if old instances simply lost.

**Handling:** Asset move = cascading instance migration (move `tenant_id` on instance rows). Document as ops procedure, not auto-trigger. Audit log records both transitions.

### EC-10 — Asset deletion cascade

**Scenario:** Operator deletes asset X. Instances on X lose meaning.

**Why it matters:** Instance rows reference `asset_id` FK. Hard delete cascades; soft delete leaves dangling.

**Handling:** Soft-delete pattern — `assets.deleted_at IS NOT NULL`. Instances stay (for audit trail). Filter out in default queries `WHERE asset.deleted_at IS NULL`. After 90 days, hard-purge orphaned instances via retention controller.

### EC-11 — Concurrent ingest race on same (tenant, asset, rule)

**Scenario:** Two scan workers process the same asset's data in parallel. Both try to insert the same instance.

**Why it matters:** UNIQUE violation on instance. One worker fails, retry needed.

**Handling:** `INSERT ... ON CONFLICT (tenant_id, asset_id, rule_id, file_path, line_number) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at, last_event_id = EXCLUDED.last_event_id` — both workers succeed, one wins the upsert race, last_seen takes latest.

**Schema:** Already covered by `ON CONFLICT DO UPDATE` upsert pattern in current findings table. Carries through to instances.

### EC-12 — Tenant overrides rule severity

**Scenario:** Tenant A wants Log4Shell as P0 always (financial industry). Tenant B accepts P2 for log4j on internal infra.

**Why it matters:** `detection_rules` is global, can't be per-tenant.

**Handling:** Per-tenant override lives in `vulnerability_instances.severity` and `priority_class` — populated by the priority engine using tenant-specific rules (RFC-003 priority gate). The rule's `severity_native` is "what the scanner said"; instance's `severity` is "what the tenant says". UI shows the latter; rule's value visible in audit details.

### EC-13 — CVE resolves to no `vulnerabilities` row yet

**Scenario:** Scan reports CVE-2026-99999 — brand new CVE, NVD has not published metadata yet.

**Why it matters:** `detection_rules.cve_ids` references CVE that's not in `vulnerabilities` table.

**Handling:** Allow dangling CVE references — `cve_ids` is plain TEXT[], not FK. Catalog refresh controller pulls NVD daily; once CVE row appears, FK resolution at query time succeeds. Until then, UI shows "CVE-2026-99999 (no NVD data yet)".

### EC-14 — Rule catalog conflict between feeds

**Scenario:** NVD says CVE-X has CVSS 9.8. OSV says 8.5. Vendor advisory says 7.2.

**Why it matters:** Refresh controller writes one value. Which?

**Handling:** Source priority hierarchy. Codified in refresh controller:

```
PRIORITY = {
  'scanner_native': 100,   -- what the scanner directly reported
  'cisa_kev':       95,    -- KEV is authoritative for exploitation
  'osv':            80,    -- ecosystem-aware, fast updates
  'ghsa':           75,    -- well-curated for OSS
  'nvd':            70,    -- official but slow
  'backfill':       10,    -- legacy backfill, lowest priority
  'manual_override':150,   -- explicit operator override beats everything
}
```

Higher priority wins on UPSERT.

### EC-15 — UPSERT trigger storm during bulk ingest

**Scenario:** Ingest 100K findings in a batch, all with new (tool_name, rule_id) pairs. Trigger fires per-row → 100K catalog upserts.

**Why it matters:** Trigger overhead per row, table-level locks if multiple chunks contend.

**Handling:** Phase A's BEFORE INSERT trigger is OK at <10K rows/batch. For higher throughput, deprecate the trigger in Phase B and move logic to application — pre-build catalog rows from distinct `(tool_name, rule_id)` of incoming batch BEFORE inserting findings, then bulk-insert with FK already populated. Code-side dedup is faster than per-row trigger calls.

### EC-16 — Cross-tenant rule pollution

**Scenario:** Tenant A custom-uploads a Nuclei template "tenantA-internal-check". Now `detection_rules` has it. Tenant B's scan never references it but it sits in the global catalog.

**Why it matters:** Catalog pollution + minor information disclosure (rule existence).

**Handling:**
- Option 1: keep `detection_rules` global, accept that custom rules pollute. Title sanitisation on ingest prevents PII leak.
- Option 2: introduce `detection_rules.tenant_id NULLABLE` — global catalog when NULL, tenant-scoped when set. UNIQUE becomes `(scanner, scanner_rule_id, COALESCE(tenant_id, '...'))`.

**Recommendation for Phase A:** Option 1, defer to Phase F if customer needs custom rules at scale.

### EC-17 — Existing pentest/manual findings have no tool_name in production

**Scenario:** Existing 30% of findings are pentest-imports with `tool_name = NULL`.

**Why it matters:** Phase A trigger skips them — Phase E NOT NULL goal blocked.

**Handling:** Backfill controller (separate job, batched) generates synthesised rule_id per EC-08 pattern. Documented in migration runbook.

### EC-18 — Scanner emits same rule with different categories on different runs

**Scenario:** First scan reports Trivy rule `XYZ` as `category='sca'`. Second scan reports same rule_id as `category='container'` (rare config drift).

**Why it matters:** detection_rules row has UNIQUE on (scanner, scanner_rule_id) — one row, one category. Conflict.

**Handling:** Trigger writes once on first sight, never updates category on conflict. Logs warning when scanner reports a category mismatch. Rule's category is determined by FIRST observation; refresh controller can correct via authoritative feed later.

### EC-19 — Replay attack: malicious agent re-submits old scan output as "new"

**Scenario:** Compromised agent replays a 6-month-old report with current `observed_at`.

**Why it matters:** Instance `last_seen_at` updates to fake now. Stale findings appear fresh. Audit trail corrupted.

**Handling:** Validate `observed_at` against scan_session record's actual time. Reject events claiming `observed_at > received_at + 5min` slack. Detection events log includes received_at separately so forensic timeline reconstructable.

### EC-20 — Scanner reports finding without asset (orphan finding)

**Scenario:** Nuclei scan target was a domain that didn't resolve at scan time. Report has no concrete asset.

**Why it matters:** `vulnerability_instances.asset_id NOT NULL` constraint fails.

**Handling:** Synthesise placeholder asset (e.g., `synthetic_target:<scan_session_id>`) at ingest, OR drop the finding with warning. Current code drops; document the choice.

---

## 7. Backwards-compatibility commitments

During Phases A–D, no breaking change to:
- REST API contracts (path, status codes, JSON shape) — instance shape mirrors current finding shape
- Webhook payloads
- Notification body templates
- SDK client method names

After Phase E, `findings` becomes a deprecated synonym for `vulnerability_instances` in API surface for one minor version, then dropped in the next major release.

## 8. Open questions

- [ ] **Rule_id format** — TEXT vs UUID? Argument for TEXT: human-readable in logs, joinable to scanner-native IDs without lookup. Argument for UUID: faster joins on 100M-row instance table. **Decision: TEXT for now, can swap to surrogate UUID if benchmarks demand.**
- [ ] **Instance unique key** — `(tenant, asset, rule)` or `(tenant, asset, rule, file, line)`? SAST findings differ by line; SCA findings are per-component. **Decision: include `file_path` and `line_number` in unique key, COALESCE for nullable.**
- [ ] **Asset deletion cascade** — when an asset is deleted, drop instances and events? **Decision: yes for instances; for events, keep historical record (set asset_id soft-deleted flag).**
- [ ] **Multi-tenant rule overrides** — can a tenant override `detection_rules.severity_native`? **Decision: no. Use `vulnerability_instances.severity` for tenant-context.**
- [ ] **Rule deprecation** — what happens when a scanner removes a plugin? **Decision: `detection_rules.status = 'deprecated'`, instances remain accessible read-only.**

## 9. Rollback plan per phase

| Phase | Rollback action | Data loss? |
|---|---|---|
| A | Drop `findings.rule_id` column + `detection_rules` table | None |
| B | Drop materialized view | None |
| C | Disable dual-write, drop `vulnerability_instances` | None (findings remains source of truth) |
| D | Disable event-write, restore `findings` reads | Last 30d audit timeline thinner |
| E | Cannot rollback (findings dropped). Backup before, restore from backup if needed | Possible |

## 10. Success metrics

After Phase E:

| Metric | Baseline (today) | Target |
|---|---|---|
| Hot working set size (1M findings) | ~3 GB | ≤600 MB |
| Dashboard query p99 (10M findings) | ~5s | ≤500ms |
| Single-table row count ceiling | ~50M | ≥500M before further partitioning |
| Operator UI list pagination latency | ~2s @ offset 100K | ≤200ms via cursor |
| Re-scan ingest throughput | ~20K findings/min | ≥100K findings/min |
| Rule catalog coverage (% of findings with FK) | 0% | ≥99% |

## 11. References

- Tenable.io plugin architecture: <https://www.tenable.com/plugins> (~200K plugins, daily updates)
- Qualys QID system: knowledge base of ~50K rules
- Wiz issue catalog: ~10K controls + asset graph (Neo4j-style)
- Snyk vulnerability database: project-centric instance model
- CrowdStrike Falcon Spotlight: hybrid CVE catalog + per-host instance
- OSV schema: <https://ossf.github.io/osv-schema/> — likely template for our rule normaliser
- Postgres declarative partitioning: <https://www.postgresql.org/docs/current/ddl-partitioning.html>
