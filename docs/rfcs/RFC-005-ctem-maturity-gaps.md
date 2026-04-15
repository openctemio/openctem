# RFC-005: CTEM Maturity Gaps — Cycles, Metrics, Controls, Escalation

- **Status**: Draft
- **Created**: 2026-04-15
- **Priority**: High
- **Depends on**: RFC-004 (Priority Classes)
- **Estimated effort**: ~3 weeks (7 gaps, 3 phases)
- **CTEM Stages**: All 5 stages
- **Reference**: https://ctem.org/docs/getting-started

---

## Tổng quan

RFC này cover 7 gaps còn lại để đưa OpenCTEM từ 67% lên ~90% CTEM compliance. Mỗi gap là một feature độc lập, có thể implement theo thứ tự bất kỳ (trừ Gap 9 phải trước Gap 3).

| Gap | Feature | Stage | Effort | Migration |
|-----|---------|-------|--------|-----------|
| 3 | CTEM Cycle Entity | Scoping | High | 000143-000144 |
| 4 | Risk Trend / Outcome Metrics | All | Medium | 000145 |
| 5 | Data Quality Scorecard | Discovery | Low | None |
| 6 | Compensating Controls | Prioritization | Medium | 000146-000147 |
| 7 | Automated SLA Escalation | Mobilization | Low | 000148 |
| 8 | Verification Checklist | Validation | Low | 000149 |
| 9 | Threat Model / Attacker Profiles | Scoping | Medium | 000150 |

---

## Gap 3: CTEM Cycle Entity

### Mục tiêu

Một CTEM cycle là đợt assessment có thời hạn (thường quarterly). Mỗi cycle ghi nhận: scope gì, tìm thấy gì, fix được gì. Đây là backbone để đo improvement over time.

### Schema

```sql
-- 000143_ctem_cycles.up.sql
CREATE TABLE ctem_cycles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'planning'
      CHECK (status IN ('planning','active','review','closed')),
    start_date DATE,
    end_date DATE,
    charter JSONB DEFAULT '{}'::jsonb,
    -- charter: {business_priorities, risk_appetite, in_scope_services[], objectives[]}
    threat_model_id UUID,  -- FK to attacker_profiles (optional)
    closed_by UUID,
    closed_at TIMESTAMPTZ,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ctem_cycles_tenant ON ctem_cycles(tenant_id, status);

-- 000144_ctem_cycle_snapshots.up.sql
CREATE TABLE ctem_cycle_scope_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cycle_id UUID NOT NULL REFERENCES ctem_cycles(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL,
    scope_target_id UUID,  -- which scope target included this asset
    included_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cycle_snapshots_cycle ON ctem_cycle_scope_snapshots(cycle_id);

CREATE TABLE ctem_cycle_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cycle_id UUID NOT NULL REFERENCES ctem_cycles(id) ON DELETE CASCADE,
    metric_type VARCHAR(50) NOT NULL,
    -- Types: risk_before, risk_after, findings_discovered, findings_resolved,
    --        mttr_hours, sla_compliance_pct, p0_resolved, p1_resolved
    value DECIMAL(12,2) NOT NULL,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cycle_metrics ON ctem_cycle_metrics(cycle_id, metric_type);
```

### Domain

```go
// pkg/domain/ctemcycle/entity.go
type Cycle struct {
    id        shared.ID
    tenantID  shared.ID
    name      string
    status    CycleStatus  // planning → active → review → closed
    startDate *time.Time
    endDate   *time.Time
    charter   Charter      // JSONB struct
}

type Charter struct {
    BusinessPriorities []string `json:"business_priorities"`
    RiskAppetite       string   `json:"risk_appetite"`
    InScopeServices    []string `json:"in_scope_services"`
    Objectives         []string `json:"objectives"`
}

func (c *Cycle) Activate()  error  // planning → active, snapshots scope
func (c *Cycle) StartReview() error // active → review
func (c *Cycle) Close(metrics) error // review → closed, requires metrics
```

### Service Logic

- `Activate()` → freeze current scope targets + matching assets into `ctem_cycle_scope_snapshots`
- `Close()` → compute metrics by querying findings created/resolved within cycle timeframe
- Metrics tính: risk score trước/sau, findings discovered/resolved, MTTR, SLA compliance %

### API

```
POST   /api/v1/ctem-cycles                    — Create
GET    /api/v1/ctem-cycles                    — List (status filter)
GET    /api/v1/ctem-cycles/{id}               — Get with metrics
PUT    /api/v1/ctem-cycles/{id}               — Update charter/dates
POST   /api/v1/ctem-cycles/{id}/activate      — Snapshot + transition
POST   /api/v1/ctem-cycles/{id}/review        — Transition
POST   /api/v1/ctem-cycles/{id}/close         — Compute metrics + transition
GET    /api/v1/ctem-cycles/{id}/scope          — Scope snapshot
GET    /api/v1/ctem-cycles/{id}/metrics        — Metrics detail
```

### UI

- `(scoping)/cycles/page.tsx` — List cycles (timeline view, status badges)
- `(scoping)/cycles/[id]/page.tsx` — Detail: charter editor, scope snapshot tab, metrics dashboard (bar charts)

---

## Gap 4: Risk Trend / Outcome Metrics

### Mục tiêu

Time-series data cho executive dashboards. ctem.org: "Risk Reduction Metrics: Trend lines reflect validated exposure reduction, not discovery volume."

### Schema

```sql
-- 000145_risk_snapshots.up.sql
CREATE TABLE risk_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    snapshot_date DATE NOT NULL,
    risk_score_avg DECIMAL(5,2),
    risk_score_max DECIMAL(5,2),
    findings_open INT DEFAULT 0,
    findings_closed_today INT DEFAULT 0,
    exposures_active INT DEFAULT 0,
    sla_compliance_pct DECIMAL(5,2),
    mttr_critical_hours DECIMAL(8,2),
    mttr_high_hours DECIMAL(8,2),
    mttr_medium_hours DECIMAL(8,2),
    mttr_low_hours DECIMAL(8,2),
    p0_open INT DEFAULT 0,
    p1_open INT DEFAULT 0,
    p2_open INT DEFAULT 0,
    p3_open INT DEFAULT 0,
    data_quality JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (tenant_id, snapshot_date)
);

CREATE INDEX idx_risk_snapshots_range
  ON risk_snapshots(tenant_id, snapshot_date DESC);
```

### Service Logic

New controller `risk_snapshot_controller.go`:
- Interval: daily (2 AM)
- For each tenant: aggregate from findings, assets, exposures → insert 1 row
- MTTR calculated: AVG(resolved_at - first_detected_at) for findings resolved today, grouped by severity

### API (extend dashboard handler)

```
GET /api/v1/dashboard/risk-trend?range=90d         — risk score time-series
GET /api/v1/dashboard/mttr-trend?range=90d          — MTTR over time
GET /api/v1/dashboard/sla-compliance?range=90d      — SLA compliance trend
GET /api/v1/dashboard/priority-trend?range=90d      — P0/P1/P2/P3 open counts over time
```

### UI

- Line charts (recharts) on dashboard: risk score, MTTR, SLA compliance
- Stacked area chart: P0/P1/P2/P3 open counts over time
- Period selector: 30d / 90d / 1y

---

## Gap 5: Data Quality Scorecard

### Mục tiêu

ctem.org Data Quality targets: "% assets with assigned owner ≥ 95%, % exposures with evidence ≥ 90%, median last-seen age < 48h, dedup rate trending up."

### Schema

None — pure computed queries. Optionally store in `risk_snapshots.data_quality` JSONB.

### Service Logic

Add to `DashboardService`:

```go
func (s *DashboardService) GetDataQualityScorecard(ctx, tenantID) (*DataQualityScorecard, error) {
    // 5 parallel queries (or 1 CTE):
    // 1. SELECT COUNT(*) FILTER(WHERE owner_id IS NOT NULL) * 100.0 / COUNT(*) FROM assets
    // 2. SELECT COUNT(*) FILTER(WHERE source_metadata IS NOT NULL) * 100.0 / COUNT(*) FROM findings
    // 3. SELECT PERCENTILE_CONT(0.5) WITHIN GROUP(ORDER BY EXTRACT(epoch FROM now()-last_seen_at)/86400) FROM assets WHERE exposure='internet'
    // 4. Dedup rate from asset_merge_log count / total assets
    // 5. Assets with status='unknown' or sub_type is null / total
}
```

```go
type DataQualityScorecard struct {
    AssetOwnershipPct     float64 `json:"asset_ownership_pct"`
    FindingEvidencePct    float64 `json:"finding_evidence_pct"`
    MedianLastSeenDays    float64 `json:"median_last_seen_days"`
    DeduplicationRate     float64 `json:"deduplication_rate"`
    UnclassifiedAssetRate float64 `json:"unclassified_asset_rate"`
}
```

### API

```
GET /api/v1/dashboard/data-quality
```

### UI

- 5 gauge/progress widgets on dashboard or dedicated `/insights/data-quality` page
- Color coded: green (≥ target), yellow (approaching), red (below)
- Targets configurable per-tenant in settings

---

## Gap 6: Compensating Controls

### Mục tiêu

ctem.org: "Valid compensating controls require defensible documentation: segmentation, identity controls, runtime protections, detection with proven coverage."

### Schema

```sql
-- 000146_compensating_controls.up.sql
CREATE TABLE compensating_controls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    control_type VARCHAR(30) NOT NULL
      CHECK (control_type IN ('segmentation','identity','runtime','detection','other')),
    status VARCHAR(20) NOT NULL DEFAULT 'active'
      CHECK (status IN ('active','inactive','expired','untested')),
    reduction_factor DECIMAL(3,2) DEFAULT 0.0
      CHECK (reduction_factor >= 0 AND reduction_factor <= 1),
    last_tested_at TIMESTAMPTZ,
    test_result VARCHAR(20)
      CHECK (test_result IS NULL OR test_result IN ('pass','fail','partial')),
    test_evidence TEXT,
    expires_at TIMESTAMPTZ,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_comp_controls_tenant ON compensating_controls(tenant_id);

-- 000147_compensating_control_links.up.sql
CREATE TABLE compensating_control_assets (
    control_id UUID NOT NULL REFERENCES compensating_controls(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    PRIMARY KEY (control_id, asset_id)
);

CREATE TABLE compensating_control_findings (
    control_id UUID NOT NULL REFERENCES compensating_controls(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    PRIMARY KEY (control_id, finding_id)
);
```

### Domain

```go
type CompensatingControl struct {
    id              shared.ID
    tenantID        shared.ID
    name            string
    controlType     ControlType
    status          ControlStatus
    reductionFactor float64   // 0.0-1.0
    lastTestedAt    *time.Time
    testResult      *TestResult
}

func (c *CompensatingControl) IsEffective() bool {
    return c.status == Active && c.testResult != nil && *c.testResult != Fail &&
           (c.expiresAt == nil || c.expiresAt.After(time.Now()))
}
```

### Integration vào Risk Formula

Trong `priority.go` ClassifyPriority:
```go
// isProtected = có ≥1 compensating control effective trên asset
// controlReductionFactor = max reduction_factor của effective controls
// P1 → P2 nếu isProtected && controlReductionFactor ≥ 0.3
```

### API

```
POST/GET    /api/v1/compensating-controls
GET/PUT/DEL /api/v1/compensating-controls/{id}
POST        /api/v1/compensating-controls/{id}/test     — Record test result
POST        /api/v1/compensating-controls/{id}/assets    — Link assets
POST        /api/v1/compensating-controls/{id}/findings  — Link findings
```

### UI

- `(validation)/controls/` — list/detail pages
- Finding detail sidebar: "Compensating Controls" section
- Control test recording form

---

## Gap 7: Automated SLA Escalation Job

### Mục tiêu

SLA policies exist nhưng không có enforcement. ctem.org: "Priority-based due dates assigned to tickets."

### Schema

```sql
-- 000148_sla_overdue_index.up.sql
CREATE INDEX CONCURRENTLY idx_findings_sla_overdue
  ON findings(tenant_id, sla_deadline)
  WHERE sla_status NOT IN ('breached','not_applicable')
    AND status NOT IN ('closed','resolved','false_positive','verified');
```

### Service Logic

New controller `sla_escalation_controller.go`:

```go
func (c *SLAEscalationController) Interval() time.Duration { return 15 * time.Minute }

func (c *SLAEscalationController) Reconcile(ctx) error {
    // 1. Query: findings WHERE sla_deadline < NOW() AND sla_status != 'breached' AND still open
    // 2. Batch UPDATE sla_status = 'breached'
    // 3. For each, enqueue notification via outbox:
    //    - Event type: "sla_breach"
    //    - Include: finding title, severity, priority class, SLA deadline, assigned_to
    // 4. If escalation_config.escalate_to_user_ids set, enqueue to those users
}
```

### Integration

- Sử dụng existing `NotificationService.EnqueueNotificationInTx()`
- Sử dụng existing `SLAPolicy.EscalationConfig` JSONB
- Add "sla_breach" to `notification.AllKnownEventTypes()`

### UI

- Notification settings: "SLA Breach" as subscribable event type
- Findings list: "Breached" filter/badge (red timer icon)

---

## Gap 8: Verification Checklist

### Mục tiêu

ctem.org: "Exposure no longer observable, ownership and status updated, validation artifacts attached, monitoring rule added, regression test scheduled."

### Schema

```sql
-- 000149_verification_checklists.up.sql
CREATE TABLE finding_verification_checklists (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL,
    exposure_cleared BOOLEAN DEFAULT false,
    evidence_attached BOOLEAN DEFAULT false,
    register_updated BOOLEAN DEFAULT false,
    monitoring_added BOOLEAN,          -- NULL = N/A
    regression_scheduled BOOLEAN,      -- NULL = N/A
    notes TEXT,
    completed_by UUID,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### Service Logic

- Auto-create checklist khi finding transitions to `fix_applied`
- Gate transition to `verified`/`closed`: checklist must exist AND `IsComplete()`
- `IsComplete()`: all non-NULL boolean fields must be true

### API

```
GET /api/v1/findings/{id}/verification-checklist
PUT /api/v1/findings/{id}/verification-checklist
```

### UI

- Finding detail: "Verification Checklist" card (appears after fix_applied)
- Checkbox list with labels
- "Verify" button disabled until all required items checked

---

## Gap 9: Threat Model / Attacker Profiles

### Mục tiêu

ctem.org: "Threat assumptions: external attacker with commodity tooling, external with stolen credentials, third-party compromise." Mỗi CTEM cycle cần declare threat model.

### Schema

```sql
-- 000150_attacker_profiles.up.sql
CREATE TABLE attacker_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    profile_type VARCHAR(30) NOT NULL
      CHECK (profile_type IN (
        'external_unauth','external_stolen_creds',
        'malicious_insider','supplier_compromise','custom'
      )),
    description TEXT,
    capabilities JSONB DEFAULT '{}'::jsonb,
    -- {network_access: "external", credential_level: "none|user|admin",
    --  persistence: false, tools: ["commodity","custom"]}
    assumptions TEXT,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_attacker_profiles_tenant ON attacker_profiles(tenant_id);

-- Link to CTEM cycles
CREATE TABLE ctem_cycle_attacker_profiles (
    cycle_id UUID NOT NULL REFERENCES ctem_cycles(id) ON DELETE CASCADE,
    profile_id UUID NOT NULL REFERENCES attacker_profiles(id) ON DELETE CASCADE,
    PRIMARY KEY (cycle_id, profile_id)
);
```

### Domain

```go
type AttackerProfile struct {
    id          shared.ID
    tenantID    shared.ID
    name        string
    profileType ProfileType
    capabilities Capabilities
    assumptions string
}

type Capabilities struct {
    NetworkAccess   string   `json:"network_access"`   // external, internal, physical
    CredentialLevel string   `json:"credential_level"` // none, user, admin
    Persistence     bool     `json:"persistence"`
    Tools           []string `json:"tools"`            // commodity, custom, zero-day
}
```

### Seed Data

4 default profiles created per tenant on first access:

| Type | Name | Capabilities |
|------|------|-------------|
| external_unauth | External Unauthenticated | network=external, cred=none, tools=commodity |
| external_stolen_creds | External with Stolen Credentials | network=external, cred=user, tools=commodity |
| malicious_insider | Malicious Insider | network=internal, cred=user, persistence=true |
| supplier_compromise | Supply Chain Compromise | network=external, cred=admin (via supplier), tools=custom |

### API

```
POST/GET    /api/v1/attacker-profiles
GET/PUT/DEL /api/v1/attacker-profiles/{id}
POST        /api/v1/ctem-cycles/{id}/attacker-profiles    — Link to cycle
GET         /api/v1/ctem-cycles/{id}/attacker-profiles    — List cycle's profiles
```

### UI

- `(scoping)/cycles/[id]/threat-model/` — tab showing linked profiles
- `settings/attacker-profiles/` — library management
- Card-based UI with preset templates

---

## Implementation Order

```
Phase 1 — Quick wins (no dependencies, ~1 week):
  ├── Gap 5: Data Quality Scorecard      [Low]
  ├── Gap 7: SLA Escalation Job          [Low]
  └── Gap 8: Verification Checklist      [Low]

Phase 2 — Foundation (~1.5 weeks):
  ├── Gap 4: Risk Trend Metrics          [Med]
  └── Gap 6: Compensating Controls       [Med]

Phase 3 — CTEM Cycle (~1.5 weeks):
  ├── Gap 9: Attacker Profiles           [Med]  (must be before Gap 3)
  └── Gap 3: CTEM Cycle Entity           [High] (ties everything together)
```

### Migration Sequence

| # | Gap | Table |
|---|-----|-------|
| 000143 | 3 | ctem_cycles |
| 000144 | 3 | ctem_cycle_scope_snapshots, ctem_cycle_metrics |
| 000145 | 4 | risk_snapshots |
| 000146 | 6 | compensating_controls |
| 000147 | 6 | compensating_control_assets, compensating_control_findings |
| 000148 | 7 | Index for SLA overdue queries |
| 000149 | 8 | finding_verification_checklists |
| 000150 | 9 | attacker_profiles, ctem_cycle_attacker_profiles |

*Lưu ý: 000142 thuộc RFC-004 (Priority Classes)*

### Permissions

| Permission | Gap |
|------------|-----|
| `ctem:cycles:read` / `ctem:cycles:write` | 3 |
| `ctem:controls:read` / `ctem:controls:write` | 6 |
| `ctem:profiles:read` / `ctem:profiles:write` | 9 |
| Gaps 4,5 reuse `dashboard:read` | |
| Gap 7 reuse `findings:policies:write` | |
| Gap 8 reuse `findings:write` | |

---

## Projected CTEM Scores After Implementation

| Stage | Before | After RFC-004 | After RFC-005 |
|-------|--------|---------------|---------------|
| 1. Scoping | 73% | 73% | **88%** (+cycle, +threat model) |
| 2. Discovery | 72% | 72% | **82%** (+data quality scorecard) |
| 3. Prioritization | 58% | **82%** (+P0-P3, EPSS/KEV) | **90%** (+compensating controls) |
| 4. Validation | 62% | 62% | **75%** (+verification checklist) |
| 5. Mobilization | 68% | 68% | **82%** (+SLA escalation, +risk trends) |
| **OVERALL** | **67%** | **71%** | **~84%** |

---

## Appendix: CTEM Differentiators (from ctem.org/docs/comparisons)

### OpenCTEM phải thể hiện rõ mình là Operating Model, không phải Tool

> "CTEM is a program structure, not a replacement for your existing tools."
> "Most security programs fail not at discovery, but at converting exposure insight into sustained operational change."

### Differentiators so với VM/EASM/Pentesting đã có và chưa có

| Differentiator | Status | Notes |
|---|---|---|
| Non-CVE exposures (misconfig, identity, secrets, SaaS) | ✅ | 20+ exposure event types |
| Business-context prioritization (not CVSS-only) | ❌ → RFC-004 | Priority classes P0-P3 |
| Validation as first-class stage (not just rescan) | ✅ | Pentest + simulation + control tests |
| Outcome metrics (exposure reduction, not ticket count) | ❌ → RFC-005 Gap 4 | Risk trend / MTTR / SLA compliance |
| Continuous iterative cycles (not annual) | ❌ → RFC-005 Gap 3 | CTEM Cycle entity |
| Cross-functional mobilization (not security-only) | ✅ | Jira integration + team assignment |
| Attack path analysis | ✅ | BFS reachability scoring |
| Compensating controls in risk formula | ❌ → RFC-005 Gap 6 | Control reduction factor |
| Data quality governance | ❌ → RFC-005 Gap 5 | Scorecard metrics |

### CTEM-Aligned Metrics Framework (update Gap 4)

| Category | VM-Aligned (hiện có) | CTEM-Aligned (thêm vào risk_snapshots) |
|----------|---------------------|----------------------------------------|
| Speed | MTTR by severity | MTTR for validated P0/P1; time-to-break attack paths |
| Quality | False positive rate | Validation yield; recurrence/regression rate |
| Risk Reduction | Vuln count | Reduction in reachable exposure to crown jewels |
| Governance | SLA compliance | Owner acceptance rates; cycle completion rate |
| Coverage | % assets scanned | % crown jewels + identities in CTEM scope |

### Executive Reporting Shift

Thay vì: "We closed 1,200 vulnerabilities this quarter"

Report: "Eliminated X externally reachable paths to payment systems, reduced P0 exposure in identity admin workflows by Y%, MTTR for validated exploitable findings improved from Z to W days"

### Future Gaps (post RFC-004/005, lower priority)

| Gap | Source | Priority |
|-----|--------|----------|
| Credential leak rotation workflow | CTEM vs VM | Medium |
| SaaS posture discovery (OAuth apps, admin roles) | CTEM vs VM, vs EASM | Medium |
| Third-party/vendor risk entity | CTEM vs VM | Medium |
| Lookalike domain / brand monitoring | CTEM vs VM | Low |
| Regression rate metric in snapshots | CTEM vs EASM | Low — add to risk_snapshots |
| MTTD (Mean Time to Detect) | CTEM vs EASM | Low — compute from first_seen |

---

## Tham khảo

- [ctem.org — Getting Started](https://ctem.org/docs/getting-started)
- [ctem.org — Scoping](https://ctem.org/docs/stages/ctem-scoping)
- [ctem.org — Discovery](https://ctem.org/docs/stages/ctem-discovery)
- [ctem.org — Prioritization](https://ctem.org/docs/stages/ctem-prioritization)
- [ctem.org — Validation](https://ctem.org/docs/stages/ctem-validation)
- [ctem.org — Mobilization](https://ctem.org/docs/stages/ctem-mobilization)
- [ctem.org — CTEM vs Vulnerability Management](https://ctem.org/docs/comparisons/ctem-vs-vulnerability-management)
- [ctem.org — CTEM vs Exposure Management](https://ctem.org/docs/comparisons/ctem-vs-exposure-management)
- [ctem.org — CTEM vs EASM/CAASM](https://ctem.org/docs/comparisons/ctem-vs-easm-caasm)
- [ctem.org — CTEM vs Pentesting](https://ctem.org/docs/comparisons/ctem-vs-pentesting)
