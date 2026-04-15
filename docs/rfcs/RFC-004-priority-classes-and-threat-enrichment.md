# RFC-004: Priority Classes P0-P3 + EPSS/KEV Enrichment

- **Status**: Completed
- **Created**: 2026-04-15
- **Priority**: Critical
- **Depends on**: EPSS/KEV sync (existing), Attack Path Scoring (existing)
- **Estimated effort**: ~2 weeks (6 phases)
- **CTEM Stage**: Prioritization (Stage 3)

### Implementation Progress

| Phase | Scope | Status |
|-------|-------|--------|
| 1. Schema + Domain | Migration 000142, priority.go, priority_rule.go, FindingData fields | Done |
| 2. Enrichment Pipeline | Repository persistence, EnrichFindings(), wire into ingest | Done |
| 3. Classification Engine | ClassifyPriority service, override rules, audit log | Done |
| 4. SLA Integration | Priority-based SLA days, deadline recalculation | Done (schema) |
| 5. API Layer | FindingResponse, filters, priority handler, rules CRUD | Done |
| 6. UI | Badge, list column, enrichment types | Done |
- **Reference**: https://ctem.org/docs/stages/ctem-prioritization

---

## 1. Vấn đề

ctem.org yêu cầu: "Prioritization turns discovery data into an ordered plan. The objective is not to fix everything — it is to address the exposures most likely to be exploited and most damaging to the business."

Hiện tại OpenCTEM:
- **Chỉ có severity** (critical/high/medium/low/info) — đây là thuộc tính kỹ thuật, không phải business priority
- **EPSS đã sync** nhưng chưa feed vào risk formula hoặc findings
- **KEV đã sync** nhưng chỉ escalate severity thô (`KEVEscalator` set severity = critical cho mọi KEV)
- **Attack path scoring** đã có BFS reachability nhưng chưa map vào findings
- **Không có override rules** — không thể tự động "KEV + reachable + crown jewel = P0"
- **SLA gắn với severity**, không phải priority class

Kết quả: team remediation nhận 1 danh sách dài findings sorted by severity, không biết cái nào thực sự dangerous.

---

## 2. Thiết kế: Priority Classification Model

### 2.1 Priority Classes (theo ctem.org)

| Class | Định nghĩa | Default SLA |
|-------|-------------|-------------|
| **P0** | Known exploited (KEV) **AND** reachable **OR** validated exploit path tới crown-jewel asset | 7 ngày |
| **P1** | High EPSS (≥0.1), reachable, high-impact service, limited compensating controls | 30 ngày |
| **P2** | Medium likelihood/impact, có compensating controls | 60 ngày |
| **P3** | Low likelihood/impact, hoặc unreachable | Track; fix opportunistically |

### 2.2 Classification Formula

```
PriorityScore = (Impact + Likelihood + ExposureConditions) × (1 - ControlReductionFactor)
```

Inputs:

| Component | Source | Scale |
|-----------|--------|-------|
| Impact | Asset criticality + CIA (crown jewel = max) | 0-5 |
| Likelihood | EPSS percentile + KEV status + exploit maturity | 0-5 |
| Exposure Conditions | Reachability (internet/internal/segmented) + auth prerequisites | 0-5 |
| Control Reduction | Compensating controls effectiveness (future: from control entity) | 0-0.5 |

### 2.3 Deterministic Classification Rules

```go
// P0: Immediate action required
if (isInKEV && isReachable) ||
   (attackPathValidated && asset.IsCrownJewel && isReachable) {
    return P0
}

// P1: High urgency
if epssScore >= 0.1 && isReachable &&
   asset.Criticality in ["critical","high"] && !isProtected {
    return P1
}

// P2: Scheduled remediation
if (epssScore >= 0.01 || severity in ["critical","high"]) && isProtected {
    return P2
}
if severity in ["critical","high"] && !isReachable {
    return P2
}

// P3: Track/opportunistic
return P3
```

### 2.4 Override Rules (per-tenant, configurable)

```json
{
  "name": "KEV on crown jewel = P0",
  "priority_class": "P0",
  "conditions": [
    {"field": "is_in_kev", "operator": "eq", "value": true},
    {"field": "asset_is_crown_jewel", "operator": "eq", "value": true}
  ],
  "is_active": true,
  "priority": 100
}
```

Rules evaluated highest-priority-first. ALL conditions must match (AND logic). First matching rule wins. If no rule matches, default classification engine runs.

---

## 3. Schema Changes

### Migration 000142: priority_classes_and_enrichment

#### 3.1 Finding enrichment columns

```sql
-- Threat intel enrichment (denormalized for query performance)
ALTER TABLE findings ADD COLUMN epss_score DECIMAL(6,5);
ALTER TABLE findings ADD COLUMN epss_percentile DECIMAL(5,2);
ALTER TABLE findings ADD COLUMN is_in_kev BOOLEAN DEFAULT false;
ALTER TABLE findings ADD COLUMN kev_due_date DATE;

-- Priority classification
ALTER TABLE findings ADD COLUMN priority_class VARCHAR(2);
ALTER TABLE findings ADD COLUMN priority_class_reason TEXT;
ALTER TABLE findings ADD COLUMN priority_class_override BOOLEAN DEFAULT false;
ALTER TABLE findings ADD COLUMN priority_class_overridden_by UUID;
ALTER TABLE findings ADD COLUMN priority_class_overridden_at TIMESTAMPTZ;

-- Reachability context (from attack path scoring)
ALTER TABLE findings ADD COLUMN is_reachable BOOLEAN DEFAULT false;
ALTER TABLE findings ADD COLUMN reachable_from_count INT DEFAULT 0;

-- Constraints
ALTER TABLE findings ADD CONSTRAINT chk_priority_class
  CHECK (priority_class IS NULL OR priority_class IN ('P0','P1','P2','P3'));

-- Indexes
CREATE INDEX idx_findings_priority ON findings(tenant_id, priority_class)
  WHERE priority_class IS NOT NULL;
CREATE INDEX idx_findings_kev ON findings(tenant_id)
  WHERE is_in_kev = true;
```

#### 3.2 Override rules table

```sql
CREATE TABLE priority_override_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    priority_class VARCHAR(2) NOT NULL
      CHECK (priority_class IN ('P0','P1','P2','P3')),
    conditions JSONB NOT NULL,
    is_active BOOLEAN DEFAULT true,
    evaluation_order INT DEFAULT 0,
    created_by UUID,
    updated_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_priority_rules_tenant
  ON priority_override_rules(tenant_id) WHERE is_active = true;
```

#### 3.3 Priority audit log

```sql
CREATE TABLE priority_class_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    finding_id UUID NOT NULL,
    previous_class VARCHAR(2),
    new_class VARCHAR(2) NOT NULL,
    reason TEXT NOT NULL,
    source VARCHAR(20) NOT NULL,  -- auto, rule, manual
    rule_id UUID,
    actor_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_priority_audit_finding
  ON priority_class_audit_log(finding_id, created_at DESC);
```

#### 3.4 SLA policy priority class days

```sql
ALTER TABLE sla_policies ADD COLUMN p0_days INT DEFAULT 7;
ALTER TABLE sla_policies ADD COLUMN p1_days INT DEFAULT 30;
ALTER TABLE sla_policies ADD COLUMN p2_days INT DEFAULT 60;
ALTER TABLE sla_policies ADD COLUMN p3_days INT DEFAULT 180;
```

---

## 4. Domain Model Changes

### 4.1 New: `pkg/domain/vulnerability/priority.go`

```go
type PriorityClass string

const (
    PriorityP0 PriorityClass = "P0"
    PriorityP1 PriorityClass = "P1"
    PriorityP2 PriorityClass = "P2"
    PriorityP3 PriorityClass = "P3"
)

type PriorityContext struct {
    Severity        string
    CVE             string
    EPSSScore       *float64
    IsInKEV         bool
    IsReachable     bool
    IsProtected     bool
    AssetCriticality string
    AssetIsCrownJewel bool
    AssetExposure    string
    AttackPathValidated bool
}

type PriorityClassification struct {
    Class  PriorityClass
    Reason string
    Source string // "auto", "rule", "manual"
    RuleID *shared.ID
}

func ClassifyPriority(ctx PriorityContext) PriorityClassification
```

### 4.2 New: `pkg/domain/vulnerability/priority_rule.go`

```go
type RuleCondition struct {
    Field    string `json:"field"`
    Operator string `json:"operator"` // eq, neq, gte, lte, in
    Value    any    `json:"value"`
}

type PriorityOverrideRule struct {
    id              shared.ID
    tenantID        shared.ID
    name            string
    priorityClass   PriorityClass
    conditions      []RuleCondition
    isActive        bool
    evaluationOrder int
    // ...
}

func (r *PriorityOverrideRule) Matches(ctx PriorityContext) bool
```

### 4.3 Modify: `pkg/domain/vulnerability/finding.go`

Thêm fields (private, with getters/setters):

```go
epssScore              *float64
epssPercentile         *float64
isInKEV                bool
kevDueDate             *time.Time
priorityClass          *PriorityClass
priorityClassReason    string
priorityClassOverride  bool
isReachable            bool
reachableFromCount     int
```

### 4.4 Modify: `pkg/domain/sla/entity.go`

```go
func (p *Policy) DaysForPriorityClass(pc PriorityClass) int {
    switch pc {
    case PriorityP0: return p.p0Days
    case PriorityP1: return p.p1Days
    case PriorityP2: return p.p2Days
    case PriorityP3: return p.p3Days
    default:         return p.DaysForSeverity(severity) // fallback
    }
}
```

---

## 5. Service Layer

### 5.1 New: `internal/app/priority_classification_service.go`

```go
type PriorityClassificationService struct {
    findingRepo      FindingRepository
    assetRepo        AssetRepository
    threatIntelRepo  ThreatIntelRepository
    ruleRepo         PriorityRuleRepository
    auditRepo        PriorityAuditRepository
    attackPathSvc    *AttackPathScoringService
    slaService       *SLAService
}

// ClassifyFinding computes priority for one finding
func (s *Service) ClassifyFinding(ctx, tenantID, findingID) error {
    // 1. Load finding + asset
    // 2. Enrich: lookup EPSS/KEV by CVE
    // 3. Get reachability from attack path cache
    // 4. Build PriorityContext
    // 5. Evaluate tenant override rules (ordered by evaluation_order DESC)
    // 6. If no rule matches, run default ClassifyPriority()
    // 7. Persist priority + enrichment fields on finding
    // 8. Recalculate SLA deadline using priority class
    // 9. Write audit log entry
}

// BatchClassify — post-ingest bulk classification
func (s *Service) BatchClassify(ctx, tenantID, findingIDs []string) error

// ReclassifyOpen — after EPSS/KEV sync or rule change
func (s *Service) ReclassifyOpen(ctx, tenantID) error

// ManualOverride — admin override with audit trail
func (s *Service) ManualOverride(ctx, tenantID, findingID, newClass, reason, actorID) error
```

### 5.2 Modify: `internal/app/threatintel_service.go`

```go
// EnrichFindings batch-lookups EPSS + KEV for a set of CVEs
func (s *ThreatIntelService) EnrichFindings(ctx, findings []*Finding) error {
    // Collect CVE IDs
    // Batch query epss_scores WHERE cve_id = ANY($1)
    // Batch query kev_catalog WHERE cve_id = ANY($1)
    // Update finding fields in-memory
}
```

### 5.3 Integration Points

```
Finding Created (ingest or manual)
  → EnrichFindings() — set epss_score, is_in_kev
  → ClassifyFinding() — compute priority class + SLA
  → Persist

EPSS/KEV Sync Complete
  → ReclassifyOpen() — re-evaluate all open findings

Override Rule Changed
  → ReclassifyOpen() — re-evaluate affected findings

Attack Path Recomputed
  → Update is_reachable on affected findings
  → ReclassifyOpen() for affected assets
```

---

## 6. API Endpoints

### 6.1 Finding Response (modify existing)

```json
{
  "id": "...",
  "severity": "high",
  "priority_class": "P1",
  "priority_class_reason": "EPSS 0.42 (top 5%), reachable, critical asset",
  "epss_score": 0.42,
  "epss_percentile": 95.3,
  "is_in_kev": false,
  "is_reachable": true,
  "reachable_from_count": 3,
  "sla_deadline": "2026-05-15T00:00:00Z"
}
```

### 6.2 New: Finding Filters

```
GET /api/v1/findings?priority_classes=P0,P1&is_in_kev=true&min_epss=0.1&is_reachable=true
```

### 6.3 New: Priority Override

```
PUT /api/v1/findings/{id}/priority
Body: {"priority_class": "P0", "reason": "Active exploitation observed"}
Requires: findings:write permission
```

### 6.4 New: Override Rules CRUD

```
GET    /api/v1/priority-rules
POST   /api/v1/priority-rules
PUT    /api/v1/priority-rules/{id}
DELETE /api/v1/priority-rules/{id}
Requires: findings:policies:write permission
```

---

## 7. UI Changes

### 7.1 PriorityClassBadge Component

```
P0 = Red pulse dot + "P0" label — signals immediate danger
P1 = Orange badge
P2 = Yellow badge
P3 = Gray badge
```

### 7.2 Finding List Table

- Thêm cột "Priority" (sortable, filterable P0/P1/P2/P3)
- Filter dropdown: priority class, is_in_kev, EPSS range, is_reachable
- Default sort: priority_class ASC, severity DESC

### 7.3 Finding Detail

- Header: PriorityClassBadge bên cạnh SeverityBadge
- New card "Threat Intelligence":
  - EPSS score gauge (0-100%)
  - KEV badge (if applicable) with due date
  - Reachability status (internet/internal/segmented)
  - Priority classification reason (human-readable)
- Override button (admin only) mở dialog: select class + write reason

### 7.4 Priority Rules Settings Page

- Table of rules with name, target class, conditions, active/inactive toggle
- Create/Edit dialog with condition builder (field dropdown + operator + value)
- Seed 4 default rules on first visit:
  1. KEV + Reachable + Crown Jewel → P0
  2. KEV + Reachable → P0
  3. EPSS ≥ 0.3 + Reachable + Critical Asset → P1
  4. EPSS ≥ 0.1 + Reachable + High Asset → P1

---

## 8. Implementation Phases

| Phase | Scope | Effort |
|-------|-------|--------|
| **1. Schema + Domain** | Migration 000142, priority.go, priority_rule.go, finding fields | 2-3 ngày |
| **2. Enrichment Pipeline** | EnrichFindings(), persist to DB, wire vào CreateFinding | 2 ngày |
| **3. Classification Engine** | ClassifyPriority(), PriorityClassificationService, override rule evaluation, audit log | 3 ngày |
| **4. SLA Integration** | Priority-based SLA days, recalculate deadline | 1 ngày |
| **5. API Layer** | FindingResponse, filters, priority handler, rules CRUD, routes | 2 ngày |
| **6. UI** | Badge, list column/filters, detail enrichment card, rules settings page | 3 ngày |

---

## 9. Edge Cases

| Case | Handling |
|------|----------|
| Finding without CVE (SAST, secrets, misconfig) | Skip EPSS/KEV enrichment. Classify on severity + reachability + asset criticality. Typically P2/P3 unless reachable to crown jewel |
| EPSS stale after sync | ReclassifyOpen() runs after every EPSS sync. Batch UPDATE with JOIN |
| Multiple override rules match | Rules sorted by evaluation_order DESC. First match wins |
| Manual override followed by re-classification | Manual override flag prevents auto-reclassification. Only manual can change |
| Existing findings (backfill) | Post-deploy job: enrich + classify all open findings. One-time batch |
| SLA conflict (priority SLA tighter than existing) | Take the tighter deadline. Never extend existing SLA |
| Asset changes (becomes crown jewel) | Trigger reclassification for all findings on that asset |
| Compensating controls (future) | `isProtected` currently from attack path `protected_by`. Later from control entity (RFC-005) |

---

## 10. Migration từ KEVEscalator

Hiện tại `KEVEscalator.EscalateKEVFindings()` trong `threat_intel_refresh.go` chạy cross-tenant UPDATE set severity=critical cho mọi KEV finding. Sau khi RFC-004 deploy:

1. Phase 1: Chạy song song — KEVEscalator vẫn set severity, PriorityClassification set P0
2. Phase 2: Disable KEVEscalator — priority class subsumes severity escalation
3. Phase 3: Remove KEVEscalator code

---

## Tham khảo

- [ctem.org — Prioritization Stage](https://ctem.org/docs/stages/ctem-prioritization)
- EPSS: https://www.first.org/epss
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
