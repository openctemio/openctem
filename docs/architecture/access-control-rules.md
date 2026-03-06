# Access Control Rules: Scope Rules & Assignment Rules

## Overview

OpenCTEM implements two independent rule engines for automated data management within the 2-Layer Access Control system:

| Feature | Scope Rules | Assignment Rules |
|---------|-------------|-----------------|
| **What it manages** | Asset access/visibility | Finding triage routing |
| **Target entity** | Assets | Findings |
| **Result** | Creates `asset_owners` records (Layer 2: Data Scope) | Creates `finding_group_assignments` records |
| **Scope** | Per-group (max 20 rules/group) | Tenant-wide |
| **Trigger** | Asset creation/tag change + manual reconcile | Finding creation/ingestion |
| **Evaluation** | Tag matching (ANY/ALL) or asset group membership | AND logic across condition fields |

These systems are **complementary and independent** - they never overlap or conflict.

```
                        ACCESS CONTROL RULES
  ┌─────────────────────────────────────────────────────────────┐
  │                                                             │
  │  SCOPE RULES                    ASSIGNMENT RULES            │
  │  (Asset -> Group)               (Finding -> Group)          │
  │                                                             │
  │  ┌──────────┐  tag_match        ┌──────────┐  conditions   │
  │  │  Asset   │ ────────────> ┌──>│ Finding  │ ──────────>   │
  │  │ (tags,   │  asset_group  │   │(severity,│  match?       │
  │  │  groups) │ ────────────> │   │ source,  │    │          │
  │  └──────────┘    match?     │   │ type,    │    v          │
  │       │            │        │   │ tags)    │ ┌──────┐      │
  │       v            v        │   └──────────┘ │Group │      │
  │  ┌──────────┐  ┌──────┐    │                 │(triage)     │
  │  │asset_    │  │Group │    │                 └──────┘      │
  │  │owners    │  │(scope)    │                    │          │
  │  └──────────┘  └──────┘    │   finding_group_  │          │
  │       │                    │   assignments     v          │
  │       v                    │   ┌──────────────────┐       │
  │  user_accessible_assets    │   │ finding_id       │       │
  │  (materialized view)       │   │ group_id         │       │
  │                            │   │ rule_id          │       │
  │                            │   └──────────────────┘       │
  └────────────────────────────┴──────────────────────────────┘
```

---

## Scope Rules (Dynamic Asset-to-Group Scoping)

### Purpose

Automatically assign assets to groups based on asset properties, giving group members visibility into those assets. This is Layer 2 (Data Scope) of the access control system.

### Use Cases

- "All assets tagged `production` should be visible to the Operations team"
- "Assets in the `external-facing` asset group should be assigned to the Security team"
- "Auto-scope `pci-zone` assets to Compliance team with `stakeholder` ownership"

### Rule Types

| Type | Description | Match Logic |
|------|-------------|-------------|
| `tag_match` | Match assets by their tags | `any` (OR) or `all` (AND) |
| `asset_group_match` | Match assets by asset group membership | OR logic (any group match) |

### Ownership Types

| Type | Full Access | View Access | Description |
|------|------------|-------------|-------------|
| `primary` | Yes | Yes | Full ownership - responsible for remediation |
| `secondary` | Yes | Yes | Backup ownership |
| `stakeholder` | No | Yes | Interested party - gets visibility |
| `informed` | No | Yes | Read-only visibility |

### Data Flow

```
1. Rule Created/Updated
   └─> Initial reconciliation (batch assign matching assets)

2. New Asset Created / Tags Changed
   └─> ScopeRuleService.EvaluateAsset()
       └─> Check ALL active rules for tenant
           └─> For each matching rule:
               └─> Create AssetOwner record (ON CONFLICT DO NOTHING)
       └─> Incremental access refresh per group (not full materialized view)

3. Manual Reconcile (POST /reconcile)
   └─> ReconcileGroup()
       ├─> Evaluate all active rules for group
       │   └─> Batch insert new matches
       ├─> Find stale auto-assignments (no longer match any rule)
       │   └─> Remove stale assignments
       └─> Single materialized view refresh
```

### API Endpoints

All under `/api/v1/groups/{groupId}/scope-rules`:

| Method | Path | Description | Permission |
|--------|------|-------------|------------|
| `GET` | `/` | List rules for group | `groups:read` |
| `POST` | `/` | Create rule | `groups:write` |
| `GET` | `/{ruleId}` | Get single rule | `groups:read` |
| `PUT` | `/{ruleId}` | Update rule | `groups:write` |
| `DELETE` | `/{ruleId}` | Delete rule (+ cleanup auto-assignments) | `groups:write` |
| `POST` | `/{ruleId}/preview` | Preview matching assets (dry run) | `groups:read` |
| `POST` | `/reconcile` | Re-evaluate all rules for group | `groups:write` |

### Request/Response Examples

**Create a tag-match scope rule:**

```json
POST /api/v1/groups/{groupId}/scope-rules
{
  "name": "Production Assets",
  "description": "Auto-assign production-tagged assets",
  "rule_type": "tag_match",
  "match_tags": ["production", "critical"],
  "match_logic": "any",
  "ownership_type": "primary",
  "priority": 10
}
```

**Create an asset-group-match scope rule:**

```json
POST /api/v1/groups/{groupId}/scope-rules
{
  "name": "External Assets",
  "description": "Assets in external-facing groups",
  "rule_type": "asset_group_match",
  "match_asset_group_ids": ["uuid-1", "uuid-2"],
  "ownership_type": "stakeholder",
  "priority": 5
}
```

**Preview response:**

```json
POST /api/v1/groups/{groupId}/scope-rules/{ruleId}/preview
{
  "rule_id": "uuid",
  "rule_name": "Production Assets",
  "matching_assets": 45,
  "already_assigned": 30,
  "would_add": 15
}
```

**Reconcile response:**

```json
POST /api/v1/groups/{groupId}/scope-rules/reconcile
{
  "rules_evaluated": 3,
  "assets_added": 12,
  "assets_removed": 2
}
```

### Reconciliation Behavior

| Scenario | Behavior |
|----------|----------|
| Rule created | Auto-reconciles matching assets immediately |
| Rule criteria updated (tags, groups, logic) | Auto-reconciles if rule is active |
| Rule name/description updated | No reconciliation |
| Rule activated/deactivated | Reconciles on activation |
| Rule deleted | Removes all auto-assigned assets from that rule |
| Manual reconcile | Evaluates all active rules + removes stale assignments |

**Stale assignment cleanup**: When assets no longer match any active rule but were auto-assigned, `ReconcileGroup` detects and removes them by comparing current auto-assigned assets against the full set of matched assets across all rules.

### Limits

| Constraint | Value |
|-----------|-------|
| Rules per group | 20 (`MaxScopeRulesPerGroup`) |
| Tags per rule | 10 (`MaxTagsPerRule`) |
| Asset groups per rule | 5 (`MaxAssetGroupsPerRule`) |
| Bulk insert batch size | 10,000 |

---

## Assignment Rules (Finding Triage Routing)

### Purpose

Automatically route findings to groups for triage based on finding properties. When a new finding is ingested, the Assignment Engine evaluates all active rules and creates `finding_group_assignments` records for matching rules.

### Use Cases

- "All Critical SQL Injection findings -> assign to Security Engineering team"
- "Findings from Nuclei scanner with High severity -> assign to AppSec team"
- "Container vulnerabilities -> assign to DevOps team + set priority to high"

### Conditions (AND Logic)

All non-empty condition fields must match for a rule to fire. Empty conditions = catch-all (always matches).

| Field | Type | Description | Matching |
|-------|------|-------------|----------|
| `finding_severity` | `string[]` | Severity levels | Case-insensitive, value in list |
| `finding_source` | `string[]` | Finding source (sast, dast, etc.) | Case-insensitive, value in list |
| `finding_type` | `string[]` | Type (vulnerability, misconfiguration) | Case-insensitive, value in list |
| `asset_tags` | `string[]` | Tags on the finding | Any tag match (OR within field) |
| `file_path_pattern` | `string` | Glob pattern for file path | `path.Match()` (Go stdlib) |
| `asset_type` | `string[]` | Asset type filter | Not evaluated (findings lack asset type) |

**Example**: A rule with `finding_severity: ["critical", "high"]` AND `finding_source: ["dast"]` will only match findings that are both critical/high severity AND from a DAST source.

### Options

| Option | Type | Description |
|--------|------|-------------|
| `notify_group` | `bool` | Send notification to group when finding assigned |
| `set_finding_priority` | `string` | Override finding priority rank |

**Priority mapping** (`set_finding_priority`):

| Value | Rank Score |
|-------|-----------|
| `critical` | 90 |
| `high` | 70 |
| `medium` | 50 |
| `low` | 30 |
| `info` / `informational` | 10 |

Only the first matching rule's priority is applied (highest priority rule wins).

### Data Flow

```
1. Finding Created (VulnerabilityService.CreateFinding)
   └─> evaluateAssignmentRules() [non-blocking, errors logged]
       ├─> AssignmentEngine.EvaluateRules(tenantID, finding)
       │   ├─> Load all active rules (sorted by priority DESC)
       │   ├─> For each rule: MatchesConditions(conditions, finding)
       │   │   └─> AND logic across all non-empty fields
       │   └─> Return []AssignmentResult (deduplicated by group)
       │
       ├─> Create FindingGroupAssignment records
       │   └─> BulkCreateFindingGroupAssignments (ON CONFLICT DO NOTHING)
       │
       └─> Apply options from first matching rule
           └─> SetFindingPriority: update finding rank via repo
```

**Key design decisions:**
- **Non-blocking**: Assignment rule errors never fail finding creation (logged as warnings)
- **All rules fire**: No short-circuiting; all matching rules contribute their target group
- **Deduplication**: If multiple rules target the same group, only one assignment created
- **Idempotent**: `UNIQUE(finding_id, group_id)` + `ON CONFLICT DO NOTHING`

### API Endpoints

All under `/api/v1/assignment-rules`:

| Method | Path | Description | Permission |
|--------|------|-------------|------------|
| `GET` | `/` | List rules (paginated, filterable) | `assignment_rules:read` |
| `POST` | `/` | Create rule | `assignment_rules:write` |
| `GET` | `/{id}` | Get single rule | `assignment_rules:read` |
| `PUT` | `/{id}` | Update rule (partial) | `assignment_rules:write` |
| `DELETE` | `/{id}` | Delete rule | `assignment_rules:delete` |
| `POST` | `/{id}/test` | Test rule against recent findings (dry run) | `assignment_rules:read` |

### Request/Response Examples

**Create an assignment rule:**

```json
POST /api/v1/assignment-rules
{
  "name": "Critical Web Vulnerabilities",
  "description": "Route critical web findings to security team",
  "priority": 100,
  "conditions": {
    "finding_severity": ["critical", "high"],
    "finding_type": ["vulnerability"],
    "finding_source": ["dast", "sast"],
    "asset_tags": ["production"]
  },
  "target_group_id": "uuid-of-security-team",
  "options": {
    "notify_group": true,
    "set_finding_priority": "critical"
  }
}
```

**List with filters:**

```
GET /api/v1/assignment-rules?active=true&search=web&order_by=priority&order=desc&limit=20&offset=0
```

**Response:**

```json
{
  "rules": [
    {
      "id": "uuid",
      "name": "Critical Web Vulnerabilities",
      "priority": 100,
      "is_active": true,
      "conditions": {
        "finding_severity": ["critical", "high"],
        "finding_type": ["vulnerability"]
      },
      "target_group_id": "uuid",
      "options": { "notify_group": true },
      "created_at": "2026-03-01T00:00:00Z",
      "updated_at": "2026-03-01T00:00:00Z"
    }
  ],
  "total_count": 15,
  "limit": 20,
  "offset": 0
}
```

**Test rule response:**

```json
POST /api/v1/assignment-rules/{id}/test
{
  "rule_id": "uuid",
  "rule_name": "Critical Web Vulnerabilities",
  "matching_findings": 23,
  "target_group_id": "uuid",
  "sample_findings": [
    {
      "id": "finding-uuid",
      "severity": "critical",
      "source": "dast",
      "tool_name": "nuclei",
      "message": "SQL Injection in login endpoint..."
    }
  ]
}
```

TestRule fetches up to 500 recent findings and evaluates the rule conditions against them in-memory using `AssignmentEngine.MatchesConditions()`.

---

## Database Schema

### Scope Rules Table (`group_asset_scope_rules`)

```sql
CREATE TABLE group_asset_scope_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    rule_type VARCHAR(50) NOT NULL,        -- 'tag_match' | 'asset_group_match'
    match_tags TEXT[],                      -- For tag_match rules
    match_logic VARCHAR(10) DEFAULT 'any', -- 'any' | 'all'
    match_asset_group_ids UUID[],          -- For asset_group_match rules
    ownership_type VARCHAR(50) NOT NULL DEFAULT 'secondary',
    priority INTEGER NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID
);
```

### Assignment Rules Table (`assignment_rules`)

```sql
CREATE TABLE assignment_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    priority INTEGER NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    conditions JSONB NOT NULL DEFAULT '{}',
    target_group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    options JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID
);
```

### Finding Group Assignments Table (`finding_group_assignments`)

```sql
CREATE TABLE finding_group_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    rule_id UUID REFERENCES assignment_rules(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(finding_id, group_id)
);
```

### Indexes (Migration 000076)

```sql
-- Scope rules: optimize ListActiveScopeRulesByGroup
CREATE INDEX idx_scope_rules_group_tenant_active_priority
    ON group_asset_scope_rules(group_id, tenant_id, is_active, priority DESC)
    WHERE is_active = TRUE;

-- Scope rules: optimize CountScopeRules and ListScopeRules
CREATE INDEX idx_scope_rules_group_tenant
    ON group_asset_scope_rules(group_id, tenant_id);

-- Assignment rules: optimize ListActiveRulesByPriority
CREATE INDEX idx_assignment_rules_tenant_active_priority
    ON assignment_rules(tenant_id, is_active, priority DESC)
    WHERE is_active = TRUE;

-- Finding group assignments
CREATE INDEX idx_fga_tenant_finding ON finding_group_assignments(tenant_id, finding_id);
CREATE INDEX idx_fga_tenant_group ON finding_group_assignments(tenant_id, group_id);
CREATE INDEX idx_fga_rule ON finding_group_assignments(rule_id);
CREATE INDEX idx_fga_tenant_rule ON finding_group_assignments(tenant_id, rule_id) WHERE rule_id IS NOT NULL;
```

---

## Security: Tenant Isolation

**Both Scope Rules and Assignment Rules enforce tenant isolation at the database level.**

Every query includes `WHERE tenant_id = ?` to prevent cross-tenant data access:

| Operation | Tenant Guard |
|-----------|-------------|
| `GetAssignmentRule` | `WHERE id = $1 AND tenant_id = $2` |
| `UpdateAssignmentRule` | `WHERE id = $N AND tenant_id = $N` |
| `DeleteAssignmentRule` | `WHERE id = $1 AND tenant_id = $2` |
| `ListAssignmentRules` | `WHERE tenant_id = $1` |
| `ListActiveRulesByPriority` | `WHERE tenant_id = $1 AND is_active = TRUE` |
| `GetScopeRule` | `WHERE id = $1 AND tenant_id = $2` |
| `ListScopeRules` | `WHERE group_id = $1 AND tenant_id = $2` |
| `ListActiveScopeRulesByGroup` | `WHERE group_id = $1 AND tenant_id = $2` |
| `FindAssetsByTagMatch` | `WHERE tenant_id = $1` |
| `FindAssetsByAssetGroupMatch` | `JOIN assets a ON ... AND a.tenant_id = $1` |
| `DeleteAutoAssignedByRule` | `WHERE scope_rule_id IN (SELECT id FROM ... WHERE tenant_id = $2)` |
| `ListAutoAssignedAssets` | `JOIN group_asset_scope_rules gasr ON ... AND gasr.tenant_id = $2` |
| `ListFindingGroupAssignments` | `WHERE tenant_id = $1 AND finding_id = $2` |
| `CountFindingsByGroupFromRules` | `WHERE tenant_id = $1 AND group_id = $2` |

**Additional validations:**
- Target group ownership verified against tenant on create/update (both scope and assignment rules)
- Target group must be active
- Handler extracts `tenantID` from JWT via `middleware.MustGetTenantID(ctx)`

---

## Performance

### Scope Rules

| Optimization | Description |
|-------------|-------------|
| Batch INSERT | `BulkCreateAssetOwnersWithSource` with `ON CONFLICT DO NOTHING` |
| Single refresh | One `RefreshUserAccessibleAssets()` call per reconciliation batch |
| Smart reconciliation | Only re-reconciles when matching criteria change (not name/description) |
| Partial index | `WHERE is_active = TRUE` on priority index |
| Bulk size limit | Max 10,000 items per batch to prevent DoS |

### Assignment Rules

| Optimization | Description |
|-------------|-------------|
| In-memory matching | Rules loaded once, evaluated against finding in-memory |
| Idempotent | `UNIQUE(finding_id, group_id)` + `ON CONFLICT DO NOTHING` |
| Non-blocking | Assignment errors never fail finding creation |
| Partial index | `WHERE is_active = TRUE` on tenant+priority index |
| Deduplication | `seen` map prevents duplicate group assignments |

---

## Key Files

### Backend

| File | Purpose |
|------|---------|
| `pkg/domain/accesscontrol/entity.go` | Domain entities: `AssetOwner`, `AssignmentRule`, `FindingGroupAssignment` |
| `pkg/domain/accesscontrol/scope_rule.go` | `ScopeRule` entity with match criteria |
| `pkg/domain/accesscontrol/value_objects.go` | `OwnershipType`, `AssignmentConditions`, `AssignmentOptions` |
| `pkg/domain/accesscontrol/repository.go` | Repository interface (84 lines, ~40 methods) |
| `internal/app/assignment_rule_service.go` | Assignment rule CRUD + TestRule |
| `internal/app/assignment_engine.go` | Finding evaluation engine (`EvaluateRules`, `MatchesConditions`) |
| `internal/app/scope_rule_service.go` | Scope rule CRUD + reconciliation + asset evaluation |
| `internal/app/vulnerability_service.go` | `evaluateAssignmentRules()` integration point |
| `internal/infra/postgres/access_control_repository.go` | PostgreSQL implementation |
| `internal/infra/http/handler/assignment_rule_handler.go` | Assignment rule HTTP handler |
| `internal/infra/http/handler/scope_rule_handler.go` | Scope rule HTTP handler |
| `internal/infra/http/routes/access_control.go` | Route registration |
| `cmd/server/services.go` | DI wiring (`AssignmentEngine` instantiation) |

### Migrations

| File | Purpose |
|------|---------|
| `migrations/000044_*.up.sql` | Assignment rules table |
| `migrations/000072_*.up.sql` | Scope rules table |
| `migrations/000073_*.up.sql` | Scope rule enhancements |
| `migrations/000075_finding_group_assignments.up.sql` | Finding group assignments table |
| `migrations/000076_access_control_indexes.up.sql` | Composite indexes |

### Frontend

| File | Purpose |
|------|---------|
| `ui/src/features/access-control/api/use-scope-rules.ts` | Scope rule SWR hooks |
| `ui/src/features/access-control/api/use-assignment-rules.ts` | Assignment rule SWR hooks |
| `ui/src/features/access-control/types/scope-rule.types.ts` | Scope rule TypeScript types |
| `ui/src/features/access-control/types/assignment-rule.types.ts` | Assignment rule TypeScript types |
| `ui/src/features/access-control/components/group-detail-sheet/scope-rules-tab.tsx` | Scope rules UI (within group detail) |
| `ui/src/features/access-control/components/assignment-rule-detail-sheet.tsx` | Assignment rule detail view |
| `ui/src/app/(dashboard)/settings/access-control/assignment-rules/page.tsx` | Assignment rules listing page |

### Tests

| File | Purpose |
|------|---------|
| `tests/unit/assignment_rule_service_test.go` | Assignment rule service tests |
| `tests/unit/data_scope_test.go` | Scope rule mock repository + tests |
