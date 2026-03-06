# Access Control Rules: Scope Rules & Assignment Rules

## Overview

OpenCTEM has two independent rule engines for automated data management:

| Feature | Scope Rules | Assignment Rules |
|---------|-------------|-----------------|
| **What it manages** | Asset access/visibility | Finding triage routing |
| **Target entity** | Assets | Findings |
| **Result** | Creates AssetOwner records (access control) | Routes findings to groups for investigation |
| **Scope** | Per-group (max 20 rules/group) | Tenant-wide (unlimited) |
| **Trigger** | Asset creation/tag change + manual reconcile | Finding creation/ingestion |

These systems are **complementary and independent** - they never overlap or conflict.

---

## Scope Rules (Dynamic Asset-to-Group Scoping)

### Purpose

Automatically assign assets to groups based on asset properties, giving group members visibility into those assets.

### Use Cases

- "All assets tagged `production` should be visible to the Operations team"
- "Assets in the `external-facing` asset group should be assigned to the Security team"

### Rule Types

| Type | Description | Match Logic |
|------|-------------|-------------|
| `tag_match` | Match assets by their tags | `any` (OR) or `all` (AND) |
| `asset_group_match` | Match assets by asset group membership | OR logic |

### Ownership Types

| Type | Description |
|------|-------------|
| `primary` | Full ownership - responsible for remediation |
| `secondary` | Backup ownership |
| `stakeholder` | Interested party - gets visibility |
| `informed` | Read-only visibility |

### API Endpoints

All under `/api/v1/groups/{groupId}/scope-rules`:

```
GET    /                     List rules for group
POST   /                     Create rule
GET    /{ruleId}             Get single rule
PUT    /{ruleId}             Update rule
DELETE /{ruleId}             Delete rule
POST   /{ruleId}/preview     Preview matching assets (dry run)
POST   /reconcile            Re-evaluate all rules for group
```

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
  "priority": 10,
  "is_active": true
}
```

**Preview response:**

```json
POST /api/v1/groups/{groupId}/scope-rules/{ruleId}/preview
{
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

### How It Works

1. **Rule created** - Admin defines matching criteria (tags or asset groups)
2. **Asset created/updated** - `ScopeRuleService.EvaluateAsset()` checks all active rules
3. **Match found** - Creates `AssetOwner` record linking asset to group
4. **Access updated** - Refreshes `user_accessible_assets` materialized view
5. **Manual reconcile** - Re-evaluates all rules for a group (useful after bulk tag changes)

### Performance

- **Batch operations**: Uses bulk INSERT with ON CONFLICT DO NOTHING
- **Smart reconciliation**: Only re-reconciles when matching criteria change (not name/description)
- **Single refresh**: One materialized view refresh per batch, not per asset

### Limits

| Constraint | Value |
|-----------|-------|
| Rules per group | 20 |
| Tags per rule | 10 |
| Asset groups per rule | 5 |

---

## Assignment Rules (Finding Triage Routing)

### Purpose

Automatically route findings to groups for triage based on finding properties (severity, type, source, tags).

### Use Cases

- "All Critical SQL Injection findings -> assign to Security Engineering team"
- "Findings from Nuclei scanner with High severity -> assign to AppSec team"
- "Container vulnerabilities -> assign to DevOps team"

### Conditions

Rules match findings based on these condition types:

| Condition | Description | Operators |
|-----------|-------------|-----------|
| `severity` | Finding severity (critical, high, medium, low) | eq, neq, in |
| `tool_name` | Scanner/tool name | eq, neq, in, contains |
| `finding_type` | Type of finding (vulnerability, misconfiguration) | eq, neq, in |
| `source` | Finding source (sast, dast, etc.) | eq, neq, in |
| `tag` | Finding tags | contains |

**Operators:**
- `eq` - Equals (case-insensitive)
- `neq` - Not equals
- `in` - Value in comma-separated list
- `contains` - String contains (case-insensitive)

### Options

| Option | Description |
|--------|-------------|
| `notify_group` | Send notification to group when finding assigned |
| `set_finding_priority` | Override finding priority (critical, high, medium, low) |

### API Endpoints

All under `/api/v1/assignment-rules`:

```
GET    /             List rules (paginated, filterable)
POST   /             Create rule
GET    /{id}         Get single rule
PUT    /{id}         Update rule (partial)
DELETE /{id}         Delete rule
POST   /{id}/test    Test rule (dry run)
```

### Request/Response Examples

**Create an assignment rule:**

```json
POST /api/v1/assignment-rules
{
  "name": "Critical Web Vulnerabilities",
  "description": "Route critical web findings to security team",
  "priority": 100,
  "conditions": {
    "asset_types": ["website", "api"],
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
      "conditions": { ... },
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

### How the Assignment Engine Works

1. **Finding ingested** - A new finding is created (via scan, API, or import)
2. **Engine triggered** - `AssignmentEngine.EvaluateRules()` loads all active rules for tenant
3. **Rules evaluated** - Each rule's conditions checked against finding (AND logic within a rule)
4. **All matches fire** - No short-circuit; all matching rules contribute their target group
5. **Deduplication** - If multiple rules target the same group, only one assignment created
6. **Result** - List of group IDs to assign the finding to

### Evaluation Logic

```
Rule conditions: [severity=critical, tool_name=nuclei, tag=production]
Finding: severity=critical, tool=nuclei, tags=[production, web]

Condition 1 (severity=critical): MATCH
Condition 2 (tool_name=nuclei): MATCH
Condition 3 (tag=production): MATCH (tags contain "production")

Result: ALL conditions match -> Rule fires -> Finding assigned to target group
```

Empty conditions list = rule always matches (catch-all).

---

## Security: Tenant Isolation

**Both Scope Rules and Assignment Rules enforce tenant isolation at the database level.**

Every query includes `WHERE tenant_id = ?` to prevent cross-tenant data access:

- `GetAssignmentRule(ctx, tenantID, ruleID)` - Cannot read other tenant's rules
- `UpdateAssignmentRule(ctx, tenantID, rule)` - Cannot modify other tenant's rules
- `DeleteAssignmentRule(ctx, tenantID, ruleID)` - Cannot delete other tenant's rules
- Same pattern for all Scope Rule operations

---

## Frontend Components

### Scope Rules (within Group Detail Sheet)

```
ui/src/features/access-control/components/group-detail-sheet/
  scope-rules-tab.tsx        # List, search, preview, delete
  scope-rule-dialog.tsx      # Create/edit with tag autocomplete
```

### Assignment Rules

```
ui/src/app/(dashboard)/settings/access-control/assignment-rules/
  page.tsx                   # Full page listing
ui/src/features/access-control/components/
  assignment-rule-detail-sheet.tsx  # View/edit detail
ui/src/features/access-control/api/
  use-assignment-rules.ts    # SWR hooks
ui/src/features/access-control/types/
  assignment-rule.types.ts   # Type definitions
```

---

## Key Files

### Backend

| File | Purpose |
|------|---------|
| `pkg/domain/accesscontrol/entity.go` | Domain entities (AssignmentRule, ScopeRule) |
| `pkg/domain/accesscontrol/repository.go` | Repository interface |
| `internal/app/assignment_rule_service.go` | Assignment rule business logic |
| `internal/app/assignment_engine.go` | Finding evaluation engine |
| `internal/app/scope_rule_service.go` | Scope rule business logic |
| `internal/infra/postgres/access_control_repository.go` | PostgreSQL implementation |
| `internal/infra/http/handler/assignment_rule_handler.go` | HTTP handler |
| `internal/infra/http/handler/scope_rule_handler.go` | HTTP handler |
| `tests/unit/assignment_rule_service_test.go` | Unit tests (43 tests) |
| `tests/unit/data_scope_test.go` | Scope rule unit tests |

### Frontend

| File | Purpose |
|------|---------|
| `src/features/access-control/api/use-scope-rules.ts` | Scope rule SWR hooks |
| `src/features/access-control/api/use-assignment-rules.ts` | Assignment rule SWR hooks |
| `src/features/access-control/types/scope-rule.types.ts` | Scope rule types |
| `src/features/access-control/types/assignment-rule.types.ts` | Assignment rule types |
