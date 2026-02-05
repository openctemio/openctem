# Suppression Rules API

This document describes the API endpoints for managing platform-controlled suppression rules.

## Overview

The Suppression API provides platform-controlled false positive management:

- **Platform-controlled**: Rules are managed centrally, not via in-code ignore files (`.semgrepignore`, `.gitleaksignore`)
- **Approval workflow**: New rules require approval before becoming active
- **Audit trail**: All actions are logged for compliance
- **Time-limited**: Rules can have expiration dates
- **Flexible matching**: Support for tool name, rule ID patterns, and file path globs

## Why Platform-Controlled?

Unlike in-code ignore files, platform-controlled suppression rules:

1. **Cannot be modified by developers** - Security team maintains control
2. **Have audit trail** - Track who created, approved, and deleted rules
3. **Require approval** - Prevent accidental or unauthorized suppressions
4. **Can be time-limited** - Temporary suppressions auto-expire
5. **Are centrally managed** - Single source of truth across all scans

---

## Endpoints

### Admin Routes (JWT Authentication)

| Method | Endpoint | Description | Permission |
|--------|----------|-------------|------------|
| POST | `/api/v1/suppressions` | Create suppression rule | `findings:suppressions:write` |
| GET | `/api/v1/suppressions` | List suppression rules | `findings:suppressions:read` |
| GET | `/api/v1/suppressions/{id}` | Get suppression rule | `findings:suppressions:read` |
| POST | `/api/v1/suppressions/{id}/approve` | Approve pending rule | `findings:suppressions:approve` |
| POST | `/api/v1/suppressions/{id}/reject` | Reject pending rule | `findings:suppressions:approve` |
| DELETE | `/api/v1/suppressions/{id}` | Delete suppression rule | `findings:suppressions:delete` |
| GET | `/api/v1/suppressions/active` | List active rules (for agents) | `findings:suppressions:read` |

---

## Suppression Rule Lifecycle

```
┌──────────┐     approve      ┌──────────┐
│ PENDING  │ ──────────────► │ APPROVED │ ──────► (active until expires)
└──────────┘                  └──────────┘
     │                              │
     │ reject                       │ expires
     ▼                              ▼
┌──────────┐                  ┌──────────┐
│ REJECTED │                  │ EXPIRED  │
└──────────┘                  └──────────┘
```

**States:**
- `pending` - Awaiting approval
- `approved` - Active, suppressing findings
- `rejected` - Denied, not active
- `expired` - Was approved but past expiration date

---

## Create Suppression Rule

Creates a new suppression rule in `pending` status.

### Request

```http
POST /api/v1/suppressions
Content-Type: application/json
Authorization: Bearer <access_token>
```

### Request Body

```json
{
  "name": "Ignore test files for SQL injection",
  "description": "Test files contain intentional SQL injection examples",
  "suppression_type": "false_positive",
  "rule_id": "semgrep.sql-injection*",
  "tool_name": "semgrep",
  "path_pattern": "tests/**/*.py",
  "asset_id": "550e8400-e29b-41d4-a716-446655440000",
  "expires_at": "2025-06-01T00:00:00Z"
}
```

### Parameters

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable name for the rule |
| `description` | string | No | Detailed explanation |
| `suppression_type` | string | Yes | Type: `false_positive`, `accepted_risk`, `wont_fix` |
| `rule_id` | string | No* | Tool rule ID pattern (supports `*` wildcard suffix) |
| `tool_name` | string | No | Tool name filter (e.g., `semgrep`, `gitleaks`) |
| `path_pattern` | string | No* | File path pattern (glob with `**` support) |
| `asset_id` | string | No | Limit to specific asset UUID |
| `expires_at` | string | No | ISO8601 expiration date |

> **Note:** At least one of `rule_id`, `path_pattern`, or `asset_id` is required.

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Ignore test files for SQL injection",
  "description": "Test files contain intentional SQL injection examples",
  "suppression_type": "false_positive",
  "rule_id": "semgrep.sql-injection*",
  "tool_name": "semgrep",
  "path_pattern": "tests/**/*.py",
  "asset_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "requested_by": "550e8400-e29b-41d4-a716-446655440002",
  "requested_at": "2025-01-28T10:00:00Z",
  "expires_at": "2025-06-01T00:00:00Z",
  "created_at": "2025-01-28T10:00:00Z",
  "updated_at": "2025-01-28T10:00:00Z"
}
```

---

## List Suppression Rules

### Request

```http
GET /api/v1/suppressions?status=pending&tool_name=semgrep
Authorization: Bearer <access_token>
```

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status: `pending`, `approved`, `rejected`, `expired` |
| `tool_name` | string | Filter by tool name |

### Response

```json
{
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "Ignore test files for SQL injection",
      "suppression_type": "false_positive",
      "rule_id": "semgrep.sql-injection*",
      "tool_name": "semgrep",
      "path_pattern": "tests/**/*.py",
      "status": "pending",
      "requested_by": "550e8400-e29b-41d4-a716-446655440002",
      "requested_at": "2025-01-28T10:00:00Z",
      "created_at": "2025-01-28T10:00:00Z",
      "updated_at": "2025-01-28T10:00:00Z"
    }
  ],
  "total": 1
}
```

---

## Get Suppression Rule

### Request

```http
GET /api/v1/suppressions/{id}
Authorization: Bearer <access_token>
```

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Ignore test files for SQL injection",
  "description": "Test files contain intentional SQL injection examples",
  "suppression_type": "false_positive",
  "rule_id": "semgrep.sql-injection*",
  "tool_name": "semgrep",
  "path_pattern": "tests/**/*.py",
  "status": "approved",
  "requested_by": "550e8400-e29b-41d4-a716-446655440002",
  "requested_at": "2025-01-28T10:00:00Z",
  "approved_by": "550e8400-e29b-41d4-a716-446655440003",
  "approved_at": "2025-01-28T11:00:00Z",
  "expires_at": "2025-06-01T00:00:00Z",
  "created_at": "2025-01-28T10:00:00Z",
  "updated_at": "2025-01-28T11:00:00Z"
}
```

---

## Approve Suppression Rule

Approves a pending suppression rule, making it active.

### Request

```http
POST /api/v1/suppressions/{id}/approve
Authorization: Bearer <access_token>
```

### Response

Returns the updated rule with `status: "approved"`, `approved_by`, and `approved_at` fields populated.

---

## Reject Suppression Rule

Rejects a pending suppression rule.

### Request

```http
POST /api/v1/suppressions/{id}/reject
Content-Type: application/json
Authorization: Bearer <access_token>
```

### Request Body

```json
{
  "reason": "This pattern is too broad and would suppress valid findings"
}
```

### Response

Returns the updated rule with `status: "rejected"`, `rejected_by`, `rejected_at`, and `rejection_reason` fields populated.

---

## Delete Suppression Rule

### Request

```http
DELETE /api/v1/suppressions/{id}
Authorization: Bearer <access_token>
```

### Response

```http
HTTP/1.1 204 No Content
```

---

## List Active Rules (Agent Endpoint)

Returns a simplified list of active suppression rules for agents to use during scans.

### Request

```http
GET /api/v1/suppressions/active
Authorization: Bearer <access_token>
```

### Response

```json
{
  "rules": [
    {
      "rule_id": "semgrep.sql-injection*",
      "tool_name": "semgrep",
      "path_pattern": "tests/**/*.py",
      "expires_at": "2025-06-01T00:00:00Z"
    },
    {
      "rule_id": "gitleaks.generic-api-key",
      "tool_name": "gitleaks",
      "path_pattern": "**/*.example",
      "asset_id": "550e8400-e29b-41d4-a716-446655440000"
    }
  ],
  "count": 2
}
```

---

## Matching Criteria

### Rule ID Patterns

| Pattern | Matches |
|---------|---------|
| `semgrep.sql-injection` | Exact match only |
| `semgrep.sql-injection*` | Any rule starting with `semgrep.sql-injection` |
| `semgrep.*` | All semgrep rules |

### Path Patterns (Glob)

| Pattern | Matches |
|---------|---------|
| `tests/*.py` | Python files directly in `tests/` |
| `tests/**/*.py` | Python files anywhere under `tests/` |
| `**/test_*.py` | Test files anywhere |
| `src/legacy/**` | Everything under `src/legacy/` |

### Matching Logic

A finding is suppressed if ALL specified criteria match:

```
suppressed = (
    (rule.tool_name is empty OR rule.tool_name == finding.tool_name) AND
    (rule.rule_id is empty OR finding.rule_id matches pattern) AND
    (rule.path_pattern is empty OR finding.file_path matches pattern) AND
    (rule.asset_id is empty OR rule.asset_id == finding.asset_id)
)
```

---

## Suppression Types

| Type | Description | Use Case |
|------|-------------|----------|
| `false_positive` | Finding is incorrect | Test files, generated code, example configs |
| `accepted_risk` | Valid finding, risk accepted | Legacy code, low-priority fixes |
| `wont_fix` | Won't be fixed | Third-party code, deprecated features |

---

## Agent Integration

### How Agents Use Suppressions

1. Agent starts scan
2. Agent fetches active suppressions from `/api/v1/suppressions/active`
3. During security gate check, agent filters out suppressed findings
4. Only non-suppressed findings above threshold cause failure

### SDK Client Example

```go
// Fetch suppressions
suppressions, err := client.GetSuppressions(ctx)
if err != nil {
    log.Warn("Could not fetch suppressions: %v", err)
}

// Security gate with suppression support
exitCode := gate.CheckAndPrintWithSuppressions(
    reports,
    threshold,
    verbose,
    suppressions,
)
```

### CI/CD Integration

The agent automatically fetches and applies suppressions when:
- `PUSH=true` (connected to platform)
- API key is configured
- Suppressions endpoint is accessible

If suppressions cannot be fetched, the scan continues without them (fail-open for availability).

---

## Permissions

| Permission | Description |
|------------|-------------|
| `findings:suppressions:read` | View suppression rules |
| `findings:suppressions:write` | Create and update rules |
| `findings:suppressions:delete` | Delete rules |
| `findings:suppressions:approve` | Approve or reject pending rules |

### Role Recommendations

| Role | Permissions |
|------|-------------|
| Developer | `findings:suppressions:read`, `findings:suppressions:write` |
| Security Engineer | All suppression permissions |
| Security Manager | All suppression permissions |

---

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `BAD_REQUEST` | 400 | Invalid request body or parameters |
| `NOT_FOUND` | 404 | Suppression rule not found |
| `CONFLICT` | 409 | Rule not in expected state (e.g., approving non-pending) |
| `UNAUTHORIZED` | 401 | Missing or invalid authentication |
| `FORBIDDEN` | 403 | Insufficient permissions |

---

## Audit Trail

All suppression actions are logged:

| Action | Logged Data |
|--------|-------------|
| `created` | Rule details, requester |
| `approved` | Approver ID |
| `rejected` | Rejecter ID, reason |
| `deleted` | Deleter ID, rule name/status |

Query audit logs via `/api/v1/audit?resource_type=suppression_rule`.

---

## Best Practices

1. **Be specific** - Use narrow patterns to avoid over-suppression
2. **Set expiration** - Temporary suppressions should have expiration dates
3. **Require approval** - Don't auto-approve suppressions
4. **Document reasons** - Use description field to explain why
5. **Review regularly** - Audit active suppressions periodically
6. **Prefer path patterns over rule IDs** - More maintainable as tools update

---

## Examples

### Suppress test files for all tools

```json
{
  "name": "Ignore all test files",
  "suppression_type": "false_positive",
  "path_pattern": "**/test/**"
}
```

### Suppress specific Semgrep rule

```json
{
  "name": "Accept hardcoded localhost",
  "suppression_type": "accepted_risk",
  "tool_name": "semgrep",
  "rule_id": "semgrep.hardcoded-credentials",
  "path_pattern": "**/config/development.yml"
}
```

### Temporary suppression for legacy code

```json
{
  "name": "Legacy code - scheduled for rewrite",
  "description": "JIRA-1234: Legacy auth module rewrite planned for Q2",
  "suppression_type": "wont_fix",
  "path_pattern": "src/legacy/**",
  "expires_at": "2025-04-01T00:00:00Z"
}
```

### Asset-specific suppression

```json
{
  "name": "Third-party fork with known issues",
  "suppression_type": "accepted_risk",
  "asset_id": "550e8400-e29b-41d4-a716-446655440000",
  "tool_name": "trivy"
}
```
