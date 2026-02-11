# Database Implementation Notes

This document contains important notes about database schema design decisions and implementation details that developers should be aware of.

## Assets Table

### finding_count - Dynamically Calculated Field

**IMPORTANT:** `finding_count` is NOT a column in the `assets` table. It is calculated dynamically via a subquery when reading assets.

**Location:** `internal/infra/postgres/asset_repository.go` - `selectQuery()` function

```sql
SELECT
    a.id, a.tenant_id, ...
    COALESCE((SELECT COUNT(*) FROM findings f WHERE f.asset_id = a.id), 0) as finding_count,
    ...
FROM assets a
```

**Why this design?**
- Ensures finding count is always accurate and up-to-date
- No need to maintain synchronization between findings and assets tables
- Avoids potential data inconsistency issues

**Implications:**
1. The `Asset` entity has a `findingCount` field in memory (for domain logic)
2. Calling `asset.UpdateFindingCount()` only updates the in-memory value
3. The `Update()` repository method does NOT persist `findingCount` to the database
4. When you read an asset, the finding count is always fresh from the database

**Related code:**
- `internal/domain/asset/entity.go` - `UpdateFindingCount()` method (in-memory only)
- `internal/domain/asset/entity.go` - `CalculateRiskScore()` uses findingCount for risk calculation
- `internal/infra/postgres/asset_repository.go` - `selectQuery()` calculates it dynamically

### Repository Identifier Normalization

When assets are created from agents (e.g., Semgrep), the identifier format may differ from SCM imports:

| Source | Identifier Format | Example |
|--------|------------------|---------|
| Semgrep Agent | `github.com-org/repo` | `github.com-openctem/openctemio/sdk` |
| SCM Import | `org/repo` | `openctemio/sdk` |

**Normalization logic:** `internal/app/ingest_service.go` - `normalizeRepositoryIdentifier()`

The system handles this by:
1. Detecting provider from prefix (e.g., `github.com-` → GitHub)
2. Extracting the path after the prefix
3. Using multiple matching strategies to find existing assets

### Provider Detection

Provider is detected from asset identifier patterns:

| Pattern | Provider |
|---------|----------|
| `github.com-*` or `github.com/*` | GitHub |
| `gitlab.com-*` or `gitlab.com/*` | GitLab |
| `bitbucket.org-*` | Bitbucket |
| `dev.azure.com-*` | Azure DevOps |
| `arn:aws:*` | AWS |
| `/subscriptions/*` | Azure |
| `projects/*` | GCP |

---

## Findings Table

### agent_id - Traceability Field

Added in migration `000020_findings_add_agent_id.up.sql`.

- References `agents(id)` with `ON DELETE SET NULL`
- Tracks which agent submitted each finding
- NULL for manual findings or findings created before this migration

### source - Finding Source Type

Valid values (from constraint `chk_findings_source`):
- `sast` - Static Application Security Testing
- `dast` - Dynamic Application Security Testing
- `sca` - Software Composition Analysis (new standard)
- `sca_tool` - Legacy alias for SCA
- `secret` - Secret detection
- `iac` - Infrastructure as Code scanning
- `container` - Container scanning
- `manual` - Manually created
- `external` - External source
- `sarif` - SARIF format import

---

---

## PostgreSQL Functions

### Platform Agent Functions (v3.2)

These functions support the K8s-style lease-based platform agent system. Added in migrations `000080`, `000083`, `000084`.

#### Queue Management Functions

| Function | Description | Migration |
|----------|-------------|-----------|
| `calculate_queue_priority(plan_slug, queued_at)` | Calculate job priority based on plan tier + wait time | 000080 |
| `get_next_platform_job(agent_id, capabilities, tools)` | Atomically claim next job from queue (uses `FOR UPDATE SKIP LOCKED`) | 000080 |
| `update_queue_priorities()` | Recalculate priorities for all pending platform jobs | 000080 |
| `recover_stuck_platform_jobs(threshold_minutes)` | Return stuck jobs to queue (max 3 retries) | 000080, 000084 |

**Priority Calculation:**
```
queue_priority = plan_base_priority + age_bonus

Plan Base Priority:
- Enterprise: 100
- Business: 75
- Team: 50
- Free: 25

Age Bonus: +1 per minute waiting, max +75
```

**Example usage in Go:**
```go
// Called by CommandRepository.GetNextPlatformJob()
query := `SELECT get_next_platform_job($1, $2, $3)`
err := db.QueryRowContext(ctx, query, agentID, capabilities, tools).Scan(&jobID)
```

#### Lease Management Functions

| Function | Description | Migration |
|----------|-------------|-----------|
| `is_lease_expired(agent_id, grace_seconds)` | Check if agent's lease has expired | 000083 |
| `renew_agent_lease(agent_id, holder_identity, duration, ...)` | Atomically renew/acquire lease | 000083 |
| `find_expired_agent_leases(grace_seconds)` | Find agents with expired leases | 000083 |
| `release_agent_lease(agent_id, holder_identity)` | Release lease (graceful shutdown) | 000083 |

**Lease Renewal Response:**
```sql
RETURNS TABLE (
    success BOOLEAN,
    resource_version INT,  -- Optimistic locking version
    message TEXT
)
```

**Example usage in Go:**
```go
// Called by LeaseService.RenewLease()
query := `SELECT * FROM renew_agent_lease($1, $2, $3, $4, $5, $6, $7, $8)`
row := db.QueryRowContext(ctx, query, agentID, holderIdentity, duration,
    currentJobs, maxJobs, cpuPercent, memoryPercent, diskPercent)
```

#### Views

| View | Description | Migration |
|------|-------------|-----------|
| `platform_agent_status` | Combined view of agents + lease status for monitoring | 000083 |

**Columns:** `id`, `name`, `agent_type`, `region`, `capabilities`, `health_status`, `holder_identity`, `lease_duration_seconds`, `last_heartbeat`, `current_jobs`, `max_jobs`, `cpu_percent`, `memory_percent`, `disk_percent`, `lease_status`, `lease_ttl_seconds`, `available_capacity`

### Custom Types

| Type | Values | Migration |
|------|--------|-----------|
| `bootstrap_token_status` | `active`, `revoked`, `expired`, `exhausted` | 000081 |

---

## Best Practices

1. **Never add a `finding_count` column** - Keep it calculated dynamically
2. **Use `CalculateRiskScore()`** after modifying data that affects risk (criticality, findings, etc.)
3. **Check `normalizeRepositoryIdentifier()`** when adding new SCM provider support
4. **Update migration constraints** when adding new finding source types
5. **Use DB functions for atomic operations** - Platform agent job claiming and lease renewal use PostgreSQL functions for concurrent safety
6. **Document new DB functions** - Add to this file when creating new PostgreSQL functions in migrations
