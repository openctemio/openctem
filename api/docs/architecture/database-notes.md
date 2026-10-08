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
- `pkg/domain/asset/entity.go` - `UpdateFindingCount()` method (in-memory only)
- `pkg/domain/asset/entity.go` - `CalculateRiskScore()` uses findingCount for risk calculation
- `internal/infra/postgres/asset_repository.go` - `selectQuery()` calculates it dynamically

### Repository Identifier Normalization

When assets are created from sensors (e.g., semgrep), the identifier format may differ from SCM imports:

| Source | Identifier Format | Example |
|--------|------------------|---------|
| Sensor (semgrep) | `github.com-org/repo` | `github.com-openctem/openctemio/sdk` |
| SCM Import | `org/repo` | `openctemio/sdk` |

**Normalization logic:** `internal/app/asset/service.go` - `findMatchingRepositoryAsset()` / `updateExistingRepositoryAsset()`

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

### sensor_id - Traceability Field

- References `sensors(id)` with `ON DELETE SET NULL`
- Tracks which sensor last submitted the finding (the upsert overwrites it; see
  [ADR-004](decisions/004-finding-provenance.md))
- NULL for manual and imported findings

### source - Finding Source Type

Valid values (constraint `chk_findings_source`): `sast`, `dast`, `sca`,
`secret`, `iac`, `container`, `cspm`, `easm`, `va`, `rasp`, `waf`, `siem`,
`manual`, `pentest`, `bug_bounty`, `red_team`, `external`, `threat_intel`,
`vendor`, `sarif`, `api`, and the legacy alias `sca_tool`. `source` is the
**technique**, not the channel (see [ADR-004](decisions/004-finding-provenance.md)).

---

## Best Practices

1. **Never add a `finding_count` column** - Keep it calculated dynamically
2. **Use `CalculateRiskScore()`** after modifying data that affects risk (criticality, findings, etc.)
3. **Check the repository matching in `internal/app/asset/service.go`** when adding new SCM provider support
4. **Update migration constraints** when adding new finding source types
6. **Document new DB functions** - Add to this file when creating new PostgreSQL functions in migrations
