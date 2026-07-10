package postgres

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/remediation"
	"github.com/openctemio/api/pkg/domain/shared"
)

// FindingRemediationKeyRepository owns the finding_remediation_keys side-table
// (RFC-015). It never reads or writes the findings table itself — group queries
// JOIN to findings read-only for status/severity/asset rollups.
type FindingRemediationKeyRepository struct {
	db *DB
}

// NewFindingRemediationKeyRepository constructs the repository.
func NewFindingRemediationKeyRepository(db *DB) *FindingRemediationKeyRepository {
	return &FindingRemediationKeyRepository{db: db}
}

var _ remediation.KeyRepository = (*FindingRemediationKeyRepository)(nil)

// Upsert records or refreshes a finding's remediation key (idempotent on finding_id).
func (r *FindingRemediationKeyRepository) Upsert(ctx context.Context, tenantID, findingID shared.ID, key, title string) error {
	const q = `
		INSERT INTO finding_remediation_keys (finding_id, tenant_id, remediation_key, title, updated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (finding_id)
		DO UPDATE SET remediation_key = EXCLUDED.remediation_key,
		              title = EXCLUDED.title,
		              updated_at = NOW()`
	if _, err := r.db.ExecContext(ctx, q, findingID.String(), tenantID.String(), key, title); err != nil {
		return fmt.Errorf("upsert remediation key: %w", err)
	}
	return nil
}

// Delete removes a finding's key.
func (r *FindingRemediationKeyRepository) Delete(ctx context.Context, findingID shared.ID) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM finding_remediation_keys WHERE finding_id = $1`, findingID.String()); err != nil {
		return fmt.Errorf("delete remediation key: %w", err)
	}
	return nil
}

// ListGroups rolls up the tenant's open, non-pentest findings by remediation key.
func (r *FindingRemediationKeyRepository) ListGroups(ctx context.Context, tenantID shared.ID, excludeStatuses []string) ([]remediation.Group, error) {
	const q = `
		SELECT frk.remediation_key,
		       MAX(frk.title) AS title,
		       COUNT(*)::int AS finding_count,
		       COUNT(DISTINCT f.asset_id)::int AS asset_count,
		       COUNT(*) FILTER (WHERE f.severity = 'critical')::int AS crit,
		       COUNT(*) FILTER (WHERE f.severity = 'high')::int AS high,
		       COUNT(*) FILTER (WHERE f.severity = 'medium')::int AS medium,
		       COUNT(*) FILTER (WHERE f.severity = 'low')::int AS low,
		       COUNT(*) FILTER (WHERE f.severity IN ('info', 'none'))::int AS info
		FROM finding_remediation_keys frk
		JOIN findings f ON f.id = frk.finding_id
		WHERE frk.tenant_id = $1
		  AND f.source <> 'pentest'
		  AND f.status <> ALL($2::text[])
		GROUP BY frk.remediation_key
		ORDER BY finding_count DESC`

	rows, err := r.db.QueryContext(ctx, q, tenantID.String(), pq.Array(excludeStatuses))
	if err != nil {
		return nil, fmt.Errorf("list remediation groups: %w", err)
	}
	defer func() { _ = rows.Close() }()

	groups := make([]remediation.Group, 0)
	for rows.Next() {
		var (
			g                          remediation.Group
			crit, high, med, low, info int
		)
		if err := rows.Scan(&g.Key, &g.Title, &g.FindingCount, &g.AssetCount, &crit, &high, &med, &low, &info); err != nil {
			return nil, err
		}
		g.SeverityCounts = map[string]int{
			"critical": crit, "high": high, "medium": med, "low": low, "info": info,
		}
		g.FixAvailable = true // a group is, by construction, an actionable fix
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// OpenFindingIDs returns the open, non-pentest finding IDs in a group.
func (r *FindingRemediationKeyRepository) OpenFindingIDs(ctx context.Context, tenantID shared.ID, key string, excludeStatuses []string) ([]shared.ID, error) {
	const q = `
		SELECT f.id
		FROM finding_remediation_keys frk
		JOIN findings f ON f.id = frk.finding_id
		WHERE frk.tenant_id = $1
		  AND frk.remediation_key = $2
		  AND f.source <> 'pentest'
		  AND f.status <> ALL($3::text[])`

	rows, err := r.db.QueryContext(ctx, q, tenantID.String(), key, pq.Array(excludeStatuses))
	if err != nil {
		return nil, fmt.Errorf("open finding ids by key: %w", err)
	}
	defer func() { _ = rows.Close() }()

	ids := make([]shared.ID, 0)
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// CountByKey returns (total, resolved) non-pentest findings sharing the key —
// total across every status, resolved being those whose status is in
// closedStatuses. Single round trip via FILTER so a keyed campaign's progress
// stays a cheap side-table rollup.
func (r *FindingRemediationKeyRepository) CountByKey(ctx context.Context, tenantID shared.ID, key string, closedStatuses []string) (int64, int64, error) {
	const q = `
		SELECT
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE f.status = ANY($3::text[])) AS resolved
		FROM finding_remediation_keys frk
		JOIN findings f ON f.id = frk.finding_id
		WHERE frk.tenant_id = $1
		  AND frk.remediation_key = $2
		  AND f.source <> 'pentest'`

	var total, resolved int64
	if err := r.db.QueryRowContext(ctx, q, tenantID.String(), key, pq.Array(closedStatuses)).Scan(&total, &resolved); err != nil {
		return 0, 0, fmt.Errorf("count findings by remediation key: %w", err)
	}
	return total, resolved, nil
}
