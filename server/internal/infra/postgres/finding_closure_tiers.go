package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// FindingRiskTiers returns the risk tier (severity, priority class, KEV) of
// each of the tenant's findings in ids, in one query, for the closure rule
// (vulnerability.DecideClosure). An id of another tenant, or of a deleted
// finding, is absent from the result.
func (r *FindingRepository) FindingRiskTiers(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]vulnerability.RiskTier, error) {
	out := make(map[shared.ID]vulnerability.RiskTier, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	idStrs := make([]string, len(ids))
	for i, id := range ids {
		idStrs[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id::text, LOWER(severity::text), COALESCE(priority_class, ''), COALESCE(is_in_kev, false)
		FROM findings
		WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
		tenantID.String(), pq.Array(idStrs))
	if err != nil {
		return nil, fmt.Errorf("finding risk tiers: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			idStr, sev, pc string
			kev            sql.NullBool
		)
		if err := rows.Scan(&idStr, &sev, &pc, &kev); err != nil {
			return nil, fmt.Errorf("finding risk tiers: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue
		}
		out[id] = vulnerability.FindingRiskTier(vulnerability.Severity(sev), pc, kev.Bool)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("finding risk tiers: %w", err)
	}
	return out, nil
}
