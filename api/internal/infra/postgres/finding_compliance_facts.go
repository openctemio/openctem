package postgres

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// ComplianceAssetFacts returns, per asset id of the tenant, what the
// compliance severity reads (docs/architecture/compliance-checks.md,
// "Priority"): critical (a crown jewel or criticality critical) and
// production (environment production). Pinned to the tenant: another
// tenant's asset id reads as no asset.
func (r *FindingRepository) ComplianceAssetFacts(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (map[shared.ID]vulnerability.ComplianceAssetFact, error) {
	out := make(map[shared.ID]vulnerability.ComplianceAssetFact, len(assetIDs))
	if len(assetIDs) == 0 {
		return out, nil
	}
	ids := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		ids[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id::text, (COALESCE(is_crown_jewel, false) OR criticality = 'critical'), COALESCE(environment = 'production', false)
		FROM assets WHERE tenant_id = $1 AND id = ANY($2::uuid[])`, tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("compliance asset facts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		var f vulnerability.ComplianceAssetFact
		if err := rows.Scan(&id, &f.Critical, &f.Production); err != nil {
			return nil, err
		}
		if aid, err := shared.IDFromString(id); err == nil {
			out[aid] = f
		}
	}
	return out, rows.Err()
}
