package postgres

// The approval policy facts of many findings in one query, for a request
// that evaluates every finding of a selection (bulk dismiss). Same columns
// and rules as PolicyFacts; scoped to one tenant.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/internal/app/finding"
	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// PolicyFactsMany reads the policy facts of findingIDs of tenantID. A finding
// of another tenant, or one that no longer exists, has no entry.
func (r *FindingApprovalRepository) PolicyFactsMany(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) (map[shared.ID]finding.PolicyFacts, error) {
	out := make(map[shared.ID]finding.PolicyFacts, len(findingIDs))
	if len(findingIDs) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(findingIDs))
	for _, id := range findingIDs {
		ids = append(ids, id.String())
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT f.id::text, f.severity, COALESCE(f.priority_class, ''), COALESCE(f.is_in_kev, false), f.epss_score::float8,
		       COALESCE(f.validation_outcome = 'reproducible', false),
		       COALESCE(a.is_crown_jewel, false), COALESCE(`+asset.InternetFacingSQL("a")+`, false),
		       f.assigned_to::text,
		       ARRAY(`+fmt.Sprintf(assetOwnersSQL, "f.asset_id")+`)::text[]
		FROM findings f
		LEFT JOIN assets a ON a.tenant_id = f.tenant_id AND a.id = f.asset_id
		WHERE f.tenant_id = $1 AND f.id = ANY($2::uuid[])`,
		tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("read approval policy facts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id       string
			pf       finding.PolicyFacts
			epss     sql.NullFloat64
			assignee sql.NullString
			owners   pq.StringArray
		)
		if err := rows.Scan(&id, &pf.Facts.Severity, &pf.Facts.PriorityClass, &pf.Facts.KEV, &epss, &pf.Facts.ExploitValidated,
			&pf.Facts.CrownJewel, &pf.Facts.InternetExposed, &assignee, &owners); err != nil {
			return nil, fmt.Errorf("scan approval policy facts: %w", err)
		}
		fid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		if epss.Valid {
			v := epss.Float64
			pf.Facts.EPSS = &v
		}
		if assignee.Valid {
			if aid, err := shared.IDFromString(assignee.String); err == nil {
				pf.AssigneeID = &aid
			}
		}
		for _, o := range owners {
			if oid, err := shared.IDFromString(o); err == nil {
				pf.AssetOwners = append(pf.AssetOwners, oid)
			}
		}
		out[fid] = pf
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read approval policy facts: %w", err)
	}
	return out, nil
}
