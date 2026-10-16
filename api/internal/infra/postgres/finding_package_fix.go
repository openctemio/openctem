package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// packageFixOpenStatuses are the statuses that still need a fix (the open and
// in-progress categories of vulnerability.FindingStatus).
var packageFixOpenStatuses = []string{
	string(vulnerability.FindingStatusNew), string(vulnerability.FindingStatusConfirmed),
	string(vulnerability.FindingStatusInProgress), string(vulnerability.FindingStatusFixApplied),
}

// ListPackageFixSiblings returns the open findings of one package version on
// one asset, with the versions that fix each: the finding's own scanner copy
// and the CVE catalog's, merged. Tenant- and asset-scoped; at most limit rows,
// most severe first.
func (r *FindingRepository) ListPackageFixSiblings(ctx context.Context, tenantID, assetID, componentID shared.ID, limit int) ([]vulnerability.PackageFixSibling, error) {
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	const query = `
		SELECT f.id, COALESCE(f.title, ''), f.severity, COALESCE(f.cve_id, ''),
			COALESCE(f.metadata->'fixed_versions', '[]'::jsonb), COALESCE(v.fixed_versions, '{}')
		FROM findings f
		LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id
		WHERE f.tenant_id = $1 AND f.asset_id = $2 AND f.component_id = $3
			AND f.status = ANY($4)
		ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
			WHEN 'low' THEN 3 ELSE 4 END, f.id
		LIMIT $5`
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), assetID.String(), componentID.String(),
		pq.Array(packageFixOpenStatuses), limit)
	if err != nil {
		return nil, fmt.Errorf("list package fix siblings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]vulnerability.PackageFixSibling, 0, 8)
	for rows.Next() {
		var s vulnerability.PackageFixSibling
		var own []byte
		var catalog []string
		if err := rows.Scan(&s.ID, &s.Title, &s.Severity, &s.CVEID, &own, pq.Array(&catalog)); err != nil {
			return nil, fmt.Errorf("scan package fix sibling: %w", err)
		}
		var ownList []string
		_ = json.Unmarshal(own, &ownList) // not a string list: no scanner copy
		s.Fixed = vulnerability.NormalizeFixedVersions("", append(ownList, catalog...))
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate package fix siblings: %w", err)
	}
	return out, nil
}
