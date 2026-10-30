package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// pathLeadWeightSQL is the step weight of a finding (vulnerability.PathSeverityWeight,
// PathWeightKEV and EPSS), used to pick the lead finding of each asset. The
// numbers come from the Go constants so the order matches the published weight.
var pathLeadWeightSQL = fmt.Sprintf(`GREATEST(
	COALESCE(epss_score, 0),
	CASE WHEN COALESCE(is_in_kev, false) THEN %g ELSE 0 END,
	CASE severity WHEN 'critical' THEN %g WHEN 'high' THEN %g WHEN 'medium' THEN %g WHEN 'low' THEN %g ELSE %g END)`,
	vulnerability.PathWeightKEV,
	vulnerability.PathSeverityWeight("critical"),
	vulnerability.PathSeverityWeight("high"),
	vulnerability.PathSeverityWeight("medium"),
	vulnerability.PathSeverityWeight("low"),
	vulnerability.PathSeverityWeight(""),
)

// AttackPathFindings returns, for each asset in assetIDs that has an open
// finding, the open count (the Open lens of the findings list for that asset),
// the KEV count among them and the lead finding: the open finding with the
// largest step weight. Informational findings and low-confidence version
// matches (potential vulnerabilities, RFC-066 §4) are never a lead. Tenant-scoped.
func (r *FindingRepository) AttackPathFindings(ctx context.Context, tenantID shared.ID, assetIDs []string) (map[string]vulnerability.AssetPathFindings, error) {
	out := make(map[string]vulnerability.AssetPathFindings, len(assetIDs))
	if len(assetIDs) == 0 {
		return out, nil
	}
	query := `
		WITH open_f AS (
			SELECT id, asset_id, title, cve_id, severity, epss_score,
				COALESCE(is_in_kev, false) AS is_in_kev, tool_name, last_seen_tool, confidence, metadata
			FROM findings
			WHERE tenant_id = $1
				AND asset_id = ANY($2::uuid[])
				AND ` + vulnerability.OpenStatusSQL("status") + `
		), counts AS (
			SELECT asset_id, COUNT(*) AS open_count, COUNT(*) FILTER (WHERE is_in_kev) AS kev_count
			FROM open_f GROUP BY asset_id
		), lead AS (
			SELECT DISTINCT ON (asset_id) asset_id, id, COALESCE(title, '') AS title,
				COALESCE(cve_id, '') AS cve_id, severity, epss_score, is_in_kev
			FROM open_f
			WHERE severity NOT IN ('info', 'none')
				AND NOT (tool_name = 'version-match' AND COALESCE(last_seen_tool, tool_name) = 'version-match'
					AND COALESCE(confidence, 0) < 80
				AND metadata->'version_match'->'confirmed_by' IS NULL)
			ORDER BY asset_id, ` + pathLeadWeightSQL + ` DESC, is_in_kev DESC, id
		)
		SELECT c.asset_id, c.open_count, c.kev_count,
			l.id, l.title, l.cve_id, l.severity, l.epss_score, l.is_in_kev
		FROM counts c LEFT JOIN lead l ON l.asset_id = c.asset_id`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(assetIDs))
	if err != nil {
		return nil, fmt.Errorf("failed to read attack-path findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			assetID             string
			openCount, kevCount int
			id, title, cve, sev sql.NullString
			epss                sql.NullFloat64
			kev                 sql.NullBool
		)
		if err := rows.Scan(&assetID, &openCount, &kevCount, &id, &title, &cve, &sev, &epss, &kev); err != nil {
			return nil, fmt.Errorf("failed to scan attack-path findings: %w", err)
		}
		f := vulnerability.AssetPathFindings{OpenCount: openCount, KEVCount: kevCount}
		if id.Valid {
			f.Lead = &vulnerability.PathLeadFinding{
				ID: id.String, Title: title.String, CVEID: cve.String, Severity: sev.String, KEV: kev.Bool,
			}
			if epss.Valid {
				v := epss.Float64
				f.Lead.EPSS = &v
			}
		}
		out[assetID] = f
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed iterating attack-path findings: %w", err)
	}
	return out, nil
}
