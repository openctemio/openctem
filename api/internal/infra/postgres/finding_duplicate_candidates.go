package postgres

// Duplicate candidates of a finding (RFC-121 §6).
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-121-bug-bounty-reports.md

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// DuplicateSuggestions returns the candidates of q.FindingID: other findings
// of the tenant, not folded duplicates, on the same asset or an asset with
// the same host (assetHostSQL), sharing a CWE, a CVE or a vulnerable path. Any source and
// status. Only candidates inside q.Scope and visible to the viewer of ctx
// (pentest member rule) are returned. Same asset first, then the number of
// matching signals, then the earliest first detection.
func (r *FindingRepository) DuplicateSuggestions(ctx context.Context, q vulnerability.DuplicateSuggestionQuery) ([]vulnerability.DuplicateSuggestion, error) {
	limit := q.Limit
	if limit <= 0 || limit > vulnerability.MaxDuplicateSuggestions {
		limit = vulnerability.MaxDuplicateSuggestions
	}
	args := []any{q.TenantID.String(), q.FindingID.String(), q.AssetID.String(),
		pq.Array(nonEmpty(q.ExtraCWEs)), pq.Array(nonEmpty(q.ExtraPaths)), limit}
	scopeCond, args := dataScopeCond("c.asset_id", q.Scope, args)
	query := `
		WITH seed AS (
			SELECT COALESCE(f.cwe_ids, '{}') || $4::text[] AS cwes,
				array_remove(COALESCE(f.cve_ids, '{}') || ARRAY[f.cve_id]::text[], NULL) AS cves,
				$5::text[] || ARRAY(SELECT ip.path FROM finding_injection_points ip
					WHERE ip.tenant_id = $1 AND ip.finding_id = f.id AND ip.path IS NOT NULL AND ip.path <> '') AS paths
			FROM findings f WHERE f.tenant_id = $1 AND f.id = $2
		),
		seed_host AS (
			SELECT ` + assetHostSQL("a") + ` AS host FROM assets a WHERE a.tenant_id = $1 AND a.id = $3
		),
		cand_assets AS (
			SELECT a.id, a.name FROM assets a
			WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
				AND (a.id = $3 OR ` + assetHostSQL("a") + ` = (SELECT NULLIF(host, '') FROM seed_host))
		)
		SELECT id, asset_id, name, title, source, status, severity, first_seen, same_asset, m_cwe, m_cve, m_path FROM (
		SELECT c.id, c.asset_id, ca.name, LEFT(COALESCE(NULLIF(c.title, ''), c.message, ''), 500) AS title,
			c.source, c.status, c.severity, COALESCE(c.first_detected_at, c.created_at) AS first_seen,
			c.asset_id = $3 AS same_asset,
			COALESCE(c.cwe_ids && s.cwes, FALSE) AS m_cwe,
			(COALESCE(c.cve_id = ANY(s.cves), FALSE) OR COALESCE(c.cve_ids && s.cves, FALSE)) AS m_cve,
			EXISTS (SELECT 1 FROM finding_injection_points ip
				WHERE ip.tenant_id = $1 AND ip.finding_id = c.id AND ip.path = ANY(s.paths)) AS m_path
		FROM findings c
		JOIN cand_assets ca ON ca.id = c.asset_id
		CROSS JOIN seed s
		WHERE c.tenant_id = $1 AND c.id <> $2 AND c.status <> 'duplicate'
			AND ` + scopeCond + pentestVisibilityExcl(ctx, "c") + `
			AND (COALESCE(c.cwe_ids && s.cwes, FALSE)
				OR COALESCE(c.cve_id = ANY(s.cves), FALSE) OR COALESCE(c.cve_ids && s.cves, FALSE)
				OR EXISTS (SELECT 1 FROM finding_injection_points ip
					WHERE ip.tenant_id = $1 AND ip.finding_id = c.id AND ip.path = ANY(s.paths)))
		) cand
		ORDER BY same_asset DESC, (m_cwe::int + m_cve::int + m_path::int) DESC, first_seen ASC, id
		LIMIT $6`
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("duplicate candidates: %w", err)
	}
	defer rows.Close()
	out := make([]vulnerability.DuplicateSuggestion, 0, limit)
	for rows.Next() {
		var d vulnerability.DuplicateSuggestion
		var id, assetID string
		if err := rows.Scan(&id, &assetID, &d.AssetName, &d.Title, &d.Source, &d.Status, &d.Severity,
			&d.FirstDetectedAt, &d.SameAsset, &d.MatchCWE, &d.MatchCVE, &d.MatchPath); err != nil {
			return nil, fmt.Errorf("duplicate candidates: scan: %w", err)
		}
		d.FindingID, _ = shared.IDFromString(id)
		d.AssetID, _ = shared.IDFromString(assetID)
		out = append(out, d)
	}
	return out, rows.Err()
}

func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
