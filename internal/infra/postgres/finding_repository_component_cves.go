package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/pagination"
)

// ListComponentCVEPairs returns one row per (global component, CVE) pair
// observed in this tenant's findings. Derived — no junction table involved.
// Joins: findings → components (global) × vulnerabilities.
//
// Note: findings.component_id references components(id) directly.
func (r *FindingRepository) ListComponentCVEPairs(
	ctx context.Context,
	tenantID shared.ID,
	filter vulnerability.ComponentCVEFilter,
	page pagination.Pagination,
) (pagination.Result[*vulnerability.ComponentCVEPair], error) {
	conditions := []string{
		"f.tenant_id = $1",
		"f.component_id IS NOT NULL",
		"f.vulnerability_id IS NOT NULL",
	}
	args := []any{tenantID.String()}
	next := 2

	if len(filter.ComponentIDs) > 0 {
		ids := make([]string, len(filter.ComponentIDs))
		for i, id := range filter.ComponentIDs {
			ids[i] = id.String()
		}
		conditions = append(conditions, fmt.Sprintf("c.id = ANY($%d)", next))
		args = append(args, pq.Array(ids))
		next++
	}
	if len(filter.CVEIDs) > 0 {
		conditions = append(conditions, fmt.Sprintf("v.cve_id = ANY($%d)", next))
		args = append(args, pq.Array(filter.CVEIDs))
		next++
	}
	if filter.OnlyOpenFindings {
		conditions = append(conditions,
			"f.status NOT IN ('resolved','verified','false_positive','accepted')")
	}
	if filter.MinSeverity != nil {
		conditions = append(conditions, fmt.Sprintf(
			"CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END >= $%d",
			next,
		))
		args = append(args, componentCVESeverityRank(*filter.MinSeverity))
		next++
	}

	where := strings.Join(conditions, " AND ")

	query := fmt.Sprintf(`
		SELECT
			c.id,
			COALESCE(c.purl, ''),
			v.cve_id,
			v.id,
			COUNT(*),
			MAX(CASE f.severity
				WHEN 'critical' THEN 5 WHEN 'high' THEN 4
				WHEN 'medium'   THEN 3 WHEN 'low'  THEN 2
				WHEN 'info'     THEN 1 ELSE 0 END),
			MIN(f.created_at),
			MAX(f.updated_at)
		FROM findings f
		JOIN components     c ON c.id = f.component_id
		JOIN vulnerabilities v ON v.id = f.vulnerability_id
		WHERE %s
		GROUP BY c.id, c.purl, v.cve_id, v.id
		ORDER BY v.cve_id
		LIMIT $%d OFFSET $%d
	`, where, next, next+1)

	queryArgs := append([]any{}, args...)
	queryArgs = append(queryArgs, page.Limit(), page.Offset())

	rows, err := r.db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return pagination.Result[*vulnerability.ComponentCVEPair]{}, fmt.Errorf("list component-cve pairs: %w", err)
	}
	defer rows.Close()

	var items []*vulnerability.ComponentCVEPair
	for rows.Next() {
		var (
			compIDStr string
			purl      string
			cveID     string
			vulnIDStr string
			count     int64
			sevRank   int
			firstAt   time.Time
			lastAt    time.Time
		)
		if err := rows.Scan(&compIDStr, &purl, &cveID, &vulnIDStr, &count, &sevRank, &firstAt, &lastAt); err != nil {
			return pagination.Result[*vulnerability.ComponentCVEPair]{}, fmt.Errorf("scan component-cve row: %w", err)
		}
		compID, err := shared.IDFromString(compIDStr)
		if err != nil {
			return pagination.Result[*vulnerability.ComponentCVEPair]{}, fmt.Errorf("parse component id: %w", err)
		}
		vulnID, err := shared.IDFromString(vulnIDStr)
		if err != nil {
			return pagination.Result[*vulnerability.ComponentCVEPair]{}, fmt.Errorf("parse vulnerability id: %w", err)
		}
		items = append(items, &vulnerability.ComponentCVEPair{
			ComponentID:     compID,
			ComponentPURL:   purl,
			CVEID:           cveID,
			VulnerabilityID: vulnID,
			FindingCount:    count,
			MaxSeverity:     componentCVERankToSeverity(sevRank),
			FirstSeenAt:     firstAt,
			LastSeenAt:      lastAt,
		})
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*vulnerability.ComponentCVEPair]{}, fmt.Errorf("iterate component-cve rows: %w", err)
	}

	// Count query — same WHERE, same original args (not the query-with-LIMIT args).
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*) FROM (
			SELECT 1
			FROM findings f
			JOIN components      c ON c.id = f.component_id
			JOIN vulnerabilities v ON v.id = f.vulnerability_id
			WHERE %s
			GROUP BY c.id, v.id
		) t
	`, where)

	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return pagination.Result[*vulnerability.ComponentCVEPair]{}, fmt.Errorf("count component-cve pairs: %w", err)
	}

	return pagination.NewResult(items, total, page), nil
}

func componentCVESeverityRank(s vulnerability.Severity) int {
	switch s {
	case vulnerability.SeverityCritical:
		return 5
	case vulnerability.SeverityHigh:
		return 4
	case vulnerability.SeverityMedium:
		return 3
	case vulnerability.SeverityLow:
		return 2
	case vulnerability.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func componentCVERankToSeverity(rank int) vulnerability.Severity {
	switch rank {
	case 5:
		return vulnerability.SeverityCritical
	case 4:
		return vulnerability.SeverityHigh
	case 3:
		return vulnerability.SeverityMedium
	case 2:
		return vulnerability.SeverityLow
	case 1:
		return vulnerability.SeverityInfo
	default:
		return vulnerability.SeverityInfo
	}
}
