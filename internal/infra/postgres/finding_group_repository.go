package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/pagination"
)

// ListFindingGroups returns findings grouped by a dimension.
// Supported dimensions: cve_id, asset_id, owner_id, component_id, severity, source, finding_type.
func (r *FindingRepository) ListFindingGroups(
	ctx context.Context,
	tenantID shared.ID,
	groupBy string,
	filter vulnerability.FindingFilter,
	page pagination.Pagination,
) (pagination.Result[*vulnerability.FindingGroup], error) {
	switch groupBy {
	case "cve_id":
		return r.groupByCVE(ctx, tenantID, filter, page)
	case "asset_id":
		return r.groupByAsset(ctx, tenantID, filter, page)
	case "owner_id":
		return r.groupByOwner(ctx, tenantID, filter, page)
	case "component_id":
		return r.groupByComponent(ctx, tenantID, filter, page)
	case "severity":
		return r.groupByField(ctx, tenantID, "severity", filter, page)
	case "source":
		return r.groupByField(ctx, tenantID, "source", filter, page)
	case "finding_type":
		return r.groupByField(ctx, tenantID, "finding_type", filter, page)
	default:
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("unsupported group_by: %s", groupBy)
	}
}

// statusCountCols returns the common status count columns for GROUP BY queries.
func statusCountCols() string {
	return `
		COUNT(*) as total,
		COUNT(*) FILTER (WHERE f.status IN ('new','confirmed')) as open,
		COUNT(*) FILTER (WHERE f.status = 'in_progress') as in_progress,
		COUNT(*) FILTER (WHERE f.status = 'fix_applied') as fix_applied,
		COUNT(*) FILTER (WHERE f.status IN ('resolved','verified')) as resolved,
		COUNT(DISTINCT f.asset_id) as affected_assets,
		COUNT(DISTINCT f.asset_id) FILTER (WHERE f.status IN ('resolved','verified')) as resolved_assets`
}

// buildFilterWhere builds WHERE clauses from FindingFilter.
// Returns clause string and args starting from argOffset.
func buildFilterWhere(filter vulnerability.FindingFilter, argOffset int) (string, []any) {
	var clauses []string
	var args []any

	if len(filter.Severities) > 0 {
		sevs := make([]string, len(filter.Severities))
		for i, s := range filter.Severities {
			sevs[i] = s.String()
		}
		clauses = append(clauses, fmt.Sprintf("f.severity = ANY($%d)", argOffset))
		args = append(args, pq.Array(sevs))
		argOffset++
	}

	if len(filter.Statuses) > 0 {
		stats := make([]string, len(filter.Statuses))
		for i, s := range filter.Statuses {
			stats[i] = s.String()
		}
		clauses = append(clauses, fmt.Sprintf("f.status = ANY($%d)", argOffset))
		args = append(args, pq.Array(stats))
		argOffset++
	}

	if len(filter.Sources) > 0 {
		srcs := make([]string, len(filter.Sources))
		for i, s := range filter.Sources {
			srcs[i] = string(s)
		}
		clauses = append(clauses, fmt.Sprintf("f.source = ANY($%d)", argOffset))
		args = append(args, pq.Array(srcs))
		argOffset++
	}

	if len(filter.CVEIDs) > 0 {
		clauses = append(clauses, fmt.Sprintf("f.cve_id = ANY($%d)", argOffset))
		args = append(args, pq.Array(filter.CVEIDs))
		argOffset++
	}

	if len(filter.AssetTags) > 0 {
		clauses = append(clauses, fmt.Sprintf(
			"f.asset_id IN (SELECT id FROM assets WHERE tenant_id = f.tenant_id AND tags && $%d)", argOffset))
		args = append(args, pq.Array(filter.AssetTags))
		argOffset++
	}

	if len(filter.FindingTypes) > 0 {
		types := make([]string, len(filter.FindingTypes))
		for i, t := range filter.FindingTypes {
			types[i] = string(t)
		}
		clauses = append(clauses, fmt.Sprintf("f.finding_type = ANY($%d)", argOffset))
		args = append(args, pq.Array(types))
		argOffset++
	}

	return strings.Join(clauses, " AND "), args
}

func (r *FindingRepository) groupByCVE(
	ctx context.Context, tenantID shared.ID,
	filter vulnerability.FindingFilter, page pagination.Pagination,
) (pagination.Result[*vulnerability.FindingGroup], error) {
	filterWhere, filterArgs := buildFilterWhere(filter, 2)
	extraWhere := ""
	if filterWhere != "" {
		extraWhere = "AND " + filterWhere
	}

	// Count query
	countQuery := fmt.Sprintf(`
		SELECT COUNT(DISTINCT f.cve_id)
		FROM findings f
		WHERE f.tenant_id = $1 AND f.cve_id IS NOT NULL AND f.source != 'pentest' %s
	`, extraWhere)

	countArgs := append([]any{tenantID.String()}, filterArgs...)
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("count group by cve: %w", err)
	}

	// Data query
	nextArg := len(filterArgs) + 2
	query := fmt.Sprintf(`
		SELECT
			f.cve_id as group_key,
			COALESCE(v.title, f.cve_id) as label,
			COALESCE(v.severity, f.severity) as severity,
			v.cvss_score, v.epss_score, v.exploit_available,
			v.cisa_kev_date_added IS NOT NULL as cisa_kev,
			%s
		FROM findings f
		LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id
		WHERE f.tenant_id = $1 AND f.cve_id IS NOT NULL AND f.source != 'pentest' %s
		GROUP BY f.cve_id, v.id, v.title, v.severity, f.severity, v.cvss_score, v.epss_score, v.exploit_available, v.cisa_kev_date_added
		ORDER BY
			CASE COALESCE(v.severity, f.severity)
				WHEN 'critical' THEN 1 WHEN 'high' THEN 2
				WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5
			END,
			COUNT(DISTINCT f.asset_id) DESC
		LIMIT $%d OFFSET $%d
	`, statusCountCols(), extraWhere, nextArg, nextArg+1)

	args := append(countArgs, page.Limit(), page.Offset())
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("group by cve: %w", err)
	}
	defer func() { _ = rows.Close() }()

	groups := make([]*vulnerability.FindingGroup, 0)
	for rows.Next() {
		var (
			groupKey                          string
			label, severity                   string
			cvssScore                         *float64
			epssScore                         *float64
			exploitAvailable, cisaKev         *bool
			total, open, ip, fa, resolved     int
			affectedAssets, resolvedAssets     int
		)
		if err := rows.Scan(
			&groupKey, &label, &severity,
			&cvssScore, &epssScore, &exploitAvailable, &cisaKev,
			&total, &open, &ip, &fa, &resolved,
			&affectedAssets, &resolvedAssets,
		); err != nil {
			return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("scan group by cve: %w", err)
		}

		meta := map[string]any{}
		if cvssScore != nil {
			meta["cvss_score"] = *cvssScore
		}
		if epssScore != nil {
			meta["epss_score"] = *epssScore
		}
		if exploitAvailable != nil {
			meta["exploit_available"] = *exploitAvailable
		}
		if cisaKev != nil {
			meta["cisa_kev"] = *cisaKev
		}

		pct := float64(0)
		if total > 0 {
			pct = float64(resolved) / float64(total) * 100
		}

		groups = append(groups, &vulnerability.FindingGroup{
			GroupKey:  groupKey,
			GroupType: "cve",
			Label:     label,
			Severity:  severity,
			Metadata:  meta,
			Stats: vulnerability.FindingGroupStats{
				Total:          total,
				Open:           open,
				InProgress:     ip,
				FixApplied:     fa,
				Resolved:       resolved,
				AffectedAssets: affectedAssets,
				ResolvedAssets: resolvedAssets,
				ProgressPct:    pct,
			},
		})
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("rows group by cve: %w", err)
	}

	return pagination.NewResult(groups, total, page), nil
}

func (r *FindingRepository) groupByAsset(
	ctx context.Context, tenantID shared.ID,
	filter vulnerability.FindingFilter, page pagination.Pagination,
) (pagination.Result[*vulnerability.FindingGroup], error) {
	filterWhere, filterArgs := buildFilterWhere(filter, 2)
	extraWhere := ""
	if filterWhere != "" {
		extraWhere = "AND " + filterWhere
	}

	countQuery := fmt.Sprintf(`
		SELECT COUNT(DISTINCT f.asset_id)
		FROM findings f WHERE f.tenant_id = $1 AND f.source != 'pentest' %s
	`, extraWhere)
	countArgs := append([]any{tenantID.String()}, filterArgs...)
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("count group by asset: %w", err)
	}

	nextArg := len(filterArgs) + 2
	query := fmt.Sprintf(`
		SELECT
			a.id::text as group_key,
			a.name as label,
			a.asset_type::text as asset_type,
			a.criticality::text as criticality,
			COALESCE(u.name, '') as owner_name,
			%s
		FROM findings f
		JOIN assets a ON a.id = f.asset_id
		LEFT JOIN users u ON u.id = a.owner_id
		WHERE f.tenant_id = $1 AND f.source != 'pentest' %s
		GROUP BY a.id, a.name, a.asset_type, a.criticality, u.name
		ORDER BY COUNT(*) DESC
		LIMIT $%d OFFSET $%d
	`, statusCountCols(), extraWhere, nextArg, nextArg+1)

	args := append(countArgs, page.Limit(), page.Offset())
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("group by asset: %w", err)
	}
	defer func() { _ = rows.Close() }()

	groups := make([]*vulnerability.FindingGroup, 0)
	for rows.Next() {
		var (
			groupKey, label                   string
			assetType, criticality, ownerName string
			total, open, ip, fa, resolved     int
			affectedAssets, resolvedAssets     int
		)
		if err := rows.Scan(
			&groupKey, &label, &assetType, &criticality, &ownerName,
			&total, &open, &ip, &fa, &resolved, &affectedAssets, &resolvedAssets,
		); err != nil {
			return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("scan group by asset: %w", err)
		}

		pct := float64(0)
		if total > 0 {
			pct = float64(resolved) / float64(total) * 100
		}

		groups = append(groups, &vulnerability.FindingGroup{
			GroupKey:  groupKey,
			GroupType: "asset",
			Label:     label,
			Severity:  criticality,
			Metadata: map[string]any{
				"asset_type":  assetType,
				"criticality": criticality,
				"owner":       ownerName,
			},
			Stats: vulnerability.FindingGroupStats{
				Total: total, Open: open, InProgress: ip, FixApplied: fa,
				Resolved: resolved, AffectedAssets: affectedAssets,
				ResolvedAssets: resolvedAssets, ProgressPct: pct,
			},
		})
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("rows group by asset: %w", err)
	}

	return pagination.NewResult(groups, total, page), nil
}

func (r *FindingRepository) groupByOwner(
	ctx context.Context, tenantID shared.ID,
	filter vulnerability.FindingFilter, page pagination.Pagination,
) (pagination.Result[*vulnerability.FindingGroup], error) {
	filterWhere, filterArgs := buildFilterWhere(filter, 2)
	extraWhere := ""
	if filterWhere != "" {
		extraWhere = "AND " + filterWhere
	}

	countQuery := fmt.Sprintf(`
		SELECT COUNT(DISTINCT COALESCE(a.owner_id::text, 'unassigned'))
		FROM findings f
		JOIN assets a ON a.id = f.asset_id
		WHERE f.tenant_id = $1 AND f.source != 'pentest' %s
	`, extraWhere)
	countArgs := append([]any{tenantID.String()}, filterArgs...)
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("count group by owner: %w", err)
	}

	nextArg := len(filterArgs) + 2
	query := fmt.Sprintf(`
		SELECT
			COALESCE(a.owner_id::text, 'unassigned') as group_key,
			COALESCE(u.name, 'Unassigned') as label,
			COALESCE(u.email, '') as email,
			%s
		FROM findings f
		JOIN assets a ON a.id = f.asset_id
		LEFT JOIN users u ON u.id = a.owner_id
		WHERE f.tenant_id = $1 AND f.source != 'pentest' %s
		GROUP BY a.owner_id, u.name, u.email
		ORDER BY COUNT(*) DESC
		LIMIT $%d OFFSET $%d
	`, statusCountCols(), extraWhere, nextArg, nextArg+1)

	args := append(countArgs, page.Limit(), page.Offset())
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("group by owner: %w", err)
	}
	defer func() { _ = rows.Close() }()

	groups := make([]*vulnerability.FindingGroup, 0)
	for rows.Next() {
		var (
			groupKey, label, email            string
			total, open, ip, fa, resolved     int
			affectedAssets, resolvedAssets     int
		)
		if err := rows.Scan(
			&groupKey, &label, &email,
			&total, &open, &ip, &fa, &resolved, &affectedAssets, &resolvedAssets,
		); err != nil {
			return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("scan group by owner: %w", err)
		}

		pct := float64(0)
		if total > 0 {
			pct = float64(resolved) / float64(total) * 100
		}

		groups = append(groups, &vulnerability.FindingGroup{
			GroupKey:  groupKey,
			GroupType: "owner",
			Label:     label,
			Metadata:  map[string]any{}, // SEC-03: email removed — use user profile API if needed
			Stats: vulnerability.FindingGroupStats{
				Total: total, Open: open, InProgress: ip, FixApplied: fa,
				Resolved: resolved, AffectedAssets: affectedAssets,
				ResolvedAssets: resolvedAssets, ProgressPct: pct,
			},
		})
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("rows group by owner: %w", err)
	}

	return pagination.NewResult(groups, total, page), nil
}

func (r *FindingRepository) groupByComponent(
	ctx context.Context, tenantID shared.ID,
	filter vulnerability.FindingFilter, page pagination.Pagination,
) (pagination.Result[*vulnerability.FindingGroup], error) {
	filterWhere, filterArgs := buildFilterWhere(filter, 2)
	extraWhere := ""
	if filterWhere != "" {
		extraWhere = "AND " + filterWhere
	}

	countQuery := fmt.Sprintf(`
		SELECT COUNT(DISTINCT f.component_id)
		FROM findings f WHERE f.tenant_id = $1 AND f.component_id IS NOT NULL AND f.source != 'pentest' %s
	`, extraWhere)
	countArgs := append([]any{tenantID.String()}, filterArgs...)
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("count group by component: %w", err)
	}

	nextArg := len(filterArgs) + 2
	query := fmt.Sprintf(`
		SELECT
			c.id::text as group_key,
			c.name || '@' || c.version as label,
			c.ecosystem as ecosystem,
			%s
		FROM findings f
		JOIN components c ON c.id = f.component_id
		WHERE f.tenant_id = $1 AND f.component_id IS NOT NULL AND f.source != 'pentest' %s
		GROUP BY c.id, c.name, c.version, c.ecosystem
		ORDER BY COUNT(*) DESC
		LIMIT $%d OFFSET $%d
	`, statusCountCols(), extraWhere, nextArg, nextArg+1)

	args := append(countArgs, page.Limit(), page.Offset())
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("group by component: %w", err)
	}
	defer func() { _ = rows.Close() }()

	groups := make([]*vulnerability.FindingGroup, 0)
	for rows.Next() {
		var (
			groupKey, label, ecosystem        string
			total, open, ip, fa, resolved     int
			affectedAssets, resolvedAssets     int
		)
		if err := rows.Scan(
			&groupKey, &label, &ecosystem,
			&total, &open, &ip, &fa, &resolved, &affectedAssets, &resolvedAssets,
		); err != nil {
			return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("scan group by component: %w", err)
		}

		pct := float64(0)
		if total > 0 {
			pct = float64(resolved) / float64(total) * 100
		}

		groups = append(groups, &vulnerability.FindingGroup{
			GroupKey:  groupKey,
			GroupType: "component",
			Label:     label,
			Metadata:  map[string]any{"ecosystem": ecosystem},
			Stats: vulnerability.FindingGroupStats{
				Total: total, Open: open, InProgress: ip, FixApplied: fa,
				Resolved: resolved, AffectedAssets: affectedAssets,
				ResolvedAssets: resolvedAssets, ProgressPct: pct,
			},
		})
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("rows group by component: %w", err)
	}

	return pagination.NewResult(groups, total, page), nil
}

// groupByField handles simple GROUP BY on a single column (severity, source, finding_type).
func (r *FindingRepository) groupByField(
	ctx context.Context, tenantID shared.ID,
	field string, filter vulnerability.FindingFilter, page pagination.Pagination,
) (pagination.Result[*vulnerability.FindingGroup], error) {
	// Whitelist field names to prevent SQL injection
	allowedFields := map[string]bool{"severity": true, "source": true, "finding_type": true}
	if !allowedFields[field] {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("invalid group field: %s", field)
	}

	filterWhere, filterArgs := buildFilterWhere(filter, 2)
	extraWhere := ""
	if filterWhere != "" {
		extraWhere = "AND " + filterWhere
	}

	countQuery := fmt.Sprintf(`
		SELECT COUNT(DISTINCT f.%s)
		FROM findings f WHERE f.tenant_id = $1 AND f.source != 'pentest' %s
	`, field, extraWhere)
	countArgs := append([]any{tenantID.String()}, filterArgs...)
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("count group by %s: %w", field, err)
	}

	nextArg := len(filterArgs) + 2
	query := fmt.Sprintf(`
		SELECT f.%s as group_key, %s
		FROM findings f
		WHERE f.tenant_id = $1 AND f.source != 'pentest' %s
		GROUP BY f.%s
		ORDER BY COUNT(*) DESC
		LIMIT $%d OFFSET $%d
	`, field, statusCountCols(), extraWhere, field, nextArg, nextArg+1)

	args := append(countArgs, page.Limit(), page.Offset())
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("group by %s: %w", field, err)
	}
	defer func() { _ = rows.Close() }()

	groups := make([]*vulnerability.FindingGroup, 0)
	for rows.Next() {
		var (
			groupKey                          string
			total, open, ip, fa, resolved     int
			affectedAssets, resolvedAssets     int
		)
		if err := rows.Scan(
			&groupKey,
			&total, &open, &ip, &fa, &resolved, &affectedAssets, &resolvedAssets,
		); err != nil {
			return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("scan group by %s: %w", field, err)
		}

		pct := float64(0)
		if total > 0 {
			pct = float64(resolved) / float64(total) * 100
		}

		groups = append(groups, &vulnerability.FindingGroup{
			GroupKey:  groupKey,
			GroupType: field,
			Label:     groupKey,
			Severity:  groupKey, // for severity dimension, groupKey IS the severity
			Stats: vulnerability.FindingGroupStats{
				Total: total, Open: open, InProgress: ip, FixApplied: fa,
				Resolved: resolved, AffectedAssets: affectedAssets,
				ResolvedAssets: resolvedAssets, ProgressPct: pct,
			},
		})
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[*vulnerability.FindingGroup]{}, fmt.Errorf("rows group by %s: %w", field, err)
	}

	return pagination.NewResult(groups, total, page), nil
}

// BulkUpdateStatusByFilter updates status for all findings matching filter.
// Excludes pentest findings. Uses single UPDATE (no per-finding iteration).
func (r *FindingRepository) BulkUpdateStatusByFilter(
	ctx context.Context, tenantID shared.ID,
	filter vulnerability.FindingFilter, status vulnerability.FindingStatus,
	resolution string, resolvedBy *shared.ID,
) (int64, error) {
	filterWhere, filterArgs := buildFilterWhere(filter, 5)
	extraWhere := ""
	if filterWhere != "" {
		extraWhere = "AND " + filterWhere
	}

	var resolvedClause string
	if status.IsClosed() {
		resolvedClause = ", resolved_at = NOW()"
	} else {
		resolvedClause = ", resolved_at = NULL, resolved_by = NULL"
	}

	query := fmt.Sprintf(`
		UPDATE findings f
		SET status = $2, resolution = $3, resolved_by = $4%s, updated_at = NOW()
		WHERE f.tenant_id = $1 AND f.source != 'pentest' %s
	`, resolvedClause, extraWhere)

	args := append([]any{tenantID.String(), status.String(), nullString(resolution), nullID(resolvedBy)}, filterArgs...)

	result, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("bulk update status by filter: %w", err)
	}

	return result.RowsAffected()
}

// FindRelatedCVEs finds CVEs sharing the same component, optimized 2-step CTE.
func (r *FindingRepository) FindRelatedCVEs(
	ctx context.Context, tenantID shared.ID,
	cveID string, filter vulnerability.FindingFilter,
) ([]vulnerability.RelatedCVE, error) {
	filterWhere, filterArgs := buildFilterWhere(filter, 3)
	extraWhere := ""
	if filterWhere != "" {
		extraWhere = "AND " + filterWhere
	}

	query := fmt.Sprintf(`
		WITH source_components AS (
			SELECT DISTINCT component_id
			FROM findings
			WHERE tenant_id = $1 AND cve_id = $2 AND component_id IS NOT NULL
		)
		SELECT f.cve_id, COALESCE(v.title, f.cve_id), COALESCE(v.severity, f.severity), COUNT(*) as finding_count
		FROM findings f
		JOIN source_components sc ON sc.component_id = f.component_id
		LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id
		WHERE f.tenant_id = $1
			AND f.cve_id != $2
			AND f.cve_id IS NOT NULL
			AND f.status IN ('new', 'confirmed', 'in_progress')
			AND f.source != 'pentest'
			%s
		GROUP BY f.cve_id, v.id, v.title, v.severity, f.severity
		ORDER BY
			CASE COALESCE(v.severity, f.severity)
				WHEN 'critical' THEN 1 WHEN 'high' THEN 2
				WHEN 'medium' THEN 3 ELSE 4
			END,
			COUNT(*) DESC
		LIMIT 10
	`, extraWhere)

	args := append([]any{tenantID.String(), cveID}, filterArgs...)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("find related cves: %w", err)
	}
	defer func() { _ = rows.Close() }()

	results := make([]vulnerability.RelatedCVE, 0)
	for rows.Next() {
		var rc vulnerability.RelatedCVE
		if err := rows.Scan(&rc.CVEID, &rc.Title, &rc.Severity, &rc.FindingCount); err != nil {
			return nil, fmt.Errorf("scan related cve: %w", err)
		}
		results = append(results, rc)
	}
	return results, rows.Err()
}

// ListByStatusAndAssets returns findings with a specific status on specific assets.
func (r *FindingRepository) ListByStatusAndAssets(
	ctx context.Context, tenantID shared.ID,
	status vulnerability.FindingStatus, assetIDs []shared.ID,
) ([]*vulnerability.Finding, error) {
	if len(assetIDs) == 0 {
		return nil, nil
	}

	ids := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		ids[i] = id.String()
	}

	query := r.selectQuery() + `
		WHERE tenant_id = $1 AND status = $2 AND asset_id = ANY($3) AND source != 'pentest'
		ORDER BY updated_at DESC`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), status.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("list by status and assets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	findings := make([]*vulnerability.Finding, 0)
	for rows.Next() {
		f, err := r.scanFindingFromRows(rows)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}
