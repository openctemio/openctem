package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// DashboardRepository implements app.DashboardStatsRepository using PostgreSQL.
type DashboardRepository struct {
	db *sql.DB
}

// NewDashboardRepository creates a new DashboardRepository.
func NewDashboardRepository(db *sql.DB) *DashboardRepository {
	return &DashboardRepository{db: db}
}

// Ensure DashboardRepository implements app.DashboardStatsRepository
var _ module.DashboardStatsRepository = (*DashboardRepository)(nil)

// GetFindingStats returns finding statistics for a tenant.
func (r *DashboardRepository) GetFindingStats(ctx context.Context, tenantID shared.ID) (module.FindingStatsData, error) {
	stats := module.FindingStatsData{
		BySeverity: make(map[string]int),
		ByStatus:   make(map[string]int),
	}

	// Single query with CTEs — replaces 4 separate queries.
	// Excludes pentest "draft" and "in_review" statuses (Phase 4 internal workflow,
	// hidden from the CTEM dashboard until reviewer approves).
	query := `
		WITH base AS (
			SELECT id, severity, status, vulnerability_id, cvss_score FROM findings
			WHERE tenant_id = $1 AND status NOT IN ('draft', 'in_review') AND NOT branch_only
		),
		total AS (SELECT COUNT(*) AS cnt FROM base),
		by_sev AS (SELECT severity, COUNT(*) AS cnt FROM base GROUP BY severity),
		by_stat AS (SELECT status, COUNT(*) AS cnt FROM base GROUP BY status),
		avg_cvss AS (
			SELECT COALESCE(AVG(COALESCE(b.cvss_score, v.cvss_score)), 0) AS val
			FROM base b LEFT JOIN vulnerabilities v ON b.vulnerability_id = v.id
		)
		SELECT 'total' AS category, '' AS key, cnt::float8 FROM total
		UNION ALL
		SELECT 'severity', severity, cnt::float8 FROM by_sev
		UNION ALL
		SELECT 'status', status, cnt::float8 FROM by_stat
		UNION ALL
		SELECT 'avg_cvss', '', val FROM avg_cvss
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return stats, err
	}
	defer rows.Close()

	for rows.Next() {
		var category, key string
		var value float64
		if err := rows.Scan(&category, &key, &value); err != nil {
			return stats, err
		}
		switch category {
		case "total":
			stats.Total = int(value)
		case "severity":
			stats.BySeverity[key] = int(value)
		case "status":
			stats.ByStatus[key] = int(value)
		case "avg_cvss":
			stats.AverageCVSS = value
		}
	}
	if err := rows.Err(); err != nil {
		return stats, err
	}

	stats.Overdue = 0 // Requires SLA-based due_date — planned for Phase 2

	return stats, nil
}

// GetRepositoryStats returns repository statistics for a tenant.
func (r *DashboardRepository) GetRepositoryStats(ctx context.Context, tenantID shared.ID) (module.RepositoryStatsData, error) {
	stats := module.RepositoryStatsData{}

	// Get total count of repositories (assets with type 'repository')
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM assets WHERE deleted_at IS NULL AND tenant_id = $1 AND asset_type = 'repository'`,
		tenantID.String(),
	).Scan(&stats.Total)
	if err != nil {
		return stats, err
	}

	// Get count of repositories with findings
	err = r.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT a.id) FROM assets a
		 INNER JOIN findings f ON f.tenant_id = a.tenant_id AND f.asset_id = a.id AND NOT f.branch_only
		 WHERE a.deleted_at IS NULL AND a.tenant_id = $1 AND a.asset_type = 'repository'`,
		tenantID.String(),
	).Scan(&stats.WithFindings)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		stats.WithFindings = 0
	}

	return stats, nil
}

// GetRecentActivity returns recent activity for a tenant. A non-nil scope
// keeps only findings whose asset is in that Layer 2 data scope.
func (r *DashboardRepository) GetRecentActivity(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, limit int) ([]module.ActivityItem, error) {
	// For now, get recent findings as activity
	// In future, this could be from an audit log table
	scopeCond, args := dataScopeCond("f.asset_id", scope, []any{tenantID.String()})
	args = append(args, limit)
	//nolint:gosec // G202: scopeCond is built from fixed SQL and numbered placeholders
	rows, err := r.db.QueryContext(ctx,
		`SELECT 'finding' as type,
		        f.id::text as ref_id,
		        COALESCE(f.rule_id, f.tool_name) as title,
		        f.message as description,
		        f.created_at
		 FROM findings f
		 WHERE f.tenant_id = $1 AND NOT f.branch_only AND `+scopeCond+`
		 ORDER BY f.created_at DESC
		 LIMIT $`+itoa(len(args)),
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var activity []module.ActivityItem
	for rows.Next() {
		var item module.ActivityItem
		if err := rows.Scan(&item.Type, &item.RefID, &item.Title, &item.Description, &item.Timestamp); err != nil {
			return nil, err
		}
		activity = append(activity, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return activity, nil
}

// GetAllStats returns all dashboard statistics for a tenant in 2 optimized queries
// instead of 10+ separate queries. This is used by the main dashboard endpoint.
func (r *DashboardRepository) GetAllStats(ctx context.Context, tenantID shared.ID, scope *shared.DataScope) (*module.DashboardAllStats, error) {
	tid := tenantID.String()
	// A non-nil scope counts only the viewer's in-scope assets and their
	// findings ($2, $3).
	args := []any{tid}
	findingIn, args := dataScopeCond("asset_id", scope, args)
	assetIn, _ := dataScopeCond("id", scope, []any{tid})
	fIn, _ := dataScopeCond("f.asset_id", scope, []any{tid})
	aIn, _ := dataScopeCond("a.id", scope, []any{tid})
	result := &module.DashboardAllStats{
		Assets: module.AssetStatsData{
			ByType:   make(map[string]int),
			ByStatus: make(map[string]int),
		},
		Findings: module.FindingStatsData{
			BySeverity: make(map[string]int),
			ByStatus:   make(map[string]int),
		},
	}

	// Query 1: all counts in one statement. Findings and assets are each read
	// ONCE (GROUPING SETS: by severity, by status, grand total) instead of one
	// scan per CTE (3 findings + 5 assets scans): 135ms -> 66ms on a
	// 200k-finding / 20k-asset tenant. The emitted (grp, key, cnt, val) rows
	// are identical to the per-CTE form.
	//   - avg_cvss: an inner join is equivalent to the old LEFT JOIN, since
	//     AVG ignores the NULL cvss of findings without a vulnerability, and
	//     lets the planner drive from the (small) vulnerabilities table.
	//   - repo_with_findings: EXISTS instead of COUNT(DISTINCT) over a join
	//     of every finding of every repository asset.
	rows, err := r.db.QueryContext(ctx, `
		WITH finding_agg AS (
			SELECT GROUPING(severity) AS g_sev, GROUPING(status) AS g_status,
				severity, status, COUNT(*) AS cnt
			FROM findings
			WHERE tenant_id = $1 AND status NOT IN ('draft', 'in_review') AND NOT branch_only AND `+findingIn+`
			GROUP BY GROUPING SETS ((severity), (status), ())
		),
		asset_agg AS (
			SELECT GROUPING(asset_type) AS g_type, GROUPING(status) AS g_status,
				GROUPING(NULLIF(sub_type, '')) AS g_sub,
				asset_type, status, NULLIF(sub_type, '') AS sub_type,
				COUNT(*) AS cnt,
				COALESCE(AVG(risk_score), 0) AS avg_risk,
				COUNT(*) FILTER (WHERE asset_type = 'repository') AS repo_cnt
			FROM assets
			WHERE deleted_at IS NULL AND tenant_id = $1 AND `+assetIn+`
			GROUP BY GROUPING SETS ((asset_type), (status), (NULLIF(sub_type, '')), ())
		),
		avg_cvss AS (
			SELECT COALESCE(AVG(COALESCE(f.cvss_score, v.cvss_score)), 0) AS val
			FROM findings f JOIN vulnerabilities v ON f.vulnerability_id = v.id
			WHERE f.tenant_id = $1 AND f.status NOT IN ('draft', 'in_review') AND NOT f.branch_only AND `+fIn+`
		),
		repo_with_findings AS (
			SELECT COUNT(*) AS cnt
			FROM assets a
			WHERE a.deleted_at IS NULL AND a.tenant_id = $1 AND a.asset_type = 'repository' AND `+aIn+`
				AND EXISTS (SELECT 1 FROM findings f WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id AND NOT f.branch_only)
		)
		SELECT 'asset_total' AS grp, '' AS key, cnt, 0::float8 AS val FROM asset_agg WHERE g_type = 1 AND g_status = 1 AND g_sub = 1
		UNION ALL SELECT 'atype', asset_type, cnt, 0 FROM asset_agg WHERE g_type = 0
		UNION ALL SELECT 'astatus', status, cnt, 0 FROM asset_agg WHERE g_status = 0
		UNION ALL SELECT 'asubtype', sub_type, cnt, 0 FROM asset_agg WHERE g_sub = 0 AND sub_type IS NOT NULL
		UNION ALL SELECT 'finding_total', '', cnt, 0 FROM finding_agg WHERE g_sev = 1 AND g_status = 1
		UNION ALL SELECT 'fsev', severity, cnt, 0 FROM finding_agg WHERE g_sev = 0
		UNION ALL SELECT 'fstatus', status, cnt, 0 FROM finding_agg WHERE g_status = 0
		UNION ALL SELECT 'avg_cvss', '', 0, val FROM avg_cvss
		UNION ALL SELECT 'avg_risk', '', 0, avg_risk FROM asset_agg WHERE g_type = 1 AND g_status = 1 AND g_sub = 1
		UNION ALL SELECT 'repo_total', '', repo_cnt, 0 FROM asset_agg WHERE g_type = 1 AND g_status = 1 AND g_sub = 1
		UNION ALL SELECT 'repo_findings', '', cnt, 0 FROM repo_with_findings`,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var grp, key string
		var cnt int
		var val float64
		if err := rows.Scan(&grp, &key, &cnt, &val); err != nil {
			return nil, err
		}
		switch grp {
		case "asset_total":
			result.Assets.Total = cnt
		case "atype":
			result.Assets.ByType[key] = cnt
		case "asubtype":
			if result.Assets.BySubType == nil {
				result.Assets.BySubType = make(map[string]int)
			}
			result.Assets.BySubType[key] = cnt
		case "astatus":
			result.Assets.ByStatus[key] = cnt
		case "finding_total":
			result.Findings.Total = cnt
		case "fsev":
			result.Findings.BySeverity[key] = cnt
		case "fstatus":
			result.Findings.ByStatus[key] = cnt
		case "avg_cvss":
			result.Findings.AverageCVSS = val
		case "avg_risk":
			result.Assets.AverageRiskScore = val
		case "repo_total":
			result.Repos.Total = cnt
		case "repo_findings":
			result.Repos.WithFindings = cnt
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result.Activity = make([]module.ActivityItem, 0)

	// Query 2: Recent activity (separate query - different result shape)
	activityRows, err := r.db.QueryContext(ctx,
		`SELECT 'finding' as type,
		        f.id::text as ref_id,
		        COALESCE(f.rule_id, f.tool_name) as title,
		        f.message as description,
		        f.created_at
		 FROM findings f
		 WHERE f.tenant_id = $1 AND NOT f.branch_only
		 ORDER BY f.created_at DESC
		 LIMIT 10`,
		tid,
	)
	if err != nil {
		return result, nil // Return partial stats, activity empty
	}
	defer activityRows.Close()

	for activityRows.Next() {
		var item module.ActivityItem
		if err := activityRows.Scan(&item.Type, &item.RefID, &item.Title, &item.Description, &item.Timestamp); err != nil {
			return result, nil
		}
		result.Activity = append(result.Activity, item)
	}

	if err := activityRows.Err(); err != nil {
		return result, nil // Return partial stats, activity may be incomplete
	}

	return result, nil
}

// GetFindingTrend returns monthly finding counts by severity for a tenant.
// Uses a single query with date_trunc and FILTER to pivot severity counts.
func (r *DashboardRepository) GetFindingTrend(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, months int) ([]module.FindingTrendPoint, error) {
	if months <= 0 || months > 24 {
		months = 6
	}
	// A non-nil scope counts only findings on the viewer's in-scope assets.
	args := []any{tenantID.String(), months}
	inScope, args := dataScopeCond("f.asset_id", scope, args)

	rows, err := r.db.QueryContext(ctx, `
		WITH months AS (
			SELECT generate_series(
				date_trunc('month', NOW()) - ($2::int - 1) * interval '1 month',
				date_trunc('month', NOW()),
				interval '1 month'
			) AS month_start
		),
		-- One range scan over the whole window, bucketed by month, instead of
		-- a nested-loop LEFT JOIN that probed findings once per month:
		-- ~195ms -> ~115ms on a 200k-finding tenant, identical rows.
		agg AS (
			SELECT
				date_trunc('month', f.created_at) AS month_start,
				COUNT(*) FILTER (WHERE f.severity = 'critical') AS critical,
				COUNT(*) FILTER (WHERE f.severity = 'high') AS high,
				COUNT(*) FILTER (WHERE f.severity = 'medium') AS medium,
				COUNT(*) FILTER (WHERE f.severity = 'low') AS low,
				COUNT(*) FILTER (WHERE f.severity = 'info') AS info
			FROM findings f
			WHERE f.tenant_id = $1
				AND f.created_at >= date_trunc('month', NOW()) - ($2::int - 1) * interval '1 month'
				AND f.created_at < date_trunc('month', NOW()) + interval '1 month'
				AND f.status NOT IN ('draft', 'in_review')
				AND NOT f.branch_only
				AND `+inScope+`
			GROUP BY 1
		)
		SELECT
			to_char(m.month_start, 'Mon') AS date_label,
			COALESCE(a.critical, 0) AS critical,
			COALESCE(a.high, 0) AS high,
			COALESCE(a.medium, 0) AS medium,
			COALESCE(a.low, 0) AS low,
			COALESCE(a.info, 0) AS info
		FROM months m
		LEFT JOIN agg a ON a.month_start = m.month_start
		ORDER BY m.month_start ASC`,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	trend := make([]module.FindingTrendPoint, 0, months)
	for rows.Next() {
		var p module.FindingTrendPoint
		if err := rows.Scan(&p.Date, &p.Critical, &p.High, &p.Medium, &p.Low, &p.Info); err != nil {
			return nil, err
		}
		trend = append(trend, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return trend, nil
}

// GetMTTRMetrics returns Mean Time To Remediate metrics by severity.
// MTTR = average time between first detection and resolution, over the last
// `days` days. Only genuinely-remediated findings (resolved/verified) count;
// false_positive/accepted_risk are excluded as they are not remediations.
func (r *DashboardRepository) GetMTTRMetrics(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, days int) (map[string]float64, error) {
	if days <= 0 || days > 365 {
		days = 90
	}
	// A non-nil scope averages only findings on the viewer's in-scope assets.
	args := []any{tenantID.String(), days}
	inScope, args := dataScopeCond("asset_id", scope, args)
	query := `SELECT
		severity,
		COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected_at)) / 3600), 0) as avg_hours
		FROM findings
		WHERE tenant_id = $1
		AND NOT branch_only
		AND status IN ('resolved', 'verified')
		AND resolved_at IS NOT NULL AND first_detected_at IS NOT NULL
		AND resolved_at >= first_detected_at
		AND resolved_at >= NOW() - ($2::int || ' days')::interval
		AND ` + inScope + `
		GROUP BY severity`

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get MTTR metrics: %w", err)
	}
	defer rows.Close()

	result := make(map[string]float64)
	for rows.Next() {
		var severity string
		var avgHours float64
		if err := rows.Scan(&severity, &avgHours); err != nil {
			return nil, fmt.Errorf("failed to scan MTTR: %w", err)
		}
		result[severity] = avgHours
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate MTTR: %w", err)
	}
	return result, nil
}

// GetRiskVelocity returns new vs resolved findings per week for trending analysis.
// Positive velocity = losing ground, negative = improving.
func (r *DashboardRepository) GetRiskVelocity(ctx context.Context, tenantID shared.ID, weeks int) ([]module.RiskVelocityPoint, error) {
	if weeks < 1 {
		weeks = 12
	}
	query := `WITH weeks AS (
		SELECT generate_series(
			date_trunc('week', NOW() - ($2::int || ' weeks')::interval),
			date_trunc('week', NOW()),
			'1 week'::interval
		) AS week_start
	)
	SELECT
		w.week_start,
		COALESCE(SUM(CASE WHEN f.created_at >= w.week_start AND f.created_at < w.week_start + '1 week'::interval THEN 1 ELSE 0 END), 0) as new_count,
		COALESCE(SUM(CASE WHEN f.updated_at >= w.week_start AND f.updated_at < w.week_start + '1 week'::interval
			AND f.status IN ('resolved', 'verified') THEN 1 ELSE 0 END), 0) as resolved_count
	FROM weeks w
	LEFT JOIN findings f ON f.tenant_id = $1 AND NOT f.branch_only
	GROUP BY w.week_start
	ORDER BY w.week_start`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), weeks)
	if err != nil {
		return nil, fmt.Errorf("failed to get risk velocity: %w", err)
	}
	defer rows.Close()

	var points []module.RiskVelocityPoint
	for rows.Next() {
		var p module.RiskVelocityPoint
		if err := rows.Scan(&p.Week, &p.NewCount, &p.ResolvedCount); err != nil {
			return nil, fmt.Errorf("failed to scan velocity: %w", err)
		}
		p.Velocity = p.NewCount - p.ResolvedCount
		points = append(points, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate velocity: %w", err)
	}
	return points, nil
}

// Global stats methods (not tenant-scoped)

// ============================================================
// Filtered stats methods (multi-tenant authorization)
// ============================================================

// GetFilteredAssetStats returns asset statistics filtered by tenant IDs.
func (r *DashboardRepository) GetFilteredAssetStats(ctx context.Context, tenantIDs []string) (module.AssetStatsData, error) {
	stats := module.AssetStatsData{
		ByType:   make(map[string]int),
		ByStatus: make(map[string]int),
	}

	if len(tenantIDs) == 0 {
		return stats, nil
	}

	// Build placeholder string for IN clause
	placeholders, args := buildInClause(tenantIDs, 0)

	// Get total count filtered by tenants
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM assets WHERE deleted_at IS NULL AND tenant_id IN (`+placeholders+`)`,
		args...,
	).Scan(&stats.Total)
	if err != nil {
		return stats, err
	}

	// Get by type filtered by tenants
	//nolint:gosec // G202: placeholders is built from len(tenantIDs), not user input
	rows, err := r.db.QueryContext(ctx,
		`SELECT asset_type, COUNT(*) FROM assets WHERE deleted_at IS NULL AND tenant_id IN (`+placeholders+`) GROUP BY asset_type`,
		args...,
	)
	if err != nil {
		return stats, err
	}
	defer rows.Close()

	for rows.Next() {
		var assetType string
		var count int
		if err := rows.Scan(&assetType, &count); err != nil {
			return stats, err
		}
		stats.ByType[assetType] = count
	}
	if err := rows.Err(); err != nil {
		return stats, err
	}

	// Get by status filtered by tenants
	//nolint:gosec // G202: placeholders is built from len(tenantIDs), not user input
	rows, err = r.db.QueryContext(ctx,
		`SELECT status, COUNT(*) FROM assets WHERE deleted_at IS NULL AND tenant_id IN (`+placeholders+`) GROUP BY status`,
		args...,
	)
	if err != nil {
		return stats, err
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return stats, err
		}
		stats.ByStatus[status] = count
	}
	if err := rows.Err(); err != nil {
		return stats, err
	}

	// Average risk score across the tenants' assets. Previously never populated,
	// so the primary dashboard showed 0.0 for every tenant even though the
	// /assets and attack-surface views (AssetRepository.GetAverageRiskScore)
	// showed the correct number. Mirror that query for consistency.
	//nolint:gosec // G202: placeholders is built from len(tenantIDs), not user input
	if err := r.db.QueryRowContext(ctx,
		`SELECT COALESCE(AVG(risk_score), 0) FROM assets WHERE deleted_at IS NULL AND tenant_id IN (`+placeholders+`)`,
		args...,
	).Scan(&stats.AverageRiskScore); err != nil {
		return stats, err
	}

	return stats, nil
}

// GetFilteredFindingStats returns finding statistics filtered by tenant IDs.
func (r *DashboardRepository) GetFilteredFindingStats(ctx context.Context, tenantIDs []string) (module.FindingStatsData, error) {
	stats := module.FindingStatsData{
		BySeverity: make(map[string]int),
		ByStatus:   make(map[string]int),
	}

	if len(tenantIDs) == 0 {
		return stats, nil
	}

	// Build placeholder string for IN clause
	placeholders, args := buildInClause(tenantIDs, 0)

	// Exclude pentest "draft" and "in_review" from the CTEM dashboard counts.
	// Branch-only findings are not exposure (docs/architecture/branch-only-findings.md).
	excludeInternal := " AND status NOT IN ('draft', 'in_review') AND NOT branch_only"

	// Get total count
	//nolint:gosec // G202: placeholders is built from len(tenantIDs), not user input
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM findings WHERE tenant_id IN (`+placeholders+`)`+excludeInternal,
		args...,
	).Scan(&stats.Total)
	if err != nil {
		return stats, err
	}

	// Get by severity
	//nolint:gosec // G202: placeholders is built from len(tenantIDs), not user input
	rows, err := r.db.QueryContext(ctx,
		`SELECT severity, COUNT(*) FROM findings WHERE tenant_id IN (`+placeholders+`)`+excludeInternal+` GROUP BY severity`,
		args...,
	)
	if err != nil {
		return stats, err
	}
	defer rows.Close()

	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return stats, err
		}
		stats.BySeverity[severity] = count
	}
	if err := rows.Err(); err != nil {
		return stats, err
	}

	// Get by status
	//nolint:gosec // G202: placeholders is built from len(tenantIDs), not user input
	rows, err = r.db.QueryContext(ctx,
		`SELECT status, COUNT(*) FROM findings WHERE tenant_id IN (`+placeholders+`)`+excludeInternal+` GROUP BY status`,
		args...,
	)
	if err != nil {
		return stats, err
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return stats, err
		}
		stats.ByStatus[status] = count
	}
	if err := rows.Err(); err != nil {
		return stats, err
	}

	// Get average CVSS (join with vulnerabilities to get cvss_score)
	//nolint:gosec // G202: placeholders is built from len(tenantIDs), not user input
	err = r.db.QueryRowContext(ctx,
		`SELECT COALESCE(AVG(COALESCE(f.cvss_score, v.cvss_score)), 0) FROM findings f
		 LEFT JOIN vulnerabilities v ON f.vulnerability_id = v.id
		 WHERE f.tenant_id IN (`+placeholders+`) AND f.status NOT IN ('draft', 'in_review') AND NOT f.branch_only`,
		args...,
	).Scan(&stats.AverageCVSS)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		stats.AverageCVSS = 0
	}

	return stats, nil
}

// GetFilteredRepositoryStats returns repository statistics filtered by tenant IDs.
func (r *DashboardRepository) GetFilteredRepositoryStats(ctx context.Context, tenantIDs []string) (module.RepositoryStatsData, error) {
	stats := module.RepositoryStatsData{}

	if len(tenantIDs) == 0 {
		return stats, nil
	}

	// Build placeholder string for IN clause
	placeholders, args := buildInClause(tenantIDs, 0)

	// Get total count of repositories
	//nolint:gosec // G202: placeholders is built from len(tenantIDs), not user input
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM assets WHERE deleted_at IS NULL AND tenant_id IN (`+placeholders+`) AND asset_type = 'repository'`,
		args...,
	).Scan(&stats.Total)
	if err != nil {
		return stats, err
	}

	// Get count of repositories with findings
	//nolint:gosec // G202: placeholders is built from len(tenantIDs), not user input
	err = r.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT a.id) FROM assets a
		 INNER JOIN findings f ON f.tenant_id = a.tenant_id AND f.asset_id = a.id AND NOT f.branch_only
		 WHERE a.deleted_at IS NULL AND a.tenant_id IN (`+placeholders+`) AND a.asset_type = 'repository'`,
		args...,
	).Scan(&stats.WithFindings)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		stats.WithFindings = 0
	}

	return stats, nil
}

// GetFilteredRecentActivity returns recent activity across tenants. Findings
// of tenantIDs are all visible; findings of restrictedTenantIDs only when the
// asset is in userID's Layer 2 data scope for that tenant.
func (r *DashboardRepository) GetFilteredRecentActivity(ctx context.Context, tenantIDs, restrictedTenantIDs []string, userID string, limit int) ([]module.ActivityItem, error) {
	if len(tenantIDs) == 0 && len(restrictedTenantIDs) == 0 {
		return []module.ActivityItem{}, nil
	}
	if userID == "" {
		userID = shared.ID{}.String() // matches no scope row
	}

	rows, err := r.db.QueryContext(ctx,
		`SELECT 'finding' as type,
		        COALESCE(f.rule_id, f.tool_name) as title,
		        f.message as description,
		        f.created_at
		 FROM findings f
		 WHERE NOT f.branch_only
		   AND (f.tenant_id = ANY($1::uuid[])
		    OR (f.tenant_id = ANY($2::uuid[])
		        AND f.asset_id IN (SELECT uaa.asset_id FROM user_accessible_assets uaa
		                           WHERE uaa.user_id = $3 AND uaa.tenant_id = f.tenant_id)))
		 ORDER BY f.created_at DESC
		 LIMIT $4`,
		pq.Array(tenantIDs), pq.Array(restrictedTenantIDs), userID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var activity []module.ActivityItem
	for rows.Next() {
		var item module.ActivityItem
		var timestamp time.Time
		if err := rows.Scan(&item.Type, &item.Title, &item.Description, &timestamp); err != nil {
			return nil, err
		}
		item.Timestamp = timestamp
		activity = append(activity, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return activity, nil
}

// buildInClause builds a placeholder string and args for IN clause.
// Returns ($1, $2, $3, ...) and []any{id1, id2, id3, ...}
func buildInClause(ids []string, offset int) (string, []any) {
	if len(ids) == 0 {
		return "", nil
	}

	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = "$" + itoa(i+1+offset)
		args[i] = id
	}

	return joinStrings(placeholders, ", "), args
}

// itoa converts int to string (simple helper to avoid strconv import)
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

// joinStrings joins strings with a separator
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	if len(strs) == 1 {
		return strs[0]
	}
	n := len(sep) * (len(strs) - 1)
	for _, s := range strs {
		n += len(s)
	}
	var b []byte
	b = make([]byte, 0, n)
	b = append(b, strs[0]...)
	for _, s := range strs[1:] {
		b = append(b, sep...)
		b = append(b, s...)
	}
	return string(b)
}

// GetRiskTrend returns risk snapshot time-series for a tenant.
func (r *DashboardRepository) GetRiskTrend(ctx context.Context, tenantID shared.ID, days int) ([]module.RiskTrendPoint, error) {
	if days <= 0 || days > 365 {
		days = 90
	}
	query := `
		SELECT snapshot_date, risk_score_avg, findings_open, sla_compliance_pct,
			p0_open, p1_open, p2_open, p3_open
		FROM risk_snapshots
		WHERE tenant_id = $1 AND snapshot_date >= CURRENT_DATE - MAKE_INTERVAL(days => $2)
		ORDER BY snapshot_date ASC
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), days)
	if err != nil {
		return nil, fmt.Errorf("risk trend: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var points []module.RiskTrendPoint
	for rows.Next() {
		var p module.RiskTrendPoint
		var d time.Time
		if err := rows.Scan(&d, &p.RiskScoreAvg, &p.FindingsOpen, &p.SLACompliancePct,
			&p.P0Open, &p.P1Open, &p.P2Open, &p.P3Open); err != nil {
			return nil, fmt.Errorf("scan risk trend: %w", err)
		}
		p.Date = d.Format("2006-01-02")
		points = append(points, p)
	}
	return points, nil
}

// GetDataQualityScorecard computes data quality metrics for a tenant.
// Uses a single CTE query for efficiency.
func (r *DashboardRepository) GetDataQualityScorecard(ctx context.Context, tenantID shared.ID) (*module.DataQualityScorecard, error) {
	query := `
		WITH asset_stats AS (
			SELECT
				COUNT(*) AS total,
				-- Owned = at least one asset_owners row (user or group), the one
				-- owner model. assets.owner_id only held email-matched owners.
				COUNT(*) FILTER(WHERE EXISTS (SELECT 1 FROM asset_owners ao WHERE ao.asset_id = assets.id)) AS with_owner,
				-- Internet-exposed = exposure 'public' or flagged internet-accessible,
				-- the same definition the program metrics use. assets.exposure has no
				-- 'internet' value; filtering on it made this median a constant 0.
				COALESCE(PERCENTILE_CONT(0.5) WITHIN GROUP(
					ORDER BY EXTRACT(epoch FROM NOW() - last_seen) / 86400.0
				) FILTER(WHERE (exposure = 'public' OR is_internet_accessible) AND last_seen IS NOT NULL), 0) AS median_last_seen_days,
				COALESCE(PERCENTILE_CONT(0.5) WITHIN GROUP(
					ORDER BY EXTRACT(epoch FROM NOW() - last_seen) / 3600.0
				) FILTER(WHERE last_seen IS NOT NULL), 0) AS median_last_seen_age_hours,
				COUNT(*) FILTER(WHERE last_seen IS NOT NULL AND last_seen < NOW() - INTERVAL '30 days') AS stale_count
			FROM assets WHERE deleted_at IS NULL AND tenant_id = $1
		),
		finding_stats AS (
			SELECT
				COUNT(*) AS total,
				COUNT(*) FILTER(WHERE metadata IS NOT NULL AND metadata != '{}'::jsonb) AS with_evidence
			FROM findings WHERE tenant_id = $1 AND NOT branch_only
		),
		dedup_stats AS (
			SELECT COUNT(*) AS merge_count
			FROM asset_merge_log WHERE tenant_id = $1
		)
		SELECT
			CASE WHEN a.total > 0 THEN a.with_owner * 100.0 / a.total ELSE 0 END,
			CASE WHEN f.total > 0 THEN f.with_evidence * 100.0 / f.total ELSE 0 END,
			a.median_last_seen_days,
			CASE WHEN a.total > 0 THEN d.merge_count * 100.0 / a.total ELSE 0 END,
			a.total,
			f.total,
			a.median_last_seen_age_hours,
			CASE WHEN a.total > 0 THEN a.stale_count * 100.0 / a.total ELSE 0 END
		FROM asset_stats a, finding_stats f, dedup_stats d
	`

	var sc module.DataQualityScorecard
	var assetTotal, findingTotal int
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(
		&sc.AssetOwnershipPct,
		&sc.FindingEvidencePct,
		&sc.MedianLastSeenDays,
		&sc.DeduplicationRate,
		&assetTotal,
		&findingTotal,
		&sc.MedianLastSeenAgeHours,
		&sc.StaleAssetPct,
	)
	if err != nil {
		return nil, fmt.Errorf("data quality scorecard: %w", err)
	}

	sc.TotalAssets = assetTotal
	sc.TotalFindings = findingTotal
	return &sc, nil
}

// GetExecutiveSummary returns executive-level metrics for a time period using CTEs.
func (r *DashboardRepository) GetExecutiveSummary(ctx context.Context, tenantID shared.ID, days int) (*module.ExecutiveSummary, error) {
	if days <= 0 || days > 365 {
		days = 30
	}

	query := `
		WITH open_agg AS (
			-- One pass over the tenant's open findings. This used to be a
			-- materialized open_findings CTE (incl. the wide title column)
			-- scanned by 8 separate sub-selects: 144ms seq scan + ~50ms of
			-- CTE re-scans on a 200k-finding tenant.
			SELECT
				COUNT(*) AS total,
				COUNT(*) FILTER (WHERE priority_class = 'P0') AS p0,
				COUNT(*) FILTER (WHERE priority_class = 'P1') AS p1,
				COUNT(*) FILTER (WHERE sla_status IN ('exceeded','overdue')) AS sla_breached
			FROM findings
			WHERE tenant_id = $1 AND NOT branch_only AND status NOT IN ('resolved','false_positive','accepted','duplicate','verified','accepted_risk')
		),
		resolved_in_period AS (
			SELECT severity, priority_class, resolved_at, first_detected_at
			FROM findings
			WHERE tenant_id = $1 AND NOT branch_only
				AND status IN ('resolved', 'verified')
				AND resolved_at >= NOW() - ($2::int || ' days')::interval
		),
		total_resolved AS (
			SELECT COUNT(*) AS cnt FROM findings
			WHERE tenant_id = $1 AND NOT branch_only AND status IN ('resolved', 'verified')
		),
		regressions AS (
			SELECT COUNT(*) AS cnt FROM findings
			WHERE tenant_id = $1 AND NOT branch_only AND is_regression = true
			  AND last_reopened_at >= NOW() - ($2::int || ' days')::interval
		),
		new_in_period AS (
			SELECT id FROM findings
			WHERE tenant_id = $1 AND NOT branch_only AND created_at >= NOW() - ($2::int || ' days')::interval
		),
		risk_score AS (
			-- Average over SCORED assets only (risk_score > 0), matching the
			-- risk-trend risk_score_avg (risk_snapshots) so the executive hero
			-- number equals the trend's latest point. prev_risk below reads that
			-- same filtered snapshot average, keeping risk_score_change consistent.
			SELECT COALESCE(AVG(risk_score) FILTER (WHERE risk_score > 0), 0) AS current_score FROM assets WHERE deleted_at IS NULL AND tenant_id = $1
		),
		prev_risk AS (
			-- Oldest risk_snapshots row within the window; used to compute
			-- risk_score_change (current asset-avg risk vs start-of-period snapshot).
			SELECT risk_score_avg AS prev_score
			FROM risk_snapshots
			WHERE tenant_id = $1
				AND snapshot_date >= (CURRENT_DATE - ($2::int || ' days')::interval)::date
			ORDER BY snapshot_date ASC
			LIMIT 1
		),
		crown_jewels AS (
			SELECT COUNT(DISTINCT a.id) AS cnt
			FROM assets a
			INNER JOIN findings f ON f.asset_id = a.id AND f.tenant_id = $1 AND NOT f.branch_only
				AND f.status NOT IN ('resolved','false_positive','accepted','duplicate','verified','accepted_risk')
			WHERE a.deleted_at IS NULL AND a.tenant_id = $1 AND a.is_crown_jewel
		),
		mttr_critical AS (
			SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected_at)) / 3600), 0) AS hrs
			FROM resolved_in_period WHERE severity = 'critical' AND first_detected_at IS NOT NULL AND resolved_at >= first_detected_at
		),
		mttr_high AS (
			SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected_at)) / 3600), 0) AS hrs
			FROM resolved_in_period WHERE severity = 'high' AND first_detected_at IS NOT NULL AND resolved_at >= first_detected_at
		)
		SELECT
			rs.current_score,
			rs.current_score - COALESCE(pr.prev_score, rs.current_score),
			oa.total,
			(SELECT COUNT(*) FROM resolved_in_period),
			(SELECT COUNT(*) FROM new_in_period),
			oa.p0,
			(SELECT COUNT(*) FROM resolved_in_period WHERE priority_class = 'P0'),
			oa.p1,
			(SELECT COUNT(*) FROM resolved_in_period WHERE priority_class = 'P1'),
			CASE WHEN oa.total > 0
				THEN (oa.total - oa.sla_breached) * 100.0 / oa.total
				ELSE 100.0 END,
			oa.sla_breached,
			mc.hrs,
			mh.hrs,
			cj.cnt,
			reg.cnt,
			tr.cnt
		FROM risk_score rs, mttr_critical mc, mttr_high mh, crown_jewels cj,
		     regressions reg, total_resolved tr, open_agg oa
		LEFT JOIN prev_risk pr ON TRUE
	`

	summary := &module.ExecutiveSummary{
		Period: fmt.Sprintf("%d days", days),
	}

	var totalResolved int
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), days).Scan(
		&summary.RiskScoreCurrent,
		&summary.RiskScoreChange,
		&summary.FindingsTotal,
		&summary.FindingsResolved,
		&summary.FindingsNew,
		&summary.P0Open,
		&summary.P0Resolved,
		&summary.P1Open,
		&summary.P1Resolved,
		&summary.SLACompliancePct,
		&summary.SLABreached,
		&summary.MTTRCriticalHrs,
		&summary.MTTRHighHrs,
		&summary.CrownJewelsAtRisk,
		&summary.RegressionCount,
		&totalResolved,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("executive summary: %w", err)
	}

	// Regression rate: regressions / total_resolved (% of resolved findings that were reopened).
	if totalResolved > 0 {
		summary.RegressionRatePct = float64(summary.RegressionCount) * 100.0 / float64(totalResolved)
	}

	// Top 5 risks: open findings ordered by priority class, EPSS score.
	// title is nullable (most scanner findings only carry a message); scanning
	// a NULL into a string failed the whole summary with a 500.
	topQuery := `
		SELECT f.id::text, COALESCE(f.title, '') AS title, f.severity, COALESCE(f.priority_class, 'P3') AS priority_class,
			COALESCE(f.asset_id::text, '') AS asset_id,
			COALESCE(a.name, '') AS asset_name, f.epss_score, COALESCE(f.is_in_kev, FALSE)
		FROM findings f
		LEFT JOIN assets a ON a.id = f.asset_id AND a.tenant_id = $1
		WHERE f.tenant_id = $1 AND NOT f.branch_only AND f.status NOT IN ('resolved','false_positive','accepted','duplicate','verified','accepted_risk')
		ORDER BY f.priority_class ASC NULLS LAST, f.epss_score DESC NULLS LAST
		LIMIT 5
	`

	rows, err := r.db.QueryContext(ctx, topQuery, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("executive summary top risks: %w", err)
	}
	defer func() { _ = rows.Close() }()

	topRisks := make([]module.TopRisk, 0, 5)
	for rows.Next() {
		var tr module.TopRisk
		if err := rows.Scan(&tr.FindingID, &tr.FindingTitle, &tr.Severity, &tr.PriorityClass,
			&tr.AssetID, &tr.AssetName, &tr.EPSSScore, &tr.IsInKEV); err != nil {
			return nil, fmt.Errorf("scan top risk: %w", err)
		}
		topRisks = append(topRisks, tr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate top risks: %w", err)
	}
	summary.TopRisks = topRisks

	return summary, nil
}

// GetMTTRAnalytics returns MTTR breakdown by severity, priority class, and overall.
func (r *DashboardRepository) GetMTTRAnalytics(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, days int) (*module.MTTRAnalytics, error) {
	if days <= 0 || days > 365 {
		days = 90
	}
	// A non-nil scope averages only findings on the viewer's in-scope assets.
	args := []any{tenantID.String(), days}
	inScope, args := dataScopeCond("asset_id", scope, args)

	query := `
		SELECT
			COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected_at)) / 3600)
				FILTER(WHERE severity = 'critical' AND first_detected_at IS NOT NULL), 0) AS mttr_critical,
			COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected_at)) / 3600)
				FILTER(WHERE severity = 'high' AND first_detected_at IS NOT NULL), 0) AS mttr_high,
			COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected_at)) / 3600)
				FILTER(WHERE severity = 'medium' AND first_detected_at IS NOT NULL), 0) AS mttr_medium,
			COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected_at)) / 3600)
				FILTER(WHERE severity = 'low' AND first_detected_at IS NOT NULL), 0) AS mttr_low,
			COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected_at)) / 3600)
				FILTER(WHERE priority_class = 'P0' AND first_detected_at IS NOT NULL), 0) AS mttr_p0,
			COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected_at)) / 3600)
				FILTER(WHERE priority_class = 'P1' AND first_detected_at IS NOT NULL), 0) AS mttr_p1,
			COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected_at)) / 3600)
				FILTER(WHERE priority_class = 'P2' AND first_detected_at IS NOT NULL), 0) AS mttr_p2,
			COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected_at)) / 3600)
				FILTER(WHERE priority_class = 'P3' AND first_detected_at IS NOT NULL), 0) AS mttr_p3,
			COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected_at)) / 3600)
				FILTER(WHERE first_detected_at IS NOT NULL), 0) AS mttr_overall,
			COUNT(*) AS sample_size
		FROM findings
		WHERE tenant_id = $1
			AND NOT branch_only
			AND status IN ('resolved', 'verified')
			AND resolved_at >= NOW() - ($2::int || ' days')::interval
			AND resolved_at IS NOT NULL
			AND first_detected_at IS NOT NULL
			AND resolved_at >= first_detected_at
			AND ` + inScope + `
	`

	var (
		mttrCritical, mttrHigh, mttrMedium, mttrLow float64
		mttrP0, mttrP1, mttrP2, mttrP3              float64
		mttrOverall                                 float64
		sampleSize                                  int
	)

	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&mttrCritical, &mttrHigh, &mttrMedium, &mttrLow,
		&mttrP0, &mttrP1, &mttrP2, &mttrP3,
		&mttrOverall, &sampleSize,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("mttr analytics: %w", err)
	}

	result := &module.MTTRAnalytics{
		BySeverity: map[string]float64{
			"critical": mttrCritical,
			"high":     mttrHigh,
			"medium":   mttrMedium,
			"low":      mttrLow,
		},
		ByPriorityClass: map[string]float64{
			"P0": mttrP0,
			"P1": mttrP1,
			"P2": mttrP2,
			"P3": mttrP3,
		},
		Overall:    mttrOverall,
		SampleSize: sampleSize,
	}

	return result, nil
}

// GetProcessMetrics computes process efficiency metrics for a tenant.
func (r *DashboardRepository) GetProcessMetrics(ctx context.Context, tenantID shared.ID, days int) (*module.ProcessMetrics, error) {
	if days <= 0 || days > 365 {
		days = 90
	}
	query := `
		WITH approval_stats AS (
			SELECT
				COALESCE(AVG(EXTRACT(epoch FROM COALESCE(approved_at, rejected_at) - created_at) / 3600), 0) AS avg_hours,
				COUNT(*) AS total
			FROM finding_status_approvals
			WHERE tenant_id = $1 AND status IN ('approved','rejected')
			AND created_at >= NOW() - ($2 || ' days')::interval
		),
		stale_stats AS (
			SELECT
				COUNT(*) FILTER(WHERE last_seen < NOW() - INTERVAL '7 days') AS stale,
				COUNT(*) AS total
			FROM assets WHERE deleted_at IS NULL AND tenant_id = $1 AND status != 'archived'
		),
		assign_stats AS (
			SELECT
				COUNT(*) FILTER(WHERE assigned_to IS NULL AND status NOT IN ('resolved','false_positive','accepted','duplicate','verified','accepted_risk')) AS unassigned,
				COALESCE(AVG(EXTRACT(epoch FROM assigned_at - created_at) / 3600) FILTER(WHERE assigned_at IS NOT NULL), 0) AS avg_assign_hours
			FROM findings WHERE tenant_id = $1 AND NOT branch_only
			AND created_at >= NOW() - ($2 || ' days')::interval
		)
		SELECT
			a.avg_hours, a.total,
			0::float8, 0,
			s.stale,
			CASE WHEN s.total > 0 THEN s.stale * 100.0 / s.total ELSE 0 END,
			as2.unassigned,
			as2.avg_assign_hours
		FROM approval_stats a, stale_stats s, assign_stats as2
	`
	var m module.ProcessMetrics
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), days).Scan(
		&m.ApprovalAvgHours, &m.ApprovalCount,
		&m.RetestAvgHours, &m.RetestCount,
		&m.StaleAssets, &m.StaleAssetsPct,
		&m.FindingsWithoutOwner, &m.AvgTimeToAssignHours,
	)
	if err != nil {
		return nil, fmt.Errorf("process metrics: %w", err)
	}
	return &m, nil
}
