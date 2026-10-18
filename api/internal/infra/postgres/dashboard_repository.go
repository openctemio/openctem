package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/filterspec"
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
		BySeverity: newSeverityCounts(),
		ByStatus:   make(map[string]int),
	}

	// Single query with CTEs — replaces 4 separate queries.
	// Excludes pentest "draft" and "in_review" statuses (Phase 4 internal workflow,
	// hidden from the CTEM dashboard until reviewer approves).
	query := `
		WITH base AS (
			SELECT id, severity, status, vulnerability_id, cvss_score FROM findings
			WHERE tenant_id = $1 AND status NOT IN ('draft', 'in_review') AND NOT branch_only` + findingExcl(ctx, "asset_id") + `
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
			stats.BySeverity[vulnerability.SeverityBucket(key)] += int(value)
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
		`SELECT COUNT(*) FROM assets WHERE deleted_at IS NULL AND tenant_id = $1`+programAssetExcl(ctx, "")+` AND asset_type = 'repository'`,
		tenantID.String(),
	).Scan(&stats.Total)
	if err != nil {
		return stats, err
	}

	// Get count of repositories with findings
	err = r.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT a.id) FROM assets a
		 INNER JOIN findings f ON f.tenant_id = a.tenant_id AND f.asset_id = a.id AND NOT f.branch_only`+findingExcl(ctx, "f.asset_id")+`
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
		 WHERE f.tenant_id = $1 AND NOT f.branch_only`+findingExcl(ctx, "f.asset_id")+publishedExcl("f")+` AND `+scopeCond+`
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
			BySeverity: newSeverityCounts(),
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
				severity, status, COUNT(*) AS cnt,
				COUNT(*) FILTER (WHERE `+vulnerability.OpenStatusSQL("status")+`) AS open_cnt,
				COUNT(*) FILTER (WHERE `+vulnerability.OpenStatusSQL("status")+` AND sla_status IN ('exceeded','overdue')) AS overdue_cnt
			FROM findings
			WHERE tenant_id = $1 AND status NOT IN ('draft', 'in_review') AND NOT branch_only`+findingExcl(ctx, "asset_id")+` AND `+findingIn+`
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
			WHERE deleted_at IS NULL AND tenant_id = $1 AND `+assetIn+MetricsInventorySQL(ctx, "assets.id")+programAssetExcl(ctx, "")+`
			GROUP BY GROUPING SETS ((asset_type), (status), (NULLIF(sub_type, '')), ())
		),
		avg_cvss AS (
			SELECT COALESCE(AVG(COALESCE(f.cvss_score, v.cvss_score)), 0) AS val
			FROM findings f JOIN vulnerabilities v ON f.vulnerability_id = v.id
			WHERE f.tenant_id = $1 AND f.status NOT IN ('draft', 'in_review') AND NOT f.branch_only`+findingExcl(ctx, "f.asset_id")+` AND `+fIn+`
		),
		repo_with_findings AS (
			SELECT COUNT(*) AS cnt
			FROM assets a
			WHERE a.deleted_at IS NULL AND a.tenant_id = $1 AND a.asset_type = 'repository' AND `+aIn+`
				AND EXISTS (SELECT 1 FROM findings f WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.id AND NOT f.branch_only`+findingExcl(ctx, "f.asset_id")+`)
		)
		SELECT 'asset_total' AS grp, '' AS key, cnt, 0::float8 AS val FROM asset_agg WHERE g_type = 1 AND g_status = 1 AND g_sub = 1
		UNION ALL SELECT 'atype', asset_type, cnt, 0 FROM asset_agg WHERE g_type = 0
		UNION ALL SELECT 'astatus', status, cnt, 0 FROM asset_agg WHERE g_status = 0
		UNION ALL SELECT 'asubtype', sub_type, cnt, 0 FROM asset_agg WHERE g_sub = 0 AND sub_type IS NOT NULL
		UNION ALL SELECT 'finding_total', '', open_cnt, 0 FROM finding_agg WHERE g_sev = 1 AND g_status = 1
		UNION ALL SELECT 'finding_overdue', '', overdue_cnt, 0 FROM finding_agg WHERE g_sev = 1 AND g_status = 1
		UNION ALL SELECT 'fsev', severity, open_cnt, 0 FROM finding_agg WHERE g_sev = 0
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
		case "finding_overdue":
			result.Findings.Overdue = cnt
		case "fsev":
			result.Findings.BySeverity[vulnerability.SeverityBucket(key)] += cnt
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
		 WHERE f.tenant_id = $1 AND NOT f.branch_only`+findingExcl(ctx, "f.asset_id")+publishedExcl("f")+`
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
				COUNT(*) FILTER (WHERE f.severity IN ('info', 'none')) AS info
			FROM findings f
			WHERE f.tenant_id = $1
				AND f.created_at >= date_trunc('month', NOW()) - ($2::int - 1) * interval '1 month'
				AND f.created_at < date_trunc('month', NOW()) + interval '1 month'
				AND f.status NOT IN ('draft', 'in_review')
				AND NOT f.branch_only`+findingExcl(ctx, "f.asset_id")+`
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
// `days` days. Only remediated findings count (vulnerability.RemediatedSQL):
// dispositions and obsolete closures (asset retired, source removed, rule
// changed) are not remediations.
func (r *DashboardRepository) GetMTTRMetrics(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, days int) (map[string]float64, error) {
	if days <= 0 || days > 365 {
		days = 90
	}
	// A non-nil scope averages only findings on the viewer's in-scope assets.
	args := []any{tenantID.String(), days}
	inScope, args := dataScopeCond("asset_id", scope, args)
	// none (CVSS 0.0) is averaged inside info, matching every by-severity count.
	query := `SELECT
		CASE WHEN severity = 'none' THEN 'info' ELSE severity END AS sev,
		COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - first_detected_at)) / 3600), 0) as avg_hours
		FROM findings
		WHERE tenant_id = $1
		AND NOT branch_only` + findingExcl(ctx, "asset_id") + `
		AND ` + vulnerability.RemediatedSQL("") + `
		AND resolved_at IS NOT NULL AND first_detected_at IS NOT NULL
		AND resolved_at >= first_detected_at
		AND resolved_at >= NOW() - ($2::int || ' days')::interval
		AND ` + inScope + `
		GROUP BY 1`

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

// dashboardScope returns the SQL predicate builder and extra arguments of a
// dashboard query that numbers its own placeholders: in(col) is "col is in the
// caller's data scope" (TRUE without a scope), args follow the query's own
// arguments, first is the first free $N. The scope uses $first and $first+1.
func dashboardScope(scope *shared.DataScope, first int) (in func(col string) string, args []any) {
	if scope == nil {
		return func(string) string { return "TRUE" }, nil
	}
	_, args = dataScopeCondAt("x", scope, first)
	return func(col string) string {
		c, _ := dataScopeCondAt(col, scope, first)
		return c
	}, args
}

// GetRiskVelocity returns new vs resolved findings per week for trending analysis.
// A fix counts in the week of its resolved_at, never of a later edit (updated_at).
// Positive velocity = losing ground, negative = improving.
func (r *DashboardRepository) GetRiskVelocity(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, weeks int) ([]module.RiskVelocityPoint, error) {
	if weeks < 1 {
		weeks = 12
	}
	// A non-nil scope counts only findings on the viewer's in-scope assets.
	inScope, scopeArgs := dashboardScope(scope, 3)
	// Two range scans over the window (created_at, resolved_at), each bucketed
	// by week, then joined to the week series; this replaces a join of every
	// week with every finding of the tenant. Both scans read the same rows the
	// per-week join did: published findings, not branch-only, in scope.
	rowFilter := `f.tenant_id = $1 AND NOT f.branch_only` + findingExcl(ctx, "f.asset_id") + publishedExcl("f") + ` AND ` + inScope("f.asset_id")
	query := `WITH weeks AS (
		SELECT generate_series(
			date_trunc('week', NOW() - ($2::int || ' weeks')::interval),
			date_trunc('week', NOW()),
			'1 week'::interval
		) AS week_start
	),
	bounds AS (
		SELECT date_trunc('week', NOW() - ($2::int || ' weeks')::interval) AS lo,
			date_trunc('week', NOW()) + '1 week'::interval AS hi
	),
	created AS (
		SELECT date_trunc('week', f.created_at) AS wk, COUNT(*) AS n
		FROM findings f, bounds b
		WHERE ` + rowFilter + ` AND f.created_at >= b.lo AND f.created_at < b.hi
		GROUP BY 1
	),
	resolved AS (
		SELECT date_trunc('week', f.resolved_at) AS wk, COUNT(*) AS n
		FROM findings f, bounds b
		WHERE ` + rowFilter + ` AND f.resolved_at >= b.lo AND f.resolved_at < b.hi
			AND ` + vulnerability.RemediatedSQL("f") + `
		GROUP BY 1
	)
	SELECT w.week_start, COALESCE(c.n, 0), COALESCE(r.n, 0)
	FROM weeks w
	LEFT JOIN created c ON c.wk = w.week_start
	LEFT JOIN resolved r ON r.wk = w.week_start
	ORDER BY w.week_start`

	rows, err := r.db.QueryContext(ctx, query, append([]any{tenantID.String(), weeks}, scopeArgs...)...)
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
			p0_open, p1_open, p2_open, p3_open, risk_version, priority_version
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
		var rv, pv sql.NullInt64
		if err := rows.Scan(&d, &p.RiskScoreAvg, &p.FindingsOpen, &p.SLACompliancePct,
			&p.P0Open, &p.P1Open, &p.P2Open, &p.P3Open, &rv, &pv); err != nil {
			return nil, fmt.Errorf("scan risk trend: %w", err)
		}
		p.Date = d.Format("2006-01-02")
		if rv.Valid {
			v := rv.Int64
			p.RiskVersion = &v
		}
		if pv.Valid {
			v := pv.Int64
			p.PriorityVersion = &v
		}
		points = append(points, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate risk trend: %w", err)
	}
	if len(points) == 0 {
		return points, nil
	}
	changes, err := r.scoringChangesSince(ctx, tenantID, days)
	if err != nil {
		return nil, err
	}
	attachScoringChanges(points, changes)
	return points, nil
}

// scoringChangesSince lists the tenant's and the platform's scoring changes
// of the trend window, oldest first.
func (r *DashboardRepository) scoringChangesSince(ctx context.Context, tenantID shared.ID, days int) ([]module.ScoringChangeMarker, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT created_at, kind, source, summary FROM scoring_changes
		WHERE (tenant_id = $1 OR tenant_id IS NULL)
		  AND created_at >= CURRENT_DATE - MAKE_INTERVAL(days => $2)
		ORDER BY created_at, id`, tenantID.String(), days)
	if err != nil {
		return nil, fmt.Errorf("scoring changes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []module.ScoringChangeMarker
	for rows.Next() {
		var m module.ScoringChangeMarker
		var at time.Time
		if err := rows.Scan(&at, &m.Kind, &m.Source, &m.Summary); err != nil {
			return nil, fmt.Errorf("scan scoring change: %w", err)
		}
		m.Date = at.UTC().Format("2006-01-02")
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scoring changes: %w", err)
	}
	return out, nil
}

// attachScoringChanges puts each change on the first point dated on or after
// it (a day without a snapshot moves the marker to the next one); a change
// after the last point stays on the last point.
func attachScoringChanges(points []module.RiskTrendPoint, changes []module.ScoringChangeMarker) {
	i := 0
	for _, c := range changes {
		for i < len(points)-1 && points[i].Date < c.Date {
			i++
		}
		points[i].ScoringChanges = append(points[i].ScoringChanges, c)
	}
}

// GetDataQualityScorecard computes data quality metrics for a tenant.
// Uses a single CTE query for efficiency.
func (r *DashboardRepository) GetDataQualityScorecard(ctx context.Context, tenantID shared.ID, scope *shared.DataScope) (*module.DataQualityScorecard, error) {
	// A non-nil scope scores only the viewer's in-scope assets and their
	// findings; the merge log is not asset-scoped, so a scoped viewer's
	// deduplication rate is not reported (0).
	inScope, scopeArgs := dashboardScope(scope, 2)
	dedupSQL := `SELECT COUNT(*) AS merge_count
			FROM asset_merge_log WHERE tenant_id = $1`
	if scope.Restricted() {
		dedupSQL = `SELECT 0::bigint AS merge_count`
	}
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
			FROM assets WHERE deleted_at IS NULL AND tenant_id = $1` + programAssetExcl(ctx, "") + ` AND ` + inScope("assets.id") + `
		),
		finding_stats AS (
			SELECT
				COUNT(*) AS total,
				COUNT(*) FILTER(WHERE metadata IS NOT NULL AND metadata != '{}'::jsonb) AS with_evidence
			FROM findings WHERE tenant_id = $1 AND NOT branch_only` + findingExcl(ctx, "asset_id") + ` AND ` + inScope("asset_id") + `
		),
		dedup_stats AS (
			` + dedupSQL + `
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
	err := r.db.QueryRowContext(ctx, query, append([]any{tenantID.String()}, scopeArgs...)...).Scan(
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
func (r *DashboardRepository) GetExecutiveSummary(ctx context.Context, tenantID shared.ID, scope, rowScope *shared.DataScope, days int) (*module.ExecutiveSummary, error) {
	if days <= 0 || days > 365 {
		days = 30
	}
	// A non-nil scope counts only findings on the viewer's in-scope assets, and
	// the assets themselves; the stored risk history is tenant-wide, so a
	// scoped viewer gets no score change.
	inScope, scopeArgs := dashboardScope(scope, 3)
	prevRisk := ""
	if scope.Restricted() {
		prevRisk = " AND FALSE"
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
				COUNT(*) FILTER (WHERE sla_status IN ('exceeded','overdue')) AS sla_breached,
				COUNT(*) FILTER (WHERE sla_status IS NOT NULL AND sla_status <> 'not_applicable') AS sla_tracked
			FROM findings
			WHERE tenant_id = $1 AND NOT branch_only` + findingExcl(ctx, "asset_id") + ` AND ` + inScope("asset_id") + ` AND ` + vulnerability.OpenStatusSQL("status") + `
		),
		resolved_in_period AS (
			SELECT severity, priority_class, resolved_at, first_detected_at
			FROM findings
			WHERE tenant_id = $1 AND NOT branch_only` + findingExcl(ctx, "asset_id") + ` AND ` + inScope("asset_id") + `
				AND ` + vulnerability.RemediatedSQL("") + `
				AND resolved_at >= NOW() - ($2::int || ' days')::interval
		),
		total_resolved AS (
			SELECT COUNT(*) AS cnt FROM findings
			WHERE tenant_id = $1 AND NOT branch_only` + findingExcl(ctx, "asset_id") + ` AND ` + inScope("asset_id") + ` AND ` + vulnerability.RemediatedSQL("") + `
		),
		regressions AS (
			SELECT COUNT(*) AS cnt FROM findings
			WHERE tenant_id = $1 AND NOT branch_only` + findingExcl(ctx, "asset_id") + ` AND ` + inScope("asset_id") + ` AND is_regression = true
			  AND last_reopened_at >= NOW() - ($2::int || ' days')::interval
		),
		new_in_period AS (
			SELECT id FROM findings
			WHERE tenant_id = $1 AND NOT branch_only` + findingExcl(ctx, "asset_id") + publishedExcl("findings") + ` AND ` + inScope("asset_id") + ` AND created_at >= NOW() - ($2::int || ' days')::interval
		),
		risk_score AS (
			-- Average over SCORED assets only (risk_score > 0), matching the
			-- risk-trend risk_score_avg (risk_snapshots) so the executive hero
			-- number equals the trend's latest point. prev_risk below reads that
			-- same filtered snapshot average, keeping risk_score_change consistent.
			SELECT COALESCE(AVG(risk_score) FILTER (WHERE risk_score > 0), 0) AS current_score FROM assets WHERE deleted_at IS NULL AND tenant_id = $1` + programAssetExcl(ctx, "") + ` AND ` + inScope("assets.id") + `
		),
		prev_risk AS (
			-- Oldest risk_snapshots row within the window; used to compute
			-- risk_score_change (current asset-avg risk vs start-of-period snapshot).
			SELECT risk_score_avg AS prev_score
			FROM risk_snapshots
			WHERE tenant_id = $1` + prevRisk + `
				AND snapshot_date >= (CURRENT_DATE - ($2::int || ' days')::interval)::date
			ORDER BY snapshot_date ASC
			LIMIT 1
		),
		crown_jewels AS (
			SELECT COUNT(DISTINCT a.id) AS cnt
			FROM assets a
			INNER JOIN findings f ON f.asset_id = a.id AND f.tenant_id = $1 AND NOT f.branch_only` + findingExcl(ctx, "f.asset_id") + ` AND ` + inScope("f.asset_id") + `
				AND ` + vulnerability.OpenStatusSQL("f.status") + `
			WHERE a.deleted_at IS NULL AND a.tenant_id = $1 AND a.is_crown_jewel
		),
		mttr_hours AS (
			SELECT severity, EXTRACT(EPOCH FROM (resolved_at - first_detected_at)) / 3600 AS hrs
			FROM resolved_in_period
			WHERE severity IN ('critical', 'high') AND first_detected_at IS NOT NULL AND resolved_at >= first_detected_at
		),
		mttr_critical AS (
			SELECT AVG(hrs) AS mean, PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY hrs) AS med,
				PERCENTILE_CONT(0.9) WITHIN GROUP (ORDER BY hrs) AS p90, COUNT(*) AS n
			FROM mttr_hours WHERE severity = 'critical'
		),
		mttr_high AS (
			SELECT AVG(hrs) AS mean, PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY hrs) AS med,
				PERCENTILE_CONT(0.9) WITHIN GROUP (ORDER BY hrs) AS p90, COUNT(*) AS n
			FROM mttr_hours WHERE severity = 'high'
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
			CASE WHEN oa.sla_tracked > 0
				THEN (oa.sla_tracked - oa.sla_breached) * 100.0 / oa.sla_tracked
				END,
			oa.sla_breached,
			mc.mean, mc.med, mc.p90, mc.n,
			mh.mean, mh.med, mh.p90, mh.n,
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
	var sla, mcMean, mcMed, mcP90, mhMean, mhMed, mhP90 sql.NullFloat64
	err := r.db.QueryRowContext(ctx, query, append([]any{tenantID.String(), days}, scopeArgs...)...).Scan(
		&summary.RiskScoreCurrent,
		&summary.RiskScoreChange,
		&summary.FindingsTotal,
		&summary.FindingsResolved,
		&summary.FindingsNew,
		&summary.P0Open,
		&summary.P0Resolved,
		&summary.P1Open,
		&summary.P1Resolved,
		&sla,
		&summary.SLABreached,
		&mcMean, &mcMed, &mcP90, &summary.MTTRCriticalSample,
		&mhMean, &mhMed, &mhP90, &summary.MTTRHighSample,
		&summary.CrownJewelsAtRisk,
		&summary.RegressionCount,
		&totalResolved,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("executive summary: %w", err)
	}

	summary.SLACompliancePct = nullFloatPtr(sla)
	summary.MTTRCriticalHrs, summary.MTTRCriticalMedianHrs, summary.MTTRCriticalP90Hrs = nullFloatPtr(mcMean), nullFloatPtr(mcMed), nullFloatPtr(mcP90)
	summary.MTTRHighHrs, summary.MTTRHighMedianHrs, summary.MTTRHighP90Hrs = nullFloatPtr(mhMean), nullFloatPtr(mhMed), nullFloatPtr(mhP90)

	// Regression rate: regressions / total_resolved (% of resolved findings that were reopened).
	if totalResolved > 0 {
		summary.RegressionRatePct = float64(summary.RegressionCount) * 100.0 / float64(totalResolved)
	}

	// Top 5 risks: open findings ordered by priority class, EPSS score.
	// title is nullable (most scanner findings only carry a message); scanning
	// a NULL into a string failed the whole summary with a 500.
	// Top risks are row data: they follow the viewer's own row scope, never
	// the scope the totals are counted over (nil for an aggregate viewer).
	topIn, topArgs := dashboardScope(rowScope, 2)
	topQuery := `
		SELECT f.id::text, COALESCE(f.title, '') AS title, f.severity, COALESCE(f.priority_class, 'P3') AS priority_class,
			COALESCE(f.asset_id::text, '') AS asset_id,
			COALESCE(a.name, '') AS asset_name, f.epss_score, COALESCE(f.is_in_kev, FALSE)
		FROM findings f
		LEFT JOIN assets a ON a.id = f.asset_id AND a.tenant_id = $1
		WHERE f.tenant_id = $1 AND NOT f.branch_only` + findingExcl(ctx, "f.asset_id") + ` AND ` + topIn("f.asset_id") + ` AND ` + vulnerability.OpenStatusSQL("f.status") + `
		ORDER BY f.priority_class ASC NULLS LAST, f.epss_score DESC NULLS LAST
		LIMIT 5
	`

	rows, err := r.db.QueryContext(ctx, topQuery, append([]any{tenantID.String()}, topArgs...)...)
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

	// A bucket with no remediated finding is NULL (not 0 h) and is left out of
	// the result; the overall figure also reports the median and the 90th
	// percentile, since remediation times are right-skewed.
	query := `
		WITH r AS (
			SELECT severity, priority_class, EXTRACT(EPOCH FROM (resolved_at - first_detected_at)) / 3600 AS hrs
			FROM findings
			WHERE tenant_id = $1
				AND NOT branch_only` + findingExcl(ctx, "asset_id") + `
				AND ` + vulnerability.RemediatedSQL("") + `
				AND resolved_at >= NOW() - ($2::int || ' days')::interval
				AND resolved_at IS NOT NULL
				AND first_detected_at IS NOT NULL
				AND resolved_at >= first_detected_at
				AND ` + inScope + `
		)
		SELECT
			AVG(hrs) FILTER(WHERE severity = 'critical'),
			AVG(hrs) FILTER(WHERE severity = 'high'),
			AVG(hrs) FILTER(WHERE severity = 'medium'),
			AVG(hrs) FILTER(WHERE severity = 'low'),
			AVG(hrs) FILTER(WHERE severity IN ('info', 'none')),
			AVG(hrs) FILTER(WHERE priority_class = 'P0'),
			AVG(hrs) FILTER(WHERE priority_class = 'P1'),
			AVG(hrs) FILTER(WHERE priority_class = 'P2'),
			AVG(hrs) FILTER(WHERE priority_class = 'P3'),
			AVG(hrs),
			PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY hrs),
			PERCENTILE_CONT(0.9) WITHIN GROUP (ORDER BY hrs),
			COUNT(*)
		FROM r
	`

	var (
		sev        [5]sql.NullFloat64
		prio       [4]sql.NullFloat64
		overall    sql.NullFloat64
		med, p90   sql.NullFloat64
		sampleSize int
	)

	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&sev[0], &sev[1], &sev[2], &sev[3], &sev[4],
		&prio[0], &prio[1], &prio[2], &prio[3],
		&overall, &med, &p90, &sampleSize,
	)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("mttr analytics: %w", err)
	}

	result := &module.MTTRAnalytics{
		BySeverity:      map[string]float64{},
		ByPriorityClass: map[string]float64{},
		Overall:         nullFloatPtr(overall),
		OverallMedian:   nullFloatPtr(med),
		OverallP90:      nullFloatPtr(p90),
		SampleSize:      sampleSize,
	}
	for i, k := range []string{"critical", "high", "medium", "low", "info"} {
		if sev[i].Valid {
			result.BySeverity[k] = sev[i].Float64
		}
	}
	for i, k := range []string{"P0", "P1", "P2", "P3"} {
		if prio[i].Valid {
			result.ByPriorityClass[k] = prio[i].Float64
		}
	}
	return result, nil
}

// GetProcessMetrics computes process efficiency metrics for a tenant.
func (r *DashboardRepository) GetProcessMetrics(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, days int) (*module.ProcessMetrics, error) {
	if days <= 0 || days > 365 {
		days = 90
	}
	// A non-nil scope measures only the viewer's in-scope assets and findings.
	inScope, scopeArgs := dashboardScope(scope, 3)
	query := `
		WITH approval_stats AS (
			SELECT
				COALESCE(AVG(EXTRACT(epoch FROM COALESCE(approved_at, rejected_at) - created_at) / 3600), 0) AS avg_hours,
				COUNT(*) AS total
			FROM finding_status_approvals
			WHERE tenant_id = $1 AND status IN ('approved','rejected')
			AND created_at >= NOW() - ($2 || ' days')::interval
			AND EXISTS (SELECT 1 FROM findings sf WHERE sf.tenant_id = $1 AND sf.id = finding_status_approvals.finding_id AND ` + inScope("sf.asset_id") + `)
		),
		stale_stats AS (
			SELECT
				COUNT(*) FILTER(WHERE last_seen < NOW() - INTERVAL '7 days') AS stale,
				COUNT(*) AS total
			FROM assets WHERE deleted_at IS NULL AND tenant_id = $1` + programAssetExcl(ctx, "") + ` AND status != 'archived' AND ` + inScope("assets.id") + `
		),
		assign_stats AS (
			SELECT
				COUNT(*) FILTER(WHERE assigned_to IS NULL AND ` + vulnerability.OpenStatusSQL("status") + `) AS unassigned,
				COALESCE(AVG(EXTRACT(epoch FROM assigned_at - created_at) / 3600) FILTER(WHERE assigned_at IS NOT NULL), 0) AS avg_assign_hours
			FROM findings WHERE tenant_id = $1 AND NOT branch_only` + findingExcl(ctx, "asset_id") + ` AND ` + inScope("asset_id") + `
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
	err := r.db.QueryRowContext(ctx, query, append([]any{tenantID.String(), days}, scopeArgs...)...).Scan(
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

// newSeverityCounts returns a by-severity count map with every reporting
// bucket present at zero, so a client always gets an info key (and never has
// to guess whether a missing key means zero or "not reported").
func newSeverityCounts() map[string]int {
	m := make(map[string]int, len(vulnerability.ReportingSeverities()))
	for _, s := range vulnerability.ReportingSeverities() {
		m[s] = 0
	}
	return m
}

// findingExcl is the predicate every dashboard query over findings ANDs: the
// program-asset rule, then the pentest member-visibility rule of the findings
// list for a viewer who is not an administrator (a pentest finding only for
// members of its campaign, never a draft or in-review one for the client
// role), through the one shared rule (vulnerability.FindingMemberVisibilitySQL).
// col is the finding's asset column, alias-qualified when the findings table
// is aliased; the tenant is $1. A context with no viewer is an internal
// call that is not on behalf of a user.
func findingExcl(ctx context.Context, col string) string {
	return programFindingExcl(ctx, col) + pentestVisibilityExcl(ctx, findingAlias(col))
}

// findingAlias is the findings alias of an asset column ("f.asset_id" is "f";
// an unqualified column reads the bare table).
func findingAlias(col string) string {
	if i := strings.LastIndex(col, "."); i > 0 {
		return col[:i]
	}
	return "findings"
}

func pentestVisibilityExcl(ctx context.Context, alias string) string {
	v, ok := shared.FindingViewerOf(ctx)
	if !ok || v.Admin {
		return ""
	}
	return " AND " + vulnerability.FindingMemberVisibilitySQL(alias, "$1", "'"+v.UserID.String()+"'::uuid")
}

// publishedExcl leaves out the findings still in pentest review (draft,
// in review): they are not part of activity, new-finding counts or velocity.
func publishedExcl(alias string) string {
	return " AND " + alias + ".status NOT IN ('draft', 'in_review')"
}

// programFindingExcl leaves out the findings of program-only assets
// (RFC-065 §16.5) unless the request includes them. col is the finding
// asset column; $1 is the tenant in every dashboard query. Null-safe: a
// finding without an asset stays.
func programFindingExcl(ctx context.Context, col string) string {
	if shared.ProgramAssetsIncluded(ctx) {
		return hiddenProgramExcl(ctx, col)
	}
	return " AND NOT EXISTS (SELECT 1 FROM assets pa WHERE pa.tenant_id = $1 AND pa.id = " + col + " AND pa.program_only)"
}

// hiddenProgramExcl keeps the private program assets hidden from the
// viewer out of metrics that include program assets (RFC-065 §15.3): an
// owner, or an internal call with no viewer, sees them all.
func hiddenProgramExcl(ctx context.Context, col string) string {
	v, ok := shared.ProgramViewerOf(ctx)
	if !ok || v.Owner {
		return ""
	}
	return " AND " + filterspec.NotHiddenForViewer(col, "$1", v.UserID)
}

// programAssetExcl leaves out program-only assets unless the request
// includes them; alias is the assets alias with its dot, or "".
func programAssetExcl(ctx context.Context, alias string) string {
	if shared.ProgramAssetsIncluded(ctx) {
		col := alias + "id"
		if alias == "" {
			col = "assets.id" // the outer table, never the subquery alias
		}
		return hiddenProgramExcl(ctx, col)
	}
	return " AND NOT " + alias + "program_only"
}
