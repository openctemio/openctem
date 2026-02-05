package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
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
var _ app.DashboardStatsRepository = (*DashboardRepository)(nil)

// GetAssetStats returns asset statistics for a tenant.
func (r *DashboardRepository) GetAssetStats(ctx context.Context, tenantID shared.ID) (app.AssetStatsData, error) {
	stats := app.AssetStatsData{
		ByType:   make(map[string]int),
		ByStatus: make(map[string]int),
	}

	// Get total count filtered by tenant
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM assets WHERE tenant_id = $1`,
		tenantID.String(),
	).Scan(&stats.Total)
	if err != nil {
		return stats, err
	}

	// Get by type filtered by tenant
	rows, err := r.db.QueryContext(ctx,
		`SELECT asset_type, COUNT(*) FROM assets WHERE tenant_id = $1 GROUP BY asset_type`,
		tenantID.String(),
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

	// Get by status filtered by tenant
	rows, err = r.db.QueryContext(ctx,
		`SELECT status, COUNT(*) FROM assets WHERE tenant_id = $1 GROUP BY status`,
		tenantID.String(),
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

	return stats, nil
}

// GetFindingStats returns finding statistics for a tenant.
func (r *DashboardRepository) GetFindingStats(ctx context.Context, tenantID shared.ID) (app.FindingStatsData, error) {
	stats := app.FindingStatsData{
		BySeverity: make(map[string]int),
		ByStatus:   make(map[string]int),
	}

	// Get total count
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM findings WHERE tenant_id = $1`,
		tenantID.String(),
	).Scan(&stats.Total)
	if err != nil {
		return stats, err
	}

	// Get by severity
	rows, err := r.db.QueryContext(ctx,
		`SELECT severity, COUNT(*) FROM findings WHERE tenant_id = $1 GROUP BY severity`,
		tenantID.String(),
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
	rows, err = r.db.QueryContext(ctx,
		`SELECT status, COUNT(*) FROM findings WHERE tenant_id = $1 GROUP BY status`,
		tenantID.String(),
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

	// Note: Overdue count disabled - due_date column not yet implemented in findings table
	// TODO: Add due_date column to findings table and enable this query
	stats.Overdue = 0

	// Get average CVSS (join with vulnerabilities to get cvss_score)
	err = r.db.QueryRowContext(ctx,
		`SELECT COALESCE(AVG(v.cvss_score), 0) FROM findings f
		 LEFT JOIN vulnerabilities v ON f.vulnerability_id = v.id
		 WHERE f.tenant_id = $1`,
		tenantID.String(),
	).Scan(&stats.AverageCVSS)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		stats.AverageCVSS = 0
	}

	return stats, nil
}

// GetRepositoryStats returns repository statistics for a tenant.
func (r *DashboardRepository) GetRepositoryStats(ctx context.Context, tenantID shared.ID) (app.RepositoryStatsData, error) {
	stats := app.RepositoryStatsData{}

	// Get total count of repositories (assets with type 'repository')
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND asset_type = 'repository'`,
		tenantID.String(),
	).Scan(&stats.Total)
	if err != nil {
		return stats, err
	}

	// Get count of repositories with findings
	err = r.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT a.id) FROM assets a
		 INNER JOIN findings f ON a.id = f.asset_id
		 WHERE a.tenant_id = $1 AND a.asset_type = 'repository'`,
		tenantID.String(),
	).Scan(&stats.WithFindings)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		stats.WithFindings = 0
	}

	return stats, nil
}

// GetRecentActivity returns recent activity for a tenant.
func (r *DashboardRepository) GetRecentActivity(ctx context.Context, tenantID shared.ID, limit int) ([]app.ActivityItem, error) {
	// For now, get recent findings as activity
	// In future, this could be from an audit log table
	rows, err := r.db.QueryContext(ctx,
		`SELECT 'finding' as type,
		        COALESCE(f.rule_id, f.tool_name) as title,
		        f.message as description,
		        f.created_at
		 FROM findings f
		 WHERE f.tenant_id = $1
		 ORDER BY f.created_at DESC
		 LIMIT $2`,
		tenantID.String(), limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var activity []app.ActivityItem
	for rows.Next() {
		var item app.ActivityItem
		if err := rows.Scan(&item.Type, &item.Title, &item.Description, &item.Timestamp); err != nil {
			return nil, err
		}
		activity = append(activity, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return activity, nil
}

// Global stats methods (not tenant-scoped)

// GetGlobalAssetStats returns global asset statistics.
func (r *DashboardRepository) GetGlobalAssetStats(ctx context.Context) (app.AssetStatsData, error) {
	stats := app.AssetStatsData{
		ByType:   make(map[string]int),
		ByStatus: make(map[string]int),
	}

	// Get total count
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets`).Scan(&stats.Total)
	if err != nil {
		return stats, err
	}

	// Get by type
	rows, err := r.db.QueryContext(ctx, `SELECT asset_type, COUNT(*) FROM assets GROUP BY asset_type`)
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

	// Get by status
	rows, err = r.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM assets GROUP BY status`)
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

	return stats, nil
}

// GetGlobalFindingStats returns global finding statistics.
func (r *DashboardRepository) GetGlobalFindingStats(ctx context.Context) (app.FindingStatsData, error) {
	stats := app.FindingStatsData{
		BySeverity: make(map[string]int),
		ByStatus:   make(map[string]int),
	}

	// Get total count
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings`).Scan(&stats.Total)
	if err != nil {
		return stats, err
	}

	// Get by severity
	rows, err := r.db.QueryContext(ctx, `SELECT severity, COUNT(*) FROM findings GROUP BY severity`)
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
	rows, err = r.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM findings GROUP BY status`)
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
	err = r.db.QueryRowContext(ctx,
		`SELECT COALESCE(AVG(v.cvss_score), 0) FROM findings f
		 LEFT JOIN vulnerabilities v ON f.vulnerability_id = v.id`).Scan(&stats.AverageCVSS)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		stats.AverageCVSS = 0
	}

	return stats, nil
}

// GetGlobalRepositoryStats returns global repository statistics.
func (r *DashboardRepository) GetGlobalRepositoryStats(ctx context.Context) (app.RepositoryStatsData, error) {
	stats := app.RepositoryStatsData{}

	// Get total count of repositories
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM assets WHERE asset_type = 'repository'`).Scan(&stats.Total)
	if err != nil {
		return stats, err
	}

	// Get count of repositories with findings
	err = r.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT a.id) FROM assets a
		 INNER JOIN findings f ON a.id = f.asset_id
		 WHERE a.asset_type = 'repository'`,
	).Scan(&stats.WithFindings)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		stats.WithFindings = 0
	}

	return stats, nil
}

// GetGlobalRecentActivity returns global recent activity.
func (r *DashboardRepository) GetGlobalRecentActivity(ctx context.Context, limit int) ([]app.ActivityItem, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT 'finding' as type,
		        COALESCE(f.rule_id, f.tool_name) as title,
		        f.message as description,
		        f.created_at
		 FROM findings f
		 ORDER BY f.created_at DESC
		 LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var activity []app.ActivityItem
	for rows.Next() {
		var item app.ActivityItem
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

// ============================================================
// Filtered stats methods (multi-tenant authorization)
// ============================================================

// GetFilteredAssetStats returns asset statistics filtered by tenant IDs.
func (r *DashboardRepository) GetFilteredAssetStats(ctx context.Context, tenantIDs []string) (app.AssetStatsData, error) {
	stats := app.AssetStatsData{
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
		`SELECT COUNT(*) FROM assets WHERE tenant_id IN (`+placeholders+`)`,
		args...,
	).Scan(&stats.Total)
	if err != nil {
		return stats, err
	}

	// Get by type filtered by tenants
	//nolint:gosec // G202: placeholders is built from len(tenantIDs), not user input
	rows, err := r.db.QueryContext(ctx,
		`SELECT asset_type, COUNT(*) FROM assets WHERE tenant_id IN (`+placeholders+`) GROUP BY asset_type`,
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
		`SELECT status, COUNT(*) FROM assets WHERE tenant_id IN (`+placeholders+`) GROUP BY status`,
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

	return stats, nil
}

// GetFilteredFindingStats returns finding statistics filtered by tenant IDs.
func (r *DashboardRepository) GetFilteredFindingStats(ctx context.Context, tenantIDs []string) (app.FindingStatsData, error) {
	stats := app.FindingStatsData{
		BySeverity: make(map[string]int),
		ByStatus:   make(map[string]int),
	}

	if len(tenantIDs) == 0 {
		return stats, nil
	}

	// Build placeholder string for IN clause
	placeholders, args := buildInClause(tenantIDs, 0)

	// Get total count
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM findings WHERE tenant_id IN (`+placeholders+`)`,
		args...,
	).Scan(&stats.Total)
	if err != nil {
		return stats, err
	}

	// Get by severity
	//nolint:gosec // G202: placeholders is built from len(tenantIDs), not user input
	rows, err := r.db.QueryContext(ctx,
		`SELECT severity, COUNT(*) FROM findings WHERE tenant_id IN (`+placeholders+`) GROUP BY severity`,
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
		`SELECT status, COUNT(*) FROM findings WHERE tenant_id IN (`+placeholders+`) GROUP BY status`,
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
		`SELECT COALESCE(AVG(v.cvss_score), 0) FROM findings f
		 LEFT JOIN vulnerabilities v ON f.vulnerability_id = v.id
		 WHERE f.tenant_id IN (`+placeholders+`)`,
		args...,
	).Scan(&stats.AverageCVSS)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		stats.AverageCVSS = 0
	}

	return stats, nil
}

// GetFilteredRepositoryStats returns repository statistics filtered by tenant IDs.
func (r *DashboardRepository) GetFilteredRepositoryStats(ctx context.Context, tenantIDs []string) (app.RepositoryStatsData, error) {
	stats := app.RepositoryStatsData{}

	if len(tenantIDs) == 0 {
		return stats, nil
	}

	// Build placeholder string for IN clause
	placeholders, args := buildInClause(tenantIDs, 0)

	// Get total count of repositories
	//nolint:gosec // G202: placeholders is built from len(tenantIDs), not user input
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM assets WHERE tenant_id IN (`+placeholders+`) AND asset_type = 'repository'`,
		args...,
	).Scan(&stats.Total)
	if err != nil {
		return stats, err
	}

	// Get count of repositories with findings
	//nolint:gosec // G202: placeholders is built from len(tenantIDs), not user input
	err = r.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT a.id) FROM assets a
		 INNER JOIN findings f ON a.id = f.asset_id
		 WHERE a.tenant_id IN (`+placeholders+`) AND a.asset_type = 'repository'`,
		args...,
	).Scan(&stats.WithFindings)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		stats.WithFindings = 0
	}

	return stats, nil
}

// GetFilteredRecentActivity returns recent activity filtered by tenant IDs.
func (r *DashboardRepository) GetFilteredRecentActivity(ctx context.Context, tenantIDs []string, limit int) ([]app.ActivityItem, error) {
	if len(tenantIDs) == 0 {
		return []app.ActivityItem{}, nil
	}

	// Build placeholder string for IN clause
	placeholders, args := buildInClause(tenantIDs, 0)
	args = append(args, limit)
	limitPlaceholder := len(tenantIDs) + 1

	//nolint:gosec // G202: placeholders and limitPlaceholder are built from len(tenantIDs), not user input
	rows, err := r.db.QueryContext(ctx,
		`SELECT 'finding' as type,
		        COALESCE(f.rule_id, f.tool_name) as title,
		        f.message as description,
		        f.created_at
		 FROM findings f
		 WHERE f.tenant_id IN (`+placeholders+`)
		 ORDER BY f.created_at DESC
		 LIMIT $`+itoa(limitPlaceholder),
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var activity []app.ActivityItem
	for rows.Next() {
		var item app.ActivityItem
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
