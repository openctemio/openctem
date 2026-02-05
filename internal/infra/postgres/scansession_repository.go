package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/scanprofile"
	"github.com/openctemio/api/pkg/domain/scansession"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// ScanSessionRepository implements scansession.Repository using PostgreSQL.
type ScanSessionRepository struct {
	db *DB
}

// NewScanSessionRepository creates a new ScanSessionRepository.
func NewScanSessionRepository(db *DB) *ScanSessionRepository {
	return &ScanSessionRepository{db: db}
}

// Create persists a new scan session.
func (r *ScanSessionRepository) Create(ctx context.Context, s *scansession.ScanSession) error {
	findingsBySeverity, err := json.Marshal(s.FindingsBySeverity)
	if err != nil {
		return fmt.Errorf("failed to marshal findings_by_severity: %w", err)
	}

	metadata, err := json.Marshal(s.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	var qualityGateResult []byte
	if s.QualityGateResult != nil {
		qualityGateResult, err = json.Marshal(s.QualityGateResult)
		if err != nil {
			return fmt.Errorf("failed to marshal quality_gate_result: %w", err)
		}
	}

	var agentID, assetID, scanProfileID *string
	if s.AgentID != nil {
		wid := s.AgentID.String()
		agentID = &wid
	}
	if s.AssetID != nil {
		aid := s.AssetID.String()
		assetID = &aid
	}
	if s.ScanProfileID != nil {
		spid := s.ScanProfileID.String()
		scanProfileID = &spid
	}

	query := `
		INSERT INTO scan_sessions (
			id, tenant_id, agent_id,
			scanner_name, scanner_version, scanner_type,
			asset_type, asset_value, asset_id,
			commit_sha, branch, base_commit_sha,
			status, error_message,
			findings_total, findings_new, findings_fixed, findings_by_severity,
			started_at, completed_at, duration_ms,
			metadata, scan_profile_id, quality_gate_result,
			created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)
	`

	_, err = r.db.ExecContext(ctx, query,
		s.ID.String(),
		s.TenantID.String(),
		agentID,
		s.ScannerName,
		s.ScannerVersion,
		s.ScannerType,
		s.AssetType,
		s.AssetValue,
		assetID,
		nullableString(s.CommitSha),
		nullableString(s.Branch),
		nullableString(s.BaseCommitSha),
		string(s.Status),
		nullableString(s.ErrorMessage),
		s.FindingsTotal,
		s.FindingsNew,
		s.FindingsFixed,
		findingsBySeverity,
		s.StartedAt,
		s.CompletedAt,
		s.DurationMs,
		metadata,
		scanProfileID,
		nullBytes(qualityGateResult),
		s.CreatedAt,
		s.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create scan session: %w", err)
	}

	return nil
}

// GetByID retrieves a scan session by ID.
func (r *ScanSessionRepository) GetByID(ctx context.Context, id shared.ID) (*scansession.ScanSession, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanFromRow(row)
}

// GetByTenantAndID retrieves a scan session by tenant and ID.
func (r *ScanSessionRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*scansession.ScanSession, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanFromRow(row)
}

// Update updates a scan session.
func (r *ScanSessionRepository) Update(ctx context.Context, s *scansession.ScanSession) error {
	findingsBySeverity, err := json.Marshal(s.FindingsBySeverity)
	if err != nil {
		return fmt.Errorf("failed to marshal findings_by_severity: %w", err)
	}

	metadata, err := json.Marshal(s.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	var qualityGateResult []byte
	if s.QualityGateResult != nil {
		qualityGateResult, err = json.Marshal(s.QualityGateResult)
		if err != nil {
			return fmt.Errorf("failed to marshal quality_gate_result: %w", err)
		}
	}

	var scanProfileID *string
	if s.ScanProfileID != nil {
		spid := s.ScanProfileID.String()
		scanProfileID = &spid
	}

	query := `
		UPDATE scan_sessions SET
			status = $2,
			error_message = $3,
			findings_total = $4,
			findings_new = $5,
			findings_fixed = $6,
			findings_by_severity = $7,
			started_at = $8,
			completed_at = $9,
			duration_ms = $10,
			metadata = $11,
			scan_profile_id = $12,
			quality_gate_result = $13,
			updated_at = $14
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		s.ID.String(),
		string(s.Status),
		nullableString(s.ErrorMessage),
		s.FindingsTotal,
		s.FindingsNew,
		s.FindingsFixed,
		findingsBySeverity,
		s.StartedAt,
		s.CompletedAt,
		s.DurationMs,
		metadata,
		scanProfileID,
		nullBytes(qualityGateResult),
		s.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update scan session: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return shared.NewDomainError("NOT_FOUND", "scan session not found", shared.ErrNotFound)
	}

	return nil
}

// Delete deletes a scan session by ID.
func (r *ScanSessionRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM scan_sessions WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete scan session: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return shared.NewDomainError("NOT_FOUND", "scan session not found", shared.ErrNotFound)
	}

	return nil
}

// List lists scan sessions with filtering and pagination.
func (r *ScanSessionRepository) List(ctx context.Context, filter scansession.Filter, page pagination.Pagination) (pagination.Result[*scansession.ScanSession], error) {
	var result pagination.Result[*scansession.ScanSession]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM scan_sessions"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count scan sessions: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list scan sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*scansession.ScanSession
	for rows.Next() {
		s, err := r.scanFromRows(rows)
		if err != nil {
			return result, fmt.Errorf("failed to scan row: %w", err)
		}
		sessions = append(sessions, s)
	}

	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("rows error: %w", err)
	}

	result = pagination.NewResult(sessions, total, page)
	return result, nil
}

// FindBaseline finds the baseline commit SHA for incremental scanning.
func (r *ScanSessionRepository) FindBaseline(ctx context.Context, tenantID shared.ID, assetType, assetValue, branch string) (string, error) {
	query := `
		SELECT commit_sha
		FROM scan_sessions
		WHERE tenant_id = $1
			AND asset_type = $2
			AND asset_value = $3
			AND branch = $4
			AND status = 'completed'
			AND commit_sha IS NOT NULL
			AND commit_sha != ''
		ORDER BY completed_at DESC
		LIMIT 1
	`

	var commitSha string
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), assetType, assetValue, branch).Scan(&commitSha)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil // No baseline found, this is okay
	}
	if err != nil {
		return "", fmt.Errorf("failed to find baseline: %w", err)
	}

	return commitSha, nil
}

// GetStats returns scan session statistics.
func (r *ScanSessionRepository) GetStats(ctx context.Context, tenantID shared.ID, since time.Time) (*scansession.Stats, error) {
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE status = 'pending') as pending,
			COUNT(*) FILTER (WHERE status = 'running') as running,
			COUNT(*) FILTER (WHERE status = 'completed') as completed,
			COUNT(*) FILTER (WHERE status = 'failed') as failed,
			COUNT(*) FILTER (WHERE status = 'canceled') as canceled,
			COALESCE(SUM(findings_total), 0) as total_findings,
			COALESCE(SUM(findings_new), 0) as total_findings_new,
			COALESCE(AVG(duration_ms) FILTER (WHERE status = 'completed'), 0) as avg_duration_ms
		FROM scan_sessions
		WHERE tenant_id = $1 AND created_at >= $2
	`

	stats := &scansession.Stats{
		ByScanner: make(map[string]int64),
		ByAsset:   make(map[string]int64),
	}

	err := r.db.QueryRowContext(ctx, query, tenantID.String(), since).Scan(
		&stats.Total,
		&stats.Pending,
		&stats.Running,
		&stats.Completed,
		&stats.Failed,
		&stats.Canceled,
		&stats.TotalFindings,
		&stats.TotalFindingsNew,
		&stats.AvgDurationMs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	// Get by scanner stats
	scannerQuery := `
		SELECT scanner_name, COUNT(*)
		FROM scan_sessions
		WHERE tenant_id = $1 AND created_at >= $2
		GROUP BY scanner_name
	`
	scannerRows, err := r.db.QueryContext(ctx, scannerQuery, tenantID.String(), since)
	if err != nil {
		return nil, fmt.Errorf("failed to get scanner stats: %w", err)
	}
	defer scannerRows.Close()

	for scannerRows.Next() {
		var name string
		var count int64
		if err := scannerRows.Scan(&name, &count); err != nil {
			return nil, fmt.Errorf("failed to scan scanner stats: %w", err)
		}
		stats.ByScanner[name] = count
	}
	if err := scannerRows.Err(); err != nil {
		return nil, fmt.Errorf("scanner rows error: %w", err)
	}

	// Get by asset type stats
	assetQuery := `
		SELECT asset_type, COUNT(*)
		FROM scan_sessions
		WHERE tenant_id = $1 AND created_at >= $2
		GROUP BY asset_type
	`
	assetRows, err := r.db.QueryContext(ctx, assetQuery, tenantID.String(), since)
	if err != nil {
		return nil, fmt.Errorf("failed to get asset stats: %w", err)
	}
	defer assetRows.Close()

	for assetRows.Next() {
		var assetType string
		var count int64
		if err := assetRows.Scan(&assetType, &count); err != nil {
			return nil, fmt.Errorf("failed to scan asset stats: %w", err)
		}
		stats.ByAsset[assetType] = count
	}
	if err := assetRows.Err(); err != nil {
		return nil, fmt.Errorf("asset rows error: %w", err)
	}

	return stats, nil
}

// ListRunning lists all running scans for a tenant.
func (r *ScanSessionRepository) ListRunning(ctx context.Context, tenantID shared.ID) ([]*scansession.ScanSession, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND status = 'running' ORDER BY started_at DESC"

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list running sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*scansession.ScanSession
	for rows.Next() {
		s, err := r.scanFromRows(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		sessions = append(sessions, s)
	}

	return sessions, nil
}

// Helper methods

func (r *ScanSessionRepository) selectQuery() string {
	return `
		SELECT
			id, tenant_id, agent_id,
			scanner_name, scanner_version, scanner_type,
			asset_type, asset_value, asset_id,
			commit_sha, branch, base_commit_sha,
			status, error_message,
			findings_total, findings_new, findings_fixed, findings_by_severity,
			started_at, completed_at, duration_ms,
			metadata, scan_profile_id, quality_gate_result,
			created_at, updated_at
		FROM scan_sessions
	`
}

func (r *ScanSessionRepository) buildWhereClause(filter scansession.Filter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID.String())
		argIndex++
	}

	if filter.AgentID != nil {
		conditions = append(conditions, fmt.Sprintf("agent_id = $%d", argIndex))
		args = append(args, filter.AgentID.String())
		argIndex++
	}

	if filter.AssetID != nil {
		conditions = append(conditions, fmt.Sprintf("asset_id = $%d", argIndex))
		args = append(args, filter.AssetID.String())
		argIndex++
	}

	if filter.ScannerName != "" {
		conditions = append(conditions, fmt.Sprintf("scanner_name = $%d", argIndex))
		args = append(args, filter.ScannerName)
		argIndex++
	}

	if filter.AssetType != "" {
		conditions = append(conditions, fmt.Sprintf("asset_type = $%d", argIndex))
		args = append(args, filter.AssetType)
		argIndex++
	}

	if filter.AssetValue != "" {
		conditions = append(conditions, fmt.Sprintf("asset_value = $%d", argIndex))
		args = append(args, filter.AssetValue)
		argIndex++
	}

	if filter.Branch != "" {
		conditions = append(conditions, fmt.Sprintf("branch = $%d", argIndex))
		args = append(args, filter.Branch)
		argIndex++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, string(*filter.Status))
		argIndex++
	}

	if filter.Since != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argIndex))
		args = append(args, *filter.Since)
		argIndex++
	}

	if filter.Until != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argIndex))
		args = append(args, *filter.Until)
		argIndex++
	}

	return strings.Join(conditions, " AND "), args
}

func (r *ScanSessionRepository) scanFromRow(row *sql.Row) (*scansession.ScanSession, error) {
	s := &scansession.ScanSession{}
	var (
		id                               string
		tenantID                         string
		agentID, assetID                 sql.NullString
		scannerVersion, scannerType      sql.NullString
		commitSha, branch, baseCommitSha sql.NullString
		errorMessage                     sql.NullString
		findingsBySeverity, metadata     []byte
		startedAt, completedAt           sql.NullTime
		durationMs                       sql.NullInt64
		scanProfileID                    sql.NullString
		qualityGateResult                []byte
	)

	err := row.Scan(
		&id, &tenantID, &agentID,
		&s.ScannerName, &scannerVersion, &scannerType,
		&s.AssetType, &s.AssetValue, &assetID,
		&commitSha, &branch, &baseCommitSha,
		&s.Status, &errorMessage,
		&s.FindingsTotal, &s.FindingsNew, &s.FindingsFixed, &findingsBySeverity,
		&startedAt, &completedAt, &durationMs,
		&metadata, &scanProfileID, &qualityGateResult,
		&s.CreatedAt, &s.UpdatedAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.NewDomainError("NOT_FOUND", "scan session not found", shared.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan row: %w", err)
	}

	s.ID = shared.MustIDFromString(id)
	s.TenantID = shared.MustIDFromString(tenantID)

	if agentID.Valid {
		wid := shared.MustIDFromString(agentID.String)
		s.AgentID = &wid
	}
	if assetID.Valid {
		aid := shared.MustIDFromString(assetID.String)
		s.AssetID = &aid
	}
	if scanProfileID.Valid {
		spid := shared.MustIDFromString(scanProfileID.String)
		s.ScanProfileID = &spid
	}
	if scannerVersion.Valid {
		s.ScannerVersion = scannerVersion.String
	}
	if scannerType.Valid {
		s.ScannerType = scannerType.String
	}
	if commitSha.Valid {
		s.CommitSha = commitSha.String
	}
	if branch.Valid {
		s.Branch = branch.String
	}
	if baseCommitSha.Valid {
		s.BaseCommitSha = baseCommitSha.String
	}
	if errorMessage.Valid {
		s.ErrorMessage = errorMessage.String
	}
	if startedAt.Valid {
		s.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		s.CompletedAt = &completedAt.Time
	}
	if durationMs.Valid {
		s.DurationMs = durationMs.Int64
	}

	if err := json.Unmarshal(findingsBySeverity, &s.FindingsBySeverity); err != nil {
		s.FindingsBySeverity = make(map[string]int)
	}
	if err := json.Unmarshal(metadata, &s.Metadata); err != nil {
		s.Metadata = make(map[string]any)
	}
	if len(qualityGateResult) > 0 {
		var qgr scanprofile.QualityGateResult
		if err := json.Unmarshal(qualityGateResult, &qgr); err == nil {
			s.QualityGateResult = &qgr
		}
	}

	return s, nil
}

func (r *ScanSessionRepository) scanFromRows(rows *sql.Rows) (*scansession.ScanSession, error) {
	s := &scansession.ScanSession{}
	var (
		id, tenantID                     string
		agentID, assetID                 sql.NullString
		scannerVersion, scannerType      sql.NullString
		commitSha, branch, baseCommitSha sql.NullString
		errorMessage                     sql.NullString
		findingsBySeverity, metadata     []byte
		startedAt, completedAt           sql.NullTime
		durationMs                       sql.NullInt64
		scanProfileID                    sql.NullString
		qualityGateResult                []byte
	)

	err := rows.Scan(
		&id, &tenantID, &agentID,
		&s.ScannerName, &scannerVersion, &scannerType,
		&s.AssetType, &s.AssetValue, &assetID,
		&commitSha, &branch, &baseCommitSha,
		&s.Status, &errorMessage,
		&s.FindingsTotal, &s.FindingsNew, &s.FindingsFixed, &findingsBySeverity,
		&startedAt, &completedAt, &durationMs,
		&metadata, &scanProfileID, &qualityGateResult,
		&s.CreatedAt, &s.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan row: %w", err)
	}

	s.ID = shared.MustIDFromString(id)
	s.TenantID = shared.MustIDFromString(tenantID)

	if agentID.Valid {
		wid := shared.MustIDFromString(agentID.String)
		s.AgentID = &wid
	}
	if assetID.Valid {
		aid := shared.MustIDFromString(assetID.String)
		s.AssetID = &aid
	}
	if scanProfileID.Valid {
		spid := shared.MustIDFromString(scanProfileID.String)
		s.ScanProfileID = &spid
	}
	if scannerVersion.Valid {
		s.ScannerVersion = scannerVersion.String
	}
	if scannerType.Valid {
		s.ScannerType = scannerType.String
	}
	if commitSha.Valid {
		s.CommitSha = commitSha.String
	}
	if branch.Valid {
		s.Branch = branch.String
	}
	if baseCommitSha.Valid {
		s.BaseCommitSha = baseCommitSha.String
	}
	if errorMessage.Valid {
		s.ErrorMessage = errorMessage.String
	}
	if startedAt.Valid {
		s.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		s.CompletedAt = &completedAt.Time
	}
	if durationMs.Valid {
		s.DurationMs = durationMs.Int64
	}

	if err := json.Unmarshal(findingsBySeverity, &s.FindingsBySeverity); err != nil {
		s.FindingsBySeverity = make(map[string]int)
	}
	if err := json.Unmarshal(metadata, &s.Metadata); err != nil {
		s.Metadata = make(map[string]any)
	}
	if len(qualityGateResult) > 0 {
		var qgr scanprofile.QualityGateResult
		if err := json.Unmarshal(qualityGateResult, &qgr); err == nil {
			s.QualityGateResult = &qgr
		}
	}

	return s, nil
}

// nullableString returns a pointer to the string if non-empty, otherwise nil.
func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Ensure implementation
var _ scansession.Repository = (*ScanSessionRepository)(nil)
