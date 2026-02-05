package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// ScanRepository implements scan.Repository using PostgreSQL.
type ScanRepository struct {
	db *DB
}

// NewScanRepository creates a new ScanRepository.
func NewScanRepository(db *DB) *ScanRepository {
	return &ScanRepository{db: db}
}

// Create persists a new scan.
func (r *ScanRepository) Create(ctx context.Context, s *scan.Scan) error {
	scannerConfig, err := json.Marshal(s.ScannerConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal scanner_config: %w", err)
	}

	var pipelineID *string
	if s.PipelineID != nil {
		pid := s.PipelineID.String()
		pipelineID = &pid
	}

	var createdBy *string
	if s.CreatedBy != nil {
		cb := s.CreatedBy.String()
		createdBy = &cb
	}

	// Handle nullable asset_group_id
	var assetGroupID *string
	if !s.AssetGroupID.IsZero() {
		agid := s.AssetGroupID.String()
		assetGroupID = &agid
	}

	// Convert AssetGroupIDs to string array for database
	assetGroupIDStrings := make([]string, len(s.AssetGroupIDs))
	for i, id := range s.AssetGroupIDs {
		assetGroupIDStrings[i] = id.String()
	}

	query := `
		INSERT INTO scans (
			id, tenant_id, name, description,
			asset_group_id, asset_group_ids, targets, scan_type, pipeline_id,
			scanner_name, scanner_config, targets_per_job,
			schedule_type, schedule_cron, schedule_day, schedule_time, schedule_timezone, next_run_at,
			tags, run_on_tenant_runner, status,
			last_run_id, last_run_at, last_run_status,
			total_runs, successful_runs, failed_runs,
			created_by, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)
	`

	_, err = r.db.ExecContext(ctx, query,
		s.ID.String(),
		s.TenantID.String(),
		s.Name,
		s.Description,
		assetGroupID,                  // Now nullable (legacy single asset group)
		pq.Array(assetGroupIDStrings), // NEW: multiple asset groups
		pq.Array(s.Targets),           // Direct targets
		string(s.ScanType),
		pipelineID,
		s.ScannerName,
		scannerConfig,
		s.TargetsPerJob,
		string(s.ScheduleType),
		s.ScheduleCron,
		s.ScheduleDay,
		s.ScheduleTime,
		s.ScheduleTimezone,
		s.NextRunAt,
		pq.Array(s.Tags),
		s.RunOnTenantRunner,
		string(s.Status),
		nil, // last_run_id
		s.LastRunAt,
		s.LastRunStatus,
		s.TotalRuns,
		s.SuccessfulRuns,
		s.FailedRuns,
		createdBy,
		s.CreatedAt,
		s.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "scan with this name already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create scan: %w", err)
	}

	return nil
}

// GetByID retrieves a scan by ID.
func (r *ScanRepository) GetByID(ctx context.Context, id shared.ID) (*scan.Scan, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanFromRow(row)
}

// GetByTenantAndID retrieves a scan by tenant and ID.
func (r *ScanRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*scan.Scan, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanFromRow(row)
}

// GetByName retrieves a scan by tenant and name.
func (r *ScanRepository) GetByName(ctx context.Context, tenantID shared.ID, name string) (*scan.Scan, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND name = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), name)
	return r.scanFromRow(row)
}

// List lists scans with filters and pagination.
func (r *ScanRepository) List(ctx context.Context, filter scan.Filter, page pagination.Pagination) (pagination.Result[*scan.Scan], error) {
	var result pagination.Result[*scan.Scan]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM scans"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count scans: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY name LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list scans: %w", err)
	}
	defer rows.Close()

	var scans []*scan.Scan
	for rows.Next() {
		s, err := r.scanFromRows(rows)
		if err != nil {
			return result, err
		}
		scans = append(scans, s)
	}

	return pagination.NewResult(scans, total, page), nil
}

// Update updates a scan.
func (r *ScanRepository) Update(ctx context.Context, s *scan.Scan) error {
	scannerConfig, err := json.Marshal(s.ScannerConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal scanner_config: %w", err)
	}

	var pipelineID *string
	if s.PipelineID != nil {
		pid := s.PipelineID.String()
		pipelineID = &pid
	}

	// Handle nullable asset_group_id
	var assetGroupID *string
	if !s.AssetGroupID.IsZero() {
		agid := s.AssetGroupID.String()
		assetGroupID = &agid
	}

	// Convert AssetGroupIDs to string array for database
	assetGroupIDStrings := make([]string, len(s.AssetGroupIDs))
	for i, id := range s.AssetGroupIDs {
		assetGroupIDStrings[i] = id.String()
	}

	query := `
		UPDATE scans
		SET name = $2, description = $3,
		    asset_group_id = $4, asset_group_ids = $5, targets = $6, scan_type = $7, pipeline_id = $8,
		    scanner_name = $9, scanner_config = $10, targets_per_job = $11,
		    schedule_type = $12, schedule_cron = $13, schedule_day = $14, schedule_time = $15, schedule_timezone = $16, next_run_at = $17,
		    tags = $18, run_on_tenant_runner = $19, status = $20,
		    updated_at = $21
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		s.ID.String(),
		s.Name,
		s.Description,
		assetGroupID,                  // Now nullable (legacy single)
		pq.Array(assetGroupIDStrings), // Multiple asset groups
		pq.Array(s.Targets),           // Direct targets
		string(s.ScanType),
		pipelineID,
		s.ScannerName,
		scannerConfig,
		s.TargetsPerJob,
		string(s.ScheduleType),
		s.ScheduleCron,
		s.ScheduleDay,
		s.ScheduleTime,
		s.ScheduleTimezone,
		s.NextRunAt,
		pq.Array(s.Tags),
		s.RunOnTenantRunner,
		string(s.Status),
		s.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "scan with this name already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to update scan: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a scan.
func (r *ScanRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM scans WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete scan: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// ListDueForExecution lists scans that are due for scheduled execution.
func (r *ScanRepository) ListDueForExecution(ctx context.Context, now time.Time) ([]*scan.Scan, error) {
	query := r.selectQuery() + `
		WHERE status = 'active'
		AND schedule_type != 'manual'
		AND next_run_at IS NOT NULL
		AND next_run_at <= $1
		ORDER BY next_run_at ASC
	`
	rows, err := r.db.QueryContext(ctx, query, now)
	if err != nil {
		return nil, fmt.Errorf("failed to list due scans: %w", err)
	}
	defer rows.Close()

	var scans []*scan.Scan
	for rows.Next() {
		s, err := r.scanFromRows(rows)
		if err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}

	return scans, nil
}

// UpdateNextRunAt updates the next run time for a scan.
func (r *ScanRepository) UpdateNextRunAt(ctx context.Context, id shared.ID, nextRunAt *time.Time) error {
	query := "UPDATE scans SET next_run_at = $2, updated_at = NOW() WHERE id = $1"
	_, err := r.db.ExecContext(ctx, query, id.String(), nextRunAt)
	if err != nil {
		return fmt.Errorf("failed to update next_run_at: %w", err)
	}
	return nil
}

// RecordRun records a run result for a scan.
func (r *ScanRepository) RecordRun(ctx context.Context, id shared.ID, runID shared.ID, status string) error {
	var successIncrement, failedIncrement int
	switch status {
	case "completed", "success":
		successIncrement = 1
	case "failed", "error":
		failedIncrement = 1
	}

	query := `
		UPDATE scans
		SET last_run_id = $2,
		    last_run_at = NOW(),
		    last_run_status = $3,
		    total_runs = total_runs + 1,
		    successful_runs = successful_runs + $4,
		    failed_runs = failed_runs + $5,
		    updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id.String(), runID.String(), status, successIncrement, failedIncrement)
	if err != nil {
		return fmt.Errorf("failed to record run: %w", err)
	}
	return nil
}

// GetStats returns aggregated statistics for scans.
func (r *ScanRepository) GetStats(ctx context.Context, tenantID shared.ID) (*scan.Stats, error) {
	stats := &scan.Stats{
		ByScheduleType: make(map[scan.ScheduleType]int64),
		ByScanType:     make(map[scan.ScanType]int64),
	}

	// Get counts by status
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE status = 'active') as active,
			COUNT(*) FILTER (WHERE status = 'paused') as paused,
			COUNT(*) FILTER (WHERE status = 'disabled') as disabled
		FROM scans
		WHERE tenant_id = $1
	`
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(
		&stats.Total, &stats.Active, &stats.Paused, &stats.Disabled,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	// Get counts by schedule type
	scheduleQuery := `
		SELECT schedule_type, COUNT(*)
		FROM scans
		WHERE tenant_id = $1
		GROUP BY schedule_type
	`
	scheduleRows, err := r.db.QueryContext(ctx, scheduleQuery, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get schedule stats: %w", err)
	}
	defer scheduleRows.Close()

	for scheduleRows.Next() {
		var scheduleType string
		var count int64
		if err := scheduleRows.Scan(&scheduleType, &count); err != nil {
			return nil, err
		}
		stats.ByScheduleType[scan.ScheduleType(scheduleType)] = count
	}
	if err := scheduleRows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate schedule rows: %w", err)
	}

	// Get counts by scan type
	scanTypeQuery := `
		SELECT scan_type, COUNT(*)
		FROM scans
		WHERE tenant_id = $1
		GROUP BY scan_type
	`
	scanTypeRows, err := r.db.QueryContext(ctx, scanTypeQuery, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get scan type stats: %w", err)
	}
	defer scanTypeRows.Close()

	for scanTypeRows.Next() {
		var scanType string
		var count int64
		if err := scanTypeRows.Scan(&scanType, &count); err != nil {
			return nil, err
		}
		stats.ByScanType[scan.ScanType(scanType)] = count
	}
	if err := scanTypeRows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate scan type rows: %w", err)
	}

	return stats, nil
}

// Count counts scans matching the filter.
func (r *ScanRepository) Count(ctx context.Context, filter scan.Filter) (int64, error) {
	countQuery := "SELECT COUNT(*) FROM scans"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		countQuery += " WHERE " + whereClause
	}

	var count int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&count)
	return count, err
}

// ListByAssetGroupID lists all scans for an asset group.
func (r *ScanRepository) ListByAssetGroupID(ctx context.Context, assetGroupID shared.ID) ([]*scan.Scan, error) {
	query := r.selectQuery() + " WHERE asset_group_id = $1 ORDER BY name"
	rows, err := r.db.QueryContext(ctx, query, assetGroupID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list by asset group: %w", err)
	}
	defer rows.Close()

	var scans []*scan.Scan
	for rows.Next() {
		s, err := r.scanFromRows(rows)
		if err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}

	return scans, nil
}

// ListByPipelineID lists all scans using a pipeline.
func (r *ScanRepository) ListByPipelineID(ctx context.Context, pipelineID shared.ID) ([]*scan.Scan, error) {
	query := r.selectQuery() + " WHERE pipeline_id = $1 ORDER BY name"
	rows, err := r.db.QueryContext(ctx, query, pipelineID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list by pipeline: %w", err)
	}
	defer rows.Close()

	var scans []*scan.Scan
	for rows.Next() {
		s, err := r.scanFromRows(rows)
		if err != nil {
			return nil, err
		}
		scans = append(scans, s)
	}

	return scans, nil
}

// UpdateStatusByAssetGroupID updates status for all scans in an asset group.
func (r *ScanRepository) UpdateStatusByAssetGroupID(ctx context.Context, assetGroupID shared.ID, status scan.Status) error {
	query := "UPDATE scans SET status = $2, updated_at = NOW() WHERE asset_group_id = $1"
	_, err := r.db.ExecContext(ctx, query, assetGroupID.String(), string(status))
	if err != nil {
		return fmt.Errorf("failed to update status by asset group: %w", err)
	}
	return nil
}

// selectQuery returns the base SELECT query.
func (r *ScanRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, name, description,
		       asset_group_id, asset_group_ids, targets, scan_type, pipeline_id,
		       scanner_name, scanner_config, targets_per_job,
		       schedule_type, schedule_cron, schedule_day, schedule_time, schedule_timezone, next_run_at,
		       tags, run_on_tenant_runner, status,
		       last_run_id, last_run_at, last_run_status,
		       total_runs, successful_runs, failed_runs,
		       created_by, created_at, updated_at
		FROM scans
	`
}

// buildWhereClause builds the WHERE clause from filters.
func (r *ScanRepository) buildWhereClause(filter scan.Filter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID.String())
		argIndex++
	}

	if filter.AssetGroupID != nil {
		conditions = append(conditions, fmt.Sprintf("asset_group_id = $%d", argIndex))
		args = append(args, filter.AssetGroupID.String())
		argIndex++
	}

	if filter.PipelineID != nil {
		conditions = append(conditions, fmt.Sprintf("pipeline_id = $%d", argIndex))
		args = append(args, filter.PipelineID.String())
		argIndex++
	}

	if filter.ScanType != nil {
		conditions = append(conditions, fmt.Sprintf("scan_type = $%d", argIndex))
		args = append(args, string(*filter.ScanType))
		argIndex++
	}

	if filter.ScheduleType != nil {
		conditions = append(conditions, fmt.Sprintf("schedule_type = $%d", argIndex))
		args = append(args, string(*filter.ScheduleType))
		argIndex++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, string(*filter.Status))
		argIndex++
	}

	if len(filter.Tags) > 0 {
		conditions = append(conditions, fmt.Sprintf("tags && $%d", argIndex))
		args = append(args, pq.Array(filter.Tags))
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex))
		args = append(args, wrapLikePattern(filter.Search))
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

// scanFromRow scans a single row into a Scan.
func (r *ScanRepository) scanFromRow(row *sql.Row) (*scan.Scan, error) {
	s := &scan.Scan{}
	var (
		id               string
		tenantID         string
		assetGroupID     sql.NullString // Now nullable
		assetGroupIDs    pq.StringArray // Multiple asset groups
		targets          pq.StringArray // Direct targets
		scanType         string
		scheduleType     string
		status           string
		tags             pq.StringArray
		scannerConfig    []byte
		pipelineID       sql.NullString
		lastRunID        sql.NullString
		createdBy        sql.NullString
		description      sql.NullString
		scannerName      sql.NullString
		scheduleCron     sql.NullString
		lastRunStatus    sql.NullString
		scheduleTimezone sql.NullString
	)

	err := row.Scan(
		&id,
		&tenantID,
		&s.Name,
		&description,
		&assetGroupID,
		&assetGroupIDs, // Multiple asset groups
		&targets,       // Direct targets
		&scanType,
		&pipelineID,
		&scannerName,
		&scannerConfig,
		&s.TargetsPerJob,
		&scheduleType,
		&scheduleCron,
		&s.ScheduleDay,
		&s.ScheduleTime,
		&scheduleTimezone,
		&s.NextRunAt,
		&tags,
		&s.RunOnTenantRunner,
		&status,
		&lastRunID,
		&s.LastRunAt,
		&lastRunStatus,
		&s.TotalRuns,
		&s.SuccessfulRuns,
		&s.FailedRuns,
		&createdBy,
		&s.CreatedAt,
		&s.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan scan: %w", err)
	}

	s.ID, _ = shared.IDFromString(id)
	s.TenantID, _ = shared.IDFromString(tenantID)
	// Handle nullable asset_group_id
	if assetGroupID.Valid {
		s.AssetGroupID, _ = shared.IDFromString(assetGroupID.String)
	}
	// Convert asset_group_ids string array to []shared.ID
	s.AssetGroupIDs = make([]shared.ID, 0, len(assetGroupIDs))
	for _, idStr := range assetGroupIDs {
		if id, err := shared.IDFromString(idStr); err == nil {
			s.AssetGroupIDs = append(s.AssetGroupIDs, id)
		}
	}
	s.Targets = targets // Set direct targets
	s.ScanType = scan.ScanType(scanType)
	s.ScheduleType = scan.ScheduleType(scheduleType)
	s.Status = scan.Status(status)
	s.Tags = tags

	s.Description = description.String
	s.ScannerName = scannerName.String
	s.ScheduleCron = scheduleCron.String
	s.LastRunStatus = lastRunStatus.String
	s.ScheduleTimezone = scheduleTimezone.String
	if s.ScheduleTimezone == "" {
		s.ScheduleTimezone = "UTC"
	}

	if pipelineID.Valid {
		pid, _ := shared.IDFromString(pipelineID.String)
		s.PipelineID = &pid
	}
	if lastRunID.Valid {
		lid, _ := shared.IDFromString(lastRunID.String)
		s.LastRunID = &lid
	}
	if createdBy.Valid {
		cid, _ := shared.IDFromString(createdBy.String)
		s.CreatedBy = &cid
	}

	if len(scannerConfig) > 0 {
		_ = json.Unmarshal(scannerConfig, &s.ScannerConfig)
	} else {
		s.ScannerConfig = make(map[string]any)
	}

	return s, nil
}

// scanFromRows scans a row from Rows into a Scan.
func (r *ScanRepository) scanFromRows(rows *sql.Rows) (*scan.Scan, error) {
	s := &scan.Scan{}
	var (
		id               string
		tenantID         string
		assetGroupID     sql.NullString // Now nullable
		assetGroupIDs    pq.StringArray // Multiple asset groups
		targets          pq.StringArray // Direct targets
		scanType         string
		scheduleType     string
		status           string
		tags             pq.StringArray
		scannerConfig    []byte
		pipelineID       sql.NullString
		lastRunID        sql.NullString
		createdBy        sql.NullString
		description      sql.NullString
		scannerName      sql.NullString
		scheduleCron     sql.NullString
		lastRunStatus    sql.NullString
		scheduleTimezone sql.NullString
	)

	err := rows.Scan(
		&id,
		&tenantID,
		&s.Name,
		&description,
		&assetGroupID,
		&assetGroupIDs, // Multiple asset groups
		&targets,       // Direct targets
		&scanType,
		&pipelineID,
		&scannerName,
		&scannerConfig,
		&s.TargetsPerJob,
		&scheduleType,
		&scheduleCron,
		&s.ScheduleDay,
		&s.ScheduleTime,
		&scheduleTimezone,
		&s.NextRunAt,
		&tags,
		&s.RunOnTenantRunner,
		&status,
		&lastRunID,
		&s.LastRunAt,
		&lastRunStatus,
		&s.TotalRuns,
		&s.SuccessfulRuns,
		&s.FailedRuns,
		&createdBy,
		&s.CreatedAt,
		&s.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan scan: %w", err)
	}

	s.ID, _ = shared.IDFromString(id)
	s.TenantID, _ = shared.IDFromString(tenantID)
	// Handle nullable asset_group_id
	if assetGroupID.Valid {
		s.AssetGroupID, _ = shared.IDFromString(assetGroupID.String)
	}
	// Convert asset_group_ids string array to []shared.ID
	s.AssetGroupIDs = make([]shared.ID, 0, len(assetGroupIDs))
	for _, idStr := range assetGroupIDs {
		if id, err := shared.IDFromString(idStr); err == nil {
			s.AssetGroupIDs = append(s.AssetGroupIDs, id)
		}
	}
	s.Targets = targets // Set direct targets
	s.ScanType = scan.ScanType(scanType)
	s.ScheduleType = scan.ScheduleType(scheduleType)
	s.Status = scan.Status(status)
	s.Tags = tags

	s.Description = description.String
	s.ScannerName = scannerName.String
	s.ScheduleCron = scheduleCron.String
	s.LastRunStatus = lastRunStatus.String
	s.ScheduleTimezone = scheduleTimezone.String
	if s.ScheduleTimezone == "" {
		s.ScheduleTimezone = "UTC"
	}

	if pipelineID.Valid {
		pid, _ := shared.IDFromString(pipelineID.String)
		s.PipelineID = &pid
	}
	if lastRunID.Valid {
		lid, _ := shared.IDFromString(lastRunID.String)
		s.LastRunID = &lid
	}
	if createdBy.Valid {
		cid, _ := shared.IDFromString(createdBy.String)
		s.CreatedBy = &cid
	}

	if len(scannerConfig) > 0 {
		_ = json.Unmarshal(scannerConfig, &s.ScannerConfig)
	} else {
		s.ScannerConfig = make(map[string]any)
	}

	return s, nil
}
