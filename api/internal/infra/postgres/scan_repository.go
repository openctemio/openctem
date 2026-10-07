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

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
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

	var scanWorkflowID *string
	if s.ScanWorkflowID != nil {
		pid := s.ScanWorkflowID.String()
		scanWorkflowID = &pid
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

	// Handle nullable profile_id
	var profileID *string
	if s.ProfileID != nil {
		pid := s.ProfileID.String()
		profileID = &pid
	}

	// Convert AssetGroupIDs to string array for database
	assetGroupIDStrings := make([]string, len(s.AssetGroupIDs))
	for i, id := range s.AssetGroupIDs {
		assetGroupIDStrings[i] = id.String()
	}

	// Default sensor preference and timeout
	sensorPref := string(s.SensorPreference)
	if sensorPref == "" {
		sensorPref = string(scan.SensorPreferenceAuto)
	}
	timeoutSecs := s.TimeoutSeconds
	if timeoutSecs <= 0 {
		timeoutSecs = scan.DefaultScanTimeoutSeconds
	}
	retryBackoff := s.RetryBackoffSeconds
	if retryBackoff <= 0 {
		retryBackoff = scan.DefaultRetryBackoffSeconds
	}

	query := `
		INSERT INTO scans (
			id, tenant_id, name, description,
			asset_group_id, asset_group_ids, targets, scan_type, scan_workflow_id,
			scanner_name, scanner_config, targets_per_job,
			schedule_type, schedule_cron, schedule_day, schedule_time, schedule_timezone, next_run_at,
			tags, run_on_tenant_runner, sensor_preference, profile_id, timeout_seconds,
			max_retries, retry_backoff_seconds, status,
			last_run_id, last_run_at, last_run_status,
			total_runs, successful_runs, failed_runs,
			created_by, created_at, updated_at, scan_zone_id, ad_hoc, schedule_rrule
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, NULLIF($38, ''))
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
		scanWorkflowID,
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
		sensorPref,
		profileID,
		timeoutSecs,
		s.MaxRetries,
		retryBackoff,
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
		nullableIDString(s.ScanZoneID),
		s.AdHoc,
		s.ScheduleRRule,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "scan with this name already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create scan: %w", err)
	}

	return nil
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
	// OrderBy is a constant expression chosen from the domain whitelist.
	baseQuery += fmt.Sprintf(" ORDER BY %s LIMIT %d OFFSET %d", filter.Sort.OrderBy(), page.PerPage, offset)

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

	var scanWorkflowID *string
	if s.ScanWorkflowID != nil {
		pid := s.ScanWorkflowID.String()
		scanWorkflowID = &pid
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

	// Handle nullable profile_id
	var profileID *string
	if s.ProfileID != nil {
		pid := s.ProfileID.String()
		profileID = &pid
	}

	// Default sensor preference and timeout
	sensorPref := string(s.SensorPreference)
	if sensorPref == "" {
		sensorPref = string(scan.SensorPreferenceAuto)
	}
	timeoutSecs := s.TimeoutSeconds
	if timeoutSecs <= 0 {
		timeoutSecs = scan.DefaultScanTimeoutSeconds
	}
	retryBackoff := s.RetryBackoffSeconds
	if retryBackoff <= 0 {
		retryBackoff = scan.DefaultRetryBackoffSeconds
	}

	query := `
		UPDATE scans
		SET name = $2, description = $3,
		    asset_group_id = $4, asset_group_ids = $5, targets = $6, scan_type = $7, scan_workflow_id = $8,
		    scanner_name = $9, scanner_config = $10, targets_per_job = $11,
		    schedule_type = $12, schedule_cron = $13, schedule_day = $14, schedule_time = $15, schedule_timezone = $16, next_run_at = $17,
		    tags = $18, run_on_tenant_runner = $19, sensor_preference = $20, profile_id = $21, timeout_seconds = $22,
		    max_retries = $23, retry_backoff_seconds = $24, status = $25,
		    updated_at = $26, scan_zone_id = $28, ad_hoc = $29, schedule_rrule = NULLIF($30, '')
		WHERE id = $1 AND tenant_id = $27
	`

	result, err := r.db.ExecContext(ctx, query,
		s.ID.String(),
		s.Name,
		s.Description,
		assetGroupID,                  // Now nullable (legacy single)
		pq.Array(assetGroupIDStrings), // Multiple asset groups
		pq.Array(s.Targets),           // Direct targets
		string(s.ScanType),
		scanWorkflowID,
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
		sensorPref,
		profileID,
		timeoutSecs,
		s.MaxRetries,
		retryBackoff,
		string(s.Status),
		s.UpdatedAt,
		s.TenantID.String(), // $27 — tenant scope: never update another tenant's scan
		nullableIDString(s.ScanZoneID),
		s.AdHoc, // $29
		s.ScheduleRRule,
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

// Delete deletes a scan of tenantID. A scan of another tenant is not found.
func (r *ScanRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	query := "DELETE FROM scans WHERE tenant_id = $1 AND id = $2"
	result, err := r.db.ExecContext(ctx, query, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("failed to delete scan: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// CountScheduledWithoutNextRun counts active scans that declare a schedule but
// have no next_run_at, and returns their names.
//
// The pairing matters: ListDueForExecution requires `next_run_at IS NOT NULL`,
// so a row in this state can never be selected, never runs, and never errors —
// while the UI keeps describing it as "daily". Four such rows were found on a
// live database, the oldest dormant since April.
//
// This deliberately reports rather than repairs. Recomputing next_run_at here
// would be a one-line change and would silently activate every dormant scan at
// once — including, on the database where this was found, a DAST scan pointed at
// the public web. Waking that up as a side effect of a deploy is not a decision
// a background loop should make. Editing the scan already recomputes the field
// through SetSchedule, so the operator has a correct path once they know.
func (r *ScanRepository) CountScheduledWithoutNextRun(ctx context.Context) (int, []string, error) {
	const query = `
		SELECT name
		FROM scans
		WHERE status = 'active'
		  AND schedule_type != 'manual'
		  AND next_run_at IS NULL
		ORDER BY created_at
	`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to count scheduled scans without next_run_at: %w", err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return 0, nil, fmt.Errorf("failed to scan name: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	return len(names), names, nil
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
func (r *ScanRepository) UpdateNextRunAt(ctx context.Context, tenantID, id shared.ID, nextRunAt *time.Time) error {
	query := "UPDATE scans SET next_run_at = $2, updated_at = NOW() WHERE id = $1 AND tenant_id = $3"
	_, err := r.db.ExecContext(ctx, query, id.String(), nextRunAt, tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to update next_run_at: %w", err)
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
		WHERE tenant_id = $1 AND ad_hoc = false
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
		WHERE tenant_id = $1 AND ad_hoc = false
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
		WHERE tenant_id = $1 AND ad_hoc = false
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

// ListByScanWorkflowID lists all scans using a scan workflow.
func (r *ScanRepository) ListByScanWorkflowID(ctx context.Context, scanWorkflowID shared.ID) ([]*scan.Scan, error) {
	query := r.selectQuery() + " WHERE scan_workflow_id = $1 ORDER BY name"
	rows, err := r.db.QueryContext(ctx, query, scanWorkflowID.String())
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

// ClaimScheduledRun claims one due occurrence of a scheduled scan: it moves
// next_run_at from dueAt to next, and only if next_run_at still equals dueAt
// and the scan is still active. Exactly one scheduler (on any replica) wins a
// given occurrence; the losers see false and skip it.
//
// This replaces a session-level pg_try_advisory_lock taken through the
// connection pool. Lock and unlock ran on whatever pooled connection each
// statement got: the unlock usually hit a different session, released nothing
// (its result was ignored), and the lock stayed held by the first session
// until that connection closed — from then on every attempt to schedule that
// scan, on every replica, saw "locked by another instance" and skipped it.
func (r *ScanRepository) ClaimScheduledRun(ctx context.Context, tenantID, id shared.ID, dueAt time.Time, next *time.Time) (bool, error) {
	const query = `
		UPDATE scans
		SET next_run_at = $3, updated_at = NOW()
		WHERE id = $1 AND next_run_at = $2 AND status = 'active' AND tenant_id = $4
	`
	res, err := r.db.ExecContext(ctx, query, id.String(), dueAt, next, tenantID.String())
	if err != nil {
		return false, fmt.Errorf("failed to claim scheduled run for scan %s: %w", id.String(), err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// DeferScheduledRun moves a scheduled scan whose run a freeze window stopped
// to until: next_run_at changes from from (nil when the schedule had no
// further occurrence) to until, only if it still holds from and the scan is
// active. Tenant-scoped.
func (r *ScanRepository) DeferScheduledRun(ctx context.Context, tenantID, id shared.ID, from *time.Time, until time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE scans
		SET next_run_at = $3, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $4 AND status = 'active'
		  AND next_run_at IS NOT DISTINCT FROM $2`,
		id.String(), nullTime(from), until, tenantID.String())
	if err != nil {
		return false, fmt.Errorf("failed to defer scheduled run for scan %s: %w", id.String(), err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// selectQuery returns the base SELECT query.
// ListOptInScans lists the tenant's scans whose scanner_config asks for
// out-of-band callbacks (allow_interactsh true, as boolean or string) or
// names custom templates, newest first, at most limit (research/25 D3
// banner). Tenant-scoped.
func (r *ScanRepository) ListOptInScans(ctx context.Context, tenantID shared.ID, limit int) ([]*scan.Scan, error) {
	query := r.selectQuery() + `
		WHERE tenant_id = $1
		  AND (lower(scanner_config->>'allow_interactsh') = 'true'
		       OR (jsonb_typeof(scanner_config->'custom_template_ids') = 'array'
		           AND jsonb_array_length(scanner_config->'custom_template_ids') > 0))
		ORDER BY created_at DESC
		LIMIT $2`
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("list opt-in scans: %w", err)
	}
	defer rows.Close()
	var out []*scan.Scan
	for rows.Next() {
		s, err := r.scanFromRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *ScanRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, name, description,
		       asset_group_id, asset_group_ids, targets, scan_type, scan_workflow_id,
		       scanner_name, scanner_config, targets_per_job,
		       schedule_type, schedule_cron, schedule_day, schedule_time, schedule_timezone, next_run_at,
		       tags, run_on_tenant_runner, sensor_preference, profile_id, timeout_seconds,
		       max_retries, retry_backoff_seconds, status,
		       last_run_id, last_run_at, last_run_status,
		       total_runs, successful_runs, failed_runs,
		       created_by, created_at, updated_at, scan_zone_id, ad_hoc, partial_runs,
		       COALESCE(schedule_rrule, ''), blocked_runs
		FROM scans
	`
}

// scanRowReader abstracts sql.Row and sql.Rows for shared scanning logic.
type scanRowReader interface {
	Scan(dest ...any) error
}

// readScan scans a single scan row using a generic row reader.
// This is the single source of truth for parsing scan rows from DB.
func (r *ScanRepository) readScan(reader scanRowReader) (*scan.Scan, error) {
	s := &scan.Scan{}
	var (
		id                  string
		tenantID            string
		assetGroupID        sql.NullString
		assetGroupIDs       pq.StringArray
		targets             pq.StringArray
		scanType            string
		scheduleType        string
		status              string
		tags                pq.StringArray
		scannerConfig       []byte
		scanWorkflowID      sql.NullString
		profileID           sql.NullString
		sensorPreference    sql.NullString
		timeoutSeconds      sql.NullInt64
		maxRetries          sql.NullInt64
		retryBackoffSeconds sql.NullInt64
		lastRunID           sql.NullString
		createdBy           sql.NullString
		description         sql.NullString
		scannerName         sql.NullString
		scheduleCron        sql.NullString
		lastRunStatus       sql.NullString
		scheduleTimezone    sql.NullString
		scanZoneID          sql.NullString
	)

	err := reader.Scan(
		&id,
		&tenantID,
		&s.Name,
		&description,
		&assetGroupID,
		&assetGroupIDs,
		&targets,
		&scanType,
		&scanWorkflowID,
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
		&sensorPreference,
		&profileID,
		&timeoutSeconds,
		&maxRetries,
		&retryBackoffSeconds,
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
		&scanZoneID,
		&s.AdHoc,
		&s.PartialRuns,
		&s.ScheduleRRule,
		&s.BlockedRuns,
	)
	if err != nil {
		return nil, err
	}
	if scanZoneID.Valid {
		if zid, err := shared.IDFromString(scanZoneID.String); err == nil {
			s.ScanZoneID = &zid
		}
	}

	s.ID, _ = shared.IDFromString(id)
	s.TenantID, _ = shared.IDFromString(tenantID)
	if assetGroupID.Valid {
		s.AssetGroupID, _ = shared.IDFromString(assetGroupID.String)
	}
	s.AssetGroupIDs = make([]shared.ID, 0, len(assetGroupIDs))
	for _, idStr := range assetGroupIDs {
		if id, err := shared.IDFromString(idStr); err == nil {
			s.AssetGroupIDs = append(s.AssetGroupIDs, id)
		}
	}
	s.Targets = targets
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

	if sensorPreference.Valid {
		s.SensorPreference = scan.SensorPreference(sensorPreference.String)
	} else {
		s.SensorPreference = scan.SensorPreferenceAuto
	}

	if timeoutSeconds.Valid && timeoutSeconds.Int64 > 0 {
		s.TimeoutSeconds = int(timeoutSeconds.Int64)
	} else {
		s.TimeoutSeconds = scan.DefaultScanTimeoutSeconds
	}

	if maxRetries.Valid && maxRetries.Int64 >= 0 {
		s.MaxRetries = int(maxRetries.Int64)
	}
	if retryBackoffSeconds.Valid && retryBackoffSeconds.Int64 > 0 {
		s.RetryBackoffSeconds = int(retryBackoffSeconds.Int64)
	} else {
		s.RetryBackoffSeconds = scan.DefaultRetryBackoffSeconds
	}

	if scanWorkflowID.Valid {
		pid, _ := shared.IDFromString(scanWorkflowID.String)
		s.ScanWorkflowID = &pid
	}
	if profileID.Valid {
		pid, _ := shared.IDFromString(profileID.String)
		s.ProfileID = &pid
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

	if filter.ScanWorkflowID != nil {
		conditions = append(conditions, fmt.Sprintf("scan_workflow_id = $%d", argIndex))
		args = append(args, filter.ScanWorkflowID.String())
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

	if filter.ExcludeAdHoc {
		conditions = append(conditions, "ad_hoc = false")
	}
	// Archived one-off scans are never listed.
	conditions = append(conditions, "archived_at IS NULL")

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
	s, err := r.readScan(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan scan: %w", err)
	}
	return s, nil
}

// scanFromRows scans a row from Rows into a Scan.
func (r *ScanRepository) scanFromRows(rows *sql.Rows) (*scan.Scan, error) {
	s, err := r.readScan(rows)
	if err != nil {
		return nil, fmt.Errorf("failed to scan scan: %w", err)
	}
	return s, nil
}

// nullableIDString maps an optional id to a nullable SQL value.
func nullableIDString(id *shared.ID) *string {
	if id == nil || id.IsZero() {
		return nil
	}
	v := id.String()
	return &v
}
