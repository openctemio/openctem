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

	"github.com/openctemio/api/pkg/domain/scope"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// ScopeScheduleRepository implements scope.ScheduleRepository using PostgreSQL.
type ScopeScheduleRepository struct {
	db *DB
}

// NewScopeScheduleRepository creates a new ScopeScheduleRepository.
func NewScopeScheduleRepository(db *DB) *ScopeScheduleRepository {
	return &ScopeScheduleRepository{db: db}
}

const scopeScheduleSelectQuery = `
	SELECT id, tenant_id, name, description, scan_type, target_scope, target_ids, target_tags,
	       scanner_configs, schedule_type, cron_expression, interval_hours, enabled,
	       last_run_at, last_run_status, next_run_at, notify_on_completion, notify_on_findings,
	       notification_channels, created_by, created_at, updated_at
	FROM scan_schedules
`

func (r *ScopeScheduleRepository) scanSchedule(row interface{ Scan(...any) error }) (*scope.Schedule, error) {
	var (
		id                   string
		tenantID             string
		name                 string
		description          sql.NullString
		scanType             string
		targetScope          string
		targetIDs            pq.StringArray
		targetTags           pq.StringArray
		scannerConfigs       []byte
		scheduleType         string
		cronExpression       sql.NullString
		intervalHours        sql.NullInt64
		enabled              bool
		lastRunAt            sql.NullTime
		lastRunStatus        sql.NullString
		nextRunAt            sql.NullTime
		notifyOnCompletion   bool
		notifyOnFindings     bool
		notificationChannels []byte
		createdBy            sql.NullString
		createdAt            sql.NullTime
		updatedAt            sql.NullTime
	)

	err := row.Scan(
		&id, &tenantID, &name, &description, &scanType, &targetScope, &targetIDs, &targetTags,
		&scannerConfigs, &scheduleType, &cronExpression, &intervalHours, &enabled,
		&lastRunAt, &lastRunStatus, &nextRunAt, &notifyOnCompletion, &notifyOnFindings,
		&notificationChannels, &createdBy, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	sid, _ := shared.IDFromString(id)
	tntID, _ := shared.IDFromString(tenantID)

	// Parse target IDs
	var parsedTargetIDs []shared.ID
	for _, tidStr := range targetIDs {
		if tid, err := shared.IDFromString(tidStr); err == nil {
			parsedTargetIDs = append(parsedTargetIDs, tid)
		}
	}

	// Parse scanner configs
	var configs map[string]interface{}
	if len(scannerConfigs) > 0 {
		if err := json.Unmarshal(scannerConfigs, &configs); err != nil {
			configs = make(map[string]interface{})
		}
	} else {
		configs = make(map[string]interface{})
	}

	// Parse notification channels
	var channels []string
	if len(notificationChannels) > 0 {
		if err := json.Unmarshal(notificationChannels, &channels); err != nil {
			channels = []string{"email"}
		}
	} else {
		channels = []string{"email"}
	}

	var lastRun *time.Time
	if lastRunAt.Valid {
		lastRun = &lastRunAt.Time
	}

	var nextRun *time.Time
	if nextRunAt.Valid {
		nextRun = &nextRunAt.Time
	}

	return scope.ReconstituteSchedule(
		sid,
		tntID,
		name,
		description.String,
		scope.ScanType(scanType),
		scope.TargetScope(targetScope),
		parsedTargetIDs,
		[]string(targetTags),
		configs,
		scope.ScheduleType(scheduleType),
		cronExpression.String,
		int(intervalHours.Int64),
		enabled,
		lastRun,
		lastRunStatus.String,
		nextRun,
		notifyOnCompletion,
		notifyOnFindings,
		channels,
		createdBy.String,
		createdAt.Time,
		updatedAt.Time,
	), nil
}

// Create persists a new scan schedule.
func (r *ScopeScheduleRepository) Create(ctx context.Context, schedule *scope.Schedule) error {
	// Convert target IDs to string array
	targetIDStrs := make([]string, len(schedule.TargetIDs()))
	for i, tid := range schedule.TargetIDs() {
		targetIDStrs[i] = tid.String()
	}

	// Marshal scanner configs
	scannerConfigsJSON, err := json.Marshal(schedule.ScannerConfigs())
	if err != nil {
		scannerConfigsJSON = []byte("{}")
	}

	// Marshal notification channels
	notificationChannelsJSON, err := json.Marshal(schedule.NotificationChannels())
	if err != nil {
		notificationChannelsJSON = []byte(`["email"]`)
	}

	query := `
		INSERT INTO scan_schedules (
			id, tenant_id, name, description, scan_type, target_scope, target_ids, target_tags,
			scanner_configs, schedule_type, cron_expression, interval_hours, enabled,
			last_run_at, last_run_status, next_run_at, notify_on_completion, notify_on_findings,
			notification_channels, created_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
	`

	_, err = r.db.ExecContext(ctx, query,
		schedule.ID().String(),
		schedule.TenantID().String(),
		schedule.Name(),
		nullString(schedule.Description()),
		schedule.ScanType().String(),
		schedule.TargetScope().String(),
		pq.StringArray(targetIDStrs),
		pq.StringArray(schedule.TargetTags()),
		scannerConfigsJSON,
		schedule.ScheduleType().String(),
		nullString(schedule.CronExpression()),
		nullInt64(schedule.IntervalHours()),
		schedule.Enabled(),
		nullTime(schedule.LastRunAt()),
		nullString(schedule.LastRunStatus()),
		nullTime(schedule.NextRunAt()),
		schedule.NotifyOnCompletion(),
		schedule.NotifyOnFindings(),
		notificationChannelsJSON,
		nullString(schedule.CreatedBy()),
		schedule.CreatedAt(),
		schedule.UpdatedAt(),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return scope.ErrScheduleAlreadyExists
		}
		return fmt.Errorf("failed to create scan schedule: %w", err)
	}

	return nil
}

// GetByID retrieves a scan schedule by its ID.
func (r *ScopeScheduleRepository) GetByID(ctx context.Context, id shared.ID) (*scope.Schedule, error) {
	query := scopeScheduleSelectQuery + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())

	schedule, err := r.scanSchedule(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, scope.ErrScheduleNotFound
		}
		return nil, fmt.Errorf("failed to get scan schedule: %w", err)
	}

	return schedule, nil
}

// Update updates an existing scan schedule.
func (r *ScopeScheduleRepository) Update(ctx context.Context, schedule *scope.Schedule) error {
	// Convert target IDs to string array
	targetIDStrs := make([]string, len(schedule.TargetIDs()))
	for i, tid := range schedule.TargetIDs() {
		targetIDStrs[i] = tid.String()
	}

	// Marshal scanner configs
	scannerConfigsJSON, err := json.Marshal(schedule.ScannerConfigs())
	if err != nil {
		scannerConfigsJSON = []byte("{}")
	}

	// Marshal notification channels
	notificationChannelsJSON, err := json.Marshal(schedule.NotificationChannels())
	if err != nil {
		notificationChannelsJSON = []byte(`["email"]`)
	}

	query := `
		UPDATE scan_schedules SET
			name = $2,
			description = $3,
			target_scope = $4,
			target_ids = $5,
			target_tags = $6,
			scanner_configs = $7,
			schedule_type = $8,
			cron_expression = $9,
			interval_hours = $10,
			enabled = $11,
			last_run_at = $12,
			last_run_status = $13,
			next_run_at = $14,
			notify_on_completion = $15,
			notify_on_findings = $16,
			notification_channels = $17,
			updated_at = $18
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		schedule.ID().String(),
		schedule.Name(),
		nullString(schedule.Description()),
		schedule.TargetScope().String(),
		pq.StringArray(targetIDStrs),
		pq.StringArray(schedule.TargetTags()),
		scannerConfigsJSON,
		schedule.ScheduleType().String(),
		nullString(schedule.CronExpression()),
		nullInt64(schedule.IntervalHours()),
		schedule.Enabled(),
		nullTime(schedule.LastRunAt()),
		nullString(schedule.LastRunStatus()),
		nullTime(schedule.NextRunAt()),
		schedule.NotifyOnCompletion(),
		schedule.NotifyOnFindings(),
		notificationChannelsJSON,
		schedule.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to update scan schedule: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return scope.ErrScheduleNotFound
	}

	return nil
}

// Delete removes a scan schedule by its ID.
func (r *ScopeScheduleRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM scan_schedules WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete scan schedule: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return scope.ErrScheduleNotFound
	}

	return nil
}

// List retrieves scan schedules with filtering and pagination.
func (r *ScopeScheduleRepository) List(ctx context.Context, filter scope.ScheduleFilter, page pagination.Pagination) (pagination.Result[*scope.Schedule], error) {
	var conditions []string
	var args []any
	argNum := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argNum))
		args = append(args, *filter.TenantID)
		argNum++
	}

	if len(filter.ScanTypes) > 0 {
		types := make([]string, len(filter.ScanTypes))
		for i, t := range filter.ScanTypes {
			types[i] = t.String()
		}
		conditions = append(conditions, fmt.Sprintf("scan_type = ANY($%d)", argNum))
		args = append(args, pq.StringArray(types))
		argNum++
	}

	if len(filter.ScheduleTypes) > 0 {
		types := make([]string, len(filter.ScheduleTypes))
		for i, t := range filter.ScheduleTypes {
			types[i] = t.String()
		}
		conditions = append(conditions, fmt.Sprintf("schedule_type = ANY($%d)", argNum))
		args = append(args, pq.StringArray(types))
		argNum++
	}

	if filter.Enabled != nil {
		conditions = append(conditions, fmt.Sprintf("enabled = $%d", argNum))
		args = append(args, *filter.Enabled)
		argNum++
	}

	if filter.Search != nil && *filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argNum, argNum))
		args = append(args, wrapLikePattern(*filter.Search))
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := "SELECT COUNT(*) FROM scan_schedules" + whereClause
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return pagination.Result[*scope.Schedule]{}, fmt.Errorf("failed to count scan schedules: %w", err)
	}

	// Query with pagination
	query := scopeScheduleSelectQuery + whereClause + " ORDER BY created_at DESC" +
		fmt.Sprintf(" LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, page.Limit(), page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*scope.Schedule]{}, fmt.Errorf("failed to list scan schedules: %w", err)
	}
	defer rows.Close()

	var schedules []*scope.Schedule
	for rows.Next() {
		schedule, err := r.scanSchedule(rows)
		if err != nil {
			return pagination.Result[*scope.Schedule]{}, fmt.Errorf("failed to scan schedule: %w", err)
		}
		schedules = append(schedules, schedule)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*scope.Schedule]{}, fmt.Errorf("iterate schedules: %w", err)
	}

	return pagination.NewResult(schedules, total, page), nil
}

// ListDue retrieves all enabled schedules that are due to run.
func (r *ScopeScheduleRepository) ListDue(ctx context.Context) ([]*scope.Schedule, error) {
	query := scopeScheduleSelectQuery + `
		WHERE enabled = true
		AND (next_run_at IS NULL OR next_run_at <= NOW())
		AND schedule_type != 'manual'
		ORDER BY next_run_at ASC NULLS FIRST`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list due schedules: %w", err)
	}
	defer rows.Close()

	var schedules []*scope.Schedule
	for rows.Next() {
		schedule, err := r.scanSchedule(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan schedule: %w", err)
		}
		schedules = append(schedules, schedule)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate due schedules: %w", err)
	}

	return schedules, nil
}

// Count returns the total number of scan schedules matching the filter.
func (r *ScopeScheduleRepository) Count(ctx context.Context, filter scope.ScheduleFilter) (int64, error) {
	var conditions []string
	var args []any
	argNum := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argNum))
		args = append(args, *filter.TenantID)
		argNum++
	}

	if filter.Enabled != nil {
		conditions = append(conditions, fmt.Sprintf("enabled = $%d", argNum))
		args = append(args, *filter.Enabled)
		argNum++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	query := "SELECT COUNT(*) FROM scan_schedules" + whereClause
	var count int64
	if err := r.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count scan schedules: %w", err)
	}

	return count, nil
}

// nullInt64 converts an int to sql.NullInt64.
func nullInt64(i int) sql.NullInt64 {
	if i == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(i), Valid: true}
}
