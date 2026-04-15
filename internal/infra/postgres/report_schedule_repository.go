package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/reportschedule"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// ReportScheduleRepository implements reportschedule.Repository using PostgreSQL.
type ReportScheduleRepository struct {
	db *DB
}

// NewReportScheduleRepository creates a new ReportScheduleRepository.
func NewReportScheduleRepository(db *DB) *ReportScheduleRepository {
	return &ReportScheduleRepository{db: db}
}

// Create persists a new report schedule.
func (r *ReportScheduleRepository) Create(ctx context.Context, s *reportschedule.ReportSchedule) error {
	options, _ := json.Marshal(s.Options())
	recipients, _ := json.Marshal(s.Recipients())

	query := `
		INSERT INTO report_schedules (
			id, tenant_id, name, report_type, format, options, recipients,
			delivery_channel, integration_id, cron_expression, timezone,
			is_active, created_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`
	_, err := r.db.ExecContext(ctx, query,
		s.ID().String(), s.TenantID().String(), s.Name(), s.ReportType(), s.Format(),
		options, recipients,
		s.DeliveryChannel(), nullIDPtr(s.IntegrationID()),
		s.CronExpression(), s.Timezone(),
		s.IsActive(), nullIDPtr(s.CreatedBy()),
		s.CreatedAt(), s.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("create report schedule: %w", err)
	}
	return nil
}

// GetByID retrieves a report schedule by ID.
func (r *ReportScheduleRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*reportschedule.ReportSchedule, error) {
	query := `
		SELECT id, tenant_id, name, report_type, format, options, recipients,
			delivery_channel, integration_id, cron_expression, timezone,
			is_active, last_run_at, last_status, next_run_at, run_count,
			created_by, created_at, updated_at
		FROM report_schedules
		WHERE tenant_id = $1 AND id = $2
	`
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scan(row)
}

// Update updates a report schedule.
func (r *ReportScheduleRepository) Update(ctx context.Context, s *reportschedule.ReportSchedule) error {
	options, _ := json.Marshal(s.Options())
	recipients, _ := json.Marshal(s.Recipients())

	query := `
		UPDATE report_schedules SET
			name = $3, report_type = $4, format = $5, options = $6, recipients = $7,
			delivery_channel = $8, integration_id = $9, cron_expression = $10, timezone = $11,
			is_active = $12, last_run_at = $13, last_status = $14, next_run_at = $15,
			run_count = $16, updated_at = $17
		WHERE tenant_id = $1 AND id = $2
	`
	_, err := r.db.ExecContext(ctx, query,
		s.TenantID().String(), s.ID().String(),
		s.Name(), s.ReportType(), s.Format(), options, recipients,
		s.DeliveryChannel(), nullIDPtr(s.IntegrationID()),
		s.CronExpression(), s.Timezone(),
		s.IsActive(), s.LastRunAt(), s.LastStatus(), s.NextRunAt(),
		s.RunCount(), s.UpdatedAt(),
	)
	return err
}

// Delete removes a report schedule.
func (r *ReportScheduleRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM report_schedules WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String(),
	)
	return err
}

// List returns report schedules for a tenant.
func (r *ReportScheduleRepository) List(ctx context.Context, filter reportschedule.ScheduleFilter, page pagination.Pagination) (pagination.Result[*reportschedule.ReportSchedule], error) {
	where := "WHERE tenant_id = $1"
	args := []any{filter.TenantID.String()}
	idx := 2

	if filter.IsActive != nil {
		where += fmt.Sprintf(" AND is_active = $%d", idx)
		args = append(args, *filter.IsActive)
		idx++
	}

	// Count
	var total int64
	countQ := "SELECT COUNT(*) FROM report_schedules " + where
	if err := r.db.QueryRowContext(ctx, countQ, args...).Scan(&total); err != nil {
		return pagination.Result[*reportschedule.ReportSchedule]{}, err
	}

	if total == 0 {
		return pagination.NewResult([]*reportschedule.ReportSchedule{}, 0, page), nil
	}

	query := fmt.Sprintf(`
		SELECT id, tenant_id, name, report_type, format, options, recipients,
			delivery_channel, integration_id, cron_expression, timezone,
			is_active, last_run_at, last_status, next_run_at, run_count,
			created_by, created_at, updated_at
		FROM report_schedules %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, where, idx, idx+1)
	args = append(args, page.Limit(), page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*reportschedule.ReportSchedule]{}, err
	}
	defer func() { _ = rows.Close() }()

	items := make([]*reportschedule.ReportSchedule, 0)
	for rows.Next() {
		s, err := r.scan(rows)
		if err != nil {
			return pagination.Result[*reportschedule.ReportSchedule]{}, err
		}
		items = append(items, s)
	}

	return pagination.NewResult(items, total, page), nil
}

// ListDue returns schedules that are due for execution.
func (r *ReportScheduleRepository) ListDue(ctx context.Context, now time.Time) ([]*reportschedule.ReportSchedule, error) {
	query := `
		SELECT id, tenant_id, name, report_type, format, options, recipients,
			delivery_channel, integration_id, cron_expression, timezone,
			is_active, last_run_at, last_status, next_run_at, run_count,
			created_by, created_at, updated_at
		FROM report_schedules
		WHERE is_active = true AND (next_run_at IS NULL OR next_run_at <= $1)
	`
	rows, err := r.db.QueryContext(ctx, query, now)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var items []*reportschedule.ReportSchedule
	for rows.Next() {
		s, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, s)
	}
	return items, nil
}

type reportScanner interface {
	Scan(dest ...any) error
}

func (r *ReportScheduleRepository) scan(row reportScanner) (*reportschedule.ReportSchedule, error) {
	var (
		id, tenantID                                                                  string
		name, reportType, format                                                      string
		optionsJSON, recipientsJSON                                                   []byte
		deliveryChannel                                                               string
		integrationID                                                                 sql.NullString
		cronExpression, timezone                                                      string
		isActive                                                                      bool
		lastRunAt, nextRunAt                                                           *time.Time
		lastStatus                                                                    string
		runCount                                                                      int
		createdByStr                                                                  sql.NullString
		createdAt, updatedAt                                                          time.Time
	)

	err := row.Scan(
		&id, &tenantID, &name, &reportType, &format, &optionsJSON, &recipientsJSON,
		&deliveryChannel, &integrationID, &cronExpression, &timezone,
		&isActive, &lastRunAt, &lastStatus, &nextRunAt, &runCount,
		&createdByStr, &createdAt, &updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, err
	}

	var options map[string]any
	_ = json.Unmarshal(optionsJSON, &options)
	if options == nil {
		options = map[string]any{}
	}

	var recipients []reportschedule.Recipient
	_ = json.Unmarshal(recipientsJSON, &recipients)

	var createdBy *shared.ID
	if createdByStr.Valid {
		p := shared.MustIDFromString(createdByStr.String)
		createdBy = &p
	}

	var intID *shared.ID
	if integrationID.Valid {
		p := shared.MustIDFromString(integrationID.String)
		intID = &p
	}

	return reportschedule.ReconstituteReportSchedule(
		shared.MustIDFromString(id),
		shared.MustIDFromString(tenantID),
		name, reportType, format,
		options, recipients,
		deliveryChannel, intID,
		cronExpression, timezone,
		isActive, lastRunAt, nextRunAt, lastStatus, runCount,
		createdBy, createdAt, updatedAt,
	), nil
}
