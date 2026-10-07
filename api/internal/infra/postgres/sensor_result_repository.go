package postgres

// Sensor results without a command: the tenant policy and the quarantine
// (docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md §5.3, migration
// 000317).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/sensorresult"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SensorResultRepository implements sensorresult.Repository.
type SensorResultRepository struct {
	db *DB
}

// NewSensorResultRepository creates the repository.
func NewSensorResultRepository(db *DB) *SensorResultRepository {
	return &SensorResultRepository{db: db}
}

var _ sensorresult.Repository = (*SensorResultRepository)(nil)

// GetPolicy returns the stored policy, or the default with Stored false.
func (r *SensorResultRepository) GetPolicy(ctx context.Context, tenantID shared.ID) (sensorresult.Policy, error) {
	p := sensorresult.DefaultPolicy(tenantID)
	var (
		mode      string
		updatedBy sql.NullString
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT mode, allow_advisory_evidence, updated_by, updated_at
		FROM sensor_result_policies WHERE tenant_id = $1`, tenantID.String()).
		Scan(&mode, &p.AllowAdvisoryEvidence, &updatedBy, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil
	}
	if err != nil {
		return p, fmt.Errorf("failed to get sensor result policy: %w", err)
	}
	p.Stored = true
	if m, err := sensorresult.ParseMode(mode); err == nil {
		p.Mode = m
	}
	p.UpdatedBy = parseNullID(updatedBy)
	return p, nil
}

// SavePolicy upserts the policy and stamps updated_at.
func (r *SensorResultRepository) SavePolicy(ctx context.Context, p *sensorresult.Policy) error {
	if _, err := sensorresult.ParseMode(string(p.Mode)); err != nil {
		return err
	}
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO sensor_result_policies (tenant_id, mode, allow_advisory_evidence, updated_by, updated_at)
		VALUES ($1, $2, $3, $4::uuid, NOW())
		ON CONFLICT (tenant_id) DO UPDATE
		SET mode = EXCLUDED.mode, allow_advisory_evidence = EXCLUDED.allow_advisory_evidence,
		    updated_by = EXCLUDED.updated_by, updated_at = NOW()
		RETURNING updated_at`,
		p.TenantID.String(), string(p.Mode), p.AllowAdvisoryEvidence, nullIDString(p.UpdatedBy)).Scan(&p.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to save sensor result policy: %w", err)
	}
	p.Stored = true
	return nil
}

// Create stores an item unless the tenant's or the sensor's pending items
// reached the limit, or the payload is larger than the quarantine keeps. The
// count and the insert run under a per-tenant transaction lock, so
// concurrent reports cannot overshoot the limit.
func (r *SensorResultRepository) Create(ctx context.Context, item *sensorresult.Item, limits sensorresult.Limits) error {
	if limits.MaxPayloadBytes > 0 && len(item.Payload) > limits.MaxPayloadBytes {
		return sensorresult.ErrFull
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin quarantine insert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('sensor_result_quarantine:' || $1))`, item.TenantID.String()); err != nil {
		return fmt.Errorf("failed to lock quarantine: %w", err)
	}
	var perTenant, perSensor int
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE sensor_id = $2)
		FROM sensor_result_quarantine
		WHERE tenant_id = $1 AND status = 'pending'`, item.TenantID.String(), item.SensorID.String()).
		Scan(&perTenant, &perSensor); err != nil {
		return fmt.Errorf("failed to count quarantine: %w", err)
	}
	if (limits.MaxPendingPerTenant > 0 && perTenant >= limits.MaxPendingPerTenant) ||
		(limits.MaxPendingPerSensor > 0 && perSensor >= limits.MaxPendingPerSensor) {
		return sensorresult.ErrFull
	}

	if item.ID.IsZero() {
		item.ID = shared.NewID()
	}
	item.Status = sensorresult.StatusPending
	item.PayloadSize = len(item.Payload)
	var segment sql.NullInt32
	if item.Segment != nil {
		segment = sql.NullInt32{Int32: int32(*item.Segment), Valid: true} //nolint:gosec // a v2 segment number is bounded by the protocol limits
	}
	if err := tx.QueryRowContext(ctx, `
		INSERT INTO sensor_result_quarantine (id, tenant_id, sensor_id, sensor_type, protocol, route, report_id,
			segment, tool_name, reason, assets_count, findings_count, payload, payload_size, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'pending')
		RETURNING created_at`,
		item.ID.String(), item.TenantID.String(), item.SensorID.String(), item.SensorType, string(item.Protocol),
		item.Route, item.ReportID, segment, item.ToolName, string(item.Reason), item.AssetsCount, item.FindingsCount,
		item.Payload, item.PayloadSize).Scan(&item.CreatedAt); err != nil {
		return fmt.Errorf("failed to store quarantined result: %w", err)
	}
	return tx.Commit()
}

const sensorResultColumns = `q.id, q.tenant_id, q.sensor_id, COALESCE(s.name, ''), q.sensor_type, q.protocol, q.route,
	q.report_id, q.segment, q.tool_name, q.reason, q.assets_count, q.findings_count, q.payload_size, q.status,
	q.created_at, q.reviewed_by, q.reviewed_at, q.result`

func scanSensorResultItem(sc interface{ Scan(...any) error }, extra ...any) (*sensorresult.Item, error) {
	var (
		it                       sensorresult.Item
		id, tenantID, sensorID   string
		protocol, reason, status string
		segment                  sql.NullInt32
		reviewedBy               sql.NullString
		reviewedAt               sql.NullTime
		result                   []byte
	)
	dest := []any{&id, &tenantID, &sensorID, &it.SensorName, &it.SensorType, &protocol, &it.Route,
		&it.ReportID, &segment, &it.ToolName, &reason, &it.AssetsCount, &it.FindingsCount, &it.PayloadSize, &status,
		&it.CreatedAt, &reviewedBy, &reviewedAt, &result}
	dest = append(dest, extra...)
	if err := sc.Scan(dest...); err != nil {
		return nil, err
	}
	var err error
	if it.ID, err = shared.IDFromString(id); err != nil {
		return nil, fmt.Errorf("invalid quarantine id: %w", err)
	}
	if it.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, fmt.Errorf("invalid quarantine tenant id: %w", err)
	}
	if it.SensorID, err = shared.IDFromString(sensorID); err != nil {
		return nil, fmt.Errorf("invalid quarantine sensor id: %w", err)
	}
	it.Protocol = sensorresult.Protocol(protocol)
	it.Reason = sensorresult.Reason(reason)
	it.Status = sensorresult.Status(status)
	if segment.Valid {
		n := int(segment.Int32)
		it.Segment = &n
	}
	it.ReviewedBy = parseNullID(reviewedBy)
	if reviewedAt.Valid {
		t := reviewedAt.Time
		it.ReviewedAt = &t
	}
	if len(result) > 0 {
		it.Result = result
	}
	return &it, nil
}

// List returns a page of items without payloads, newest first.
func (r *SensorResultRepository) List(ctx context.Context, tenantID shared.ID, f sensorresult.ListFilter) ([]sensorresult.Item, int, error) {
	perPage := f.PerPage
	if perPage <= 0 || perPage > 100 {
		perPage = 25
	}
	page := f.Page
	if page <= 0 {
		page = 1
	}
	where := `q.tenant_id = $1`
	args := []any{tenantID.String()}
	if f.Status != "" {
		args = append(args, string(f.Status))
		where += fmt.Sprintf(" AND q.status = $%d", len(args))
	}
	if f.SensorID != nil {
		args = append(args, f.SensorID.String())
		where += fmt.Sprintf(" AND q.sensor_id = $%d", len(args))
	}

	var total int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensor_result_quarantine q WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count quarantined results: %w", err)
	}

	args = append(args, perPage, (page-1)*perPage)
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+sensorResultColumns+`
		FROM sensor_result_quarantine q
		LEFT JOIN sensors s ON s.id = q.sensor_id AND s.tenant_id = q.tenant_id AND NOT s.is_platform_sensor
		WHERE `+where+fmt.Sprintf(` ORDER BY q.created_at DESC, q.id LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list quarantined results: %w", err)
	}
	defer rows.Close()
	out := make([]sensorresult.Item, 0)
	for rows.Next() {
		it, err := scanSensorResultItem(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan quarantined result: %w", err)
		}
		out = append(out, *it)
	}
	return out, total, rows.Err()
}

// Get returns one item with its payload.
func (r *SensorResultRepository) Get(ctx context.Context, tenantID, id shared.ID) (*sensorresult.Item, error) {
	var payload []byte
	row := r.db.QueryRowContext(ctx, `
		SELECT `+sensorResultColumns+`, q.payload
		FROM sensor_result_quarantine q
		LEFT JOIN sensors s ON s.id = q.sensor_id AND s.tenant_id = q.tenant_id AND NOT s.is_platform_sensor
		WHERE q.tenant_id = $1 AND q.id = $2`, tenantID.String(), id.String())
	it, err := scanSensorResultItem(row, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sensorresult.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get quarantined result: %w", err)
	}
	it.Payload = payload
	return it, nil
}

// Review moves a pending item to accepted or discarded, once.
func (r *SensorResultRepository) Review(ctx context.Context, tenantID, id shared.ID, to sensorresult.Status, by shared.ID) error {
	if to != sensorresult.StatusAccepted && to != sensorresult.StatusDiscarded {
		return fmt.Errorf("%w: a review accepts or discards", shared.ErrValidation)
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE sensor_result_quarantine
		SET status = $3, reviewed_by = $4, reviewed_at = NOW(),
		    payload = CASE WHEN $3 = 'discarded' THEN NULL ELSE payload END
		WHERE tenant_id = $1 AND id = $2 AND status = 'pending'`,
		tenantID.String(), id.String(), string(to), by.String())
	if err != nil {
		return fmt.Errorf("failed to review quarantined result: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	var status string
	err = r.db.QueryRowContext(ctx, `SELECT status FROM sensor_result_quarantine WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String()).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return sensorresult.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to read quarantined result: %w", err)
	}
	return sensorresult.ErrAlreadyReviewed
}

// SetResult stores what applying an accepted item did.
func (r *SensorResultRepository) SetResult(ctx context.Context, tenantID, id shared.ID, result []byte) error {
	if _, err := r.db.ExecContext(ctx, `
		UPDATE sensor_result_quarantine SET result = $3::jsonb
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String(), string(result)); err != nil {
		return fmt.Errorf("failed to store quarantined result outcome: %w", err)
	}
	return nil
}

// PurgeReviewed deletes reviewed items older than the cutoff.
func (r *SensorResultRepository) PurgeReviewed(ctx context.Context, before time.Time) (int, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM sensor_result_quarantine WHERE status <> 'pending' AND reviewed_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("failed to purge reviewed quarantined results: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
