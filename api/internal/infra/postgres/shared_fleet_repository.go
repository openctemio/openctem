package postgres

// The console's read model of the shared sensor fleet
// (docs/rfcs/RFC-100-shared-sensors.md §12). Every query names its columns:
// job rows carry metadata only (organization, tool, state, times), never the
// payload, result or error text; the one exception is GetSharedJob, whose
// payload only the audited job view reads. Every sensor query and write is
// limited to scope = 'instance'.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// SharedFleetRepository implements sensorapp.SharedFleetStore.
type SharedFleetRepository struct {
	db *DB
}

// NewSharedFleetRepository builds the repository.
func NewSharedFleetRepository(db *DB) *SharedFleetRepository {
	return &SharedFleetRepository{db: db}
}

var _ sensorapp.SharedFleetStore = (*SharedFleetRepository)(nil)

// sharedJobTool is the tool a job's payload names (command.PayloadTool).
const sharedJobTool = `COALESCE(NULLIF(c.payload->>'scanner', ''), NULLIF(c.payload->>'preferred_tool', ''), '')`

// ListSharedSensors returns every instance sensor, newest first.
func (r *SharedFleetRepository) ListSharedSensors(ctx context.Context) ([]sensorapp.SharedFleetSensor, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT s.id, s.name, COALESCE(s.region, ''), s.status, COALESCE(s.health, ''), COALESCE(s.version, ''),
		       COALESCE(`+sensorDispatchTools("s")+`, '{}'::text[]),
		       (SELECT count(*) FROM commands ac
		         WHERE (ac.sensor_id = s.id OR ac.platform_sensor_id = s.id)
		           AND ac.status IN ('acknowledged', 'running'))::int,
		       COALESCE(s.effective_max_jobs, 0), s.last_seen_at, s.created_at
		FROM sensors s
		WHERE s.scope = 'instance'
		ORDER BY s.created_at DESC, s.id
		LIMIT 500`)
	if err != nil {
		return nil, fmt.Errorf("list shared sensors: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []sensorapp.SharedFleetSensor{}
	for rows.Next() {
		var (
			s     sensorapp.SharedFleetSensor
			id    string
			tools pq.StringArray
			seen  sql.NullTime
		)
		if err := rows.Scan(&id, &s.Name, &s.Region, &s.Status, &s.Health, &s.Version, &tools,
			&s.CurrentJobs, &s.MaxJobs, &seen, &s.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan shared sensor: %w", err)
		}
		if s.ID, err = shared.IDFromString(id); err != nil {
			return nil, err
		}
		s.Tools = []string(tools)
		if s.Tools == nil {
			s.Tools = []string{}
		}
		if seen.Valid {
			t := seen.Time
			s.LastSeenAt = &t
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// SharedQueue returns the queued and running shared jobs per tool lane and
// per organization (with the last day's completed and failed counts).
func (r *SharedFleetRepository) SharedQueue(ctx context.Context) (sensorapp.SharedQueue, error) {
	out := sensorapp.SharedQueue{Lanes: []sensorapp.SharedLane{}, Organizations: []sensorapp.SharedOrgUsage{}}
	lanes, err := r.db.QueryContext(ctx, `
		SELECT `+sharedJobTool+` AS tool,
		       count(*) FILTER (WHERE c.status = 'pending')::int,
		       count(*) FILTER (WHERE c.status IN ('acknowledged', 'running'))::int
		FROM commands c
		WHERE c.is_platform_job AND c.status IN ('pending', 'acknowledged', 'running')
		GROUP BY 1
		ORDER BY 1`)
	if err != nil {
		return out, fmt.Errorf("shared queue lanes: %w", err)
	}
	defer func() { _ = lanes.Close() }()
	for lanes.Next() {
		var l sensorapp.SharedLane
		if err := lanes.Scan(&l.Tool, &l.Queued, &l.Running); err != nil {
			return out, fmt.Errorf("scan shared lane: %w", err)
		}
		out.Lanes = append(out.Lanes, l)
	}
	if err := lanes.Err(); err != nil {
		return out, err
	}

	orgs, err := r.db.QueryContext(ctx, `
		SELECT c.tenant_id, COALESCE(t.name, ''),
		       count(*) FILTER (WHERE c.status = 'pending')::int,
		       count(*) FILTER (WHERE c.status IN ('acknowledged', 'running'))::int,
		       count(*) FILTER (WHERE c.status = 'completed' AND c.completed_at > now() - interval '24 hours')::int,
		       count(*) FILTER (WHERE c.status IN ('failed', 'expired') AND COALESCE(c.completed_at, c.created_at) > now() - interval '24 hours')::int
		FROM commands c
		LEFT JOIN tenants t ON t.id = c.tenant_id
		WHERE c.is_platform_job
		  AND (c.status IN ('pending', 'acknowledged', 'running') OR COALESCE(c.completed_at, c.created_at) > now() - interval '24 hours')
		GROUP BY c.tenant_id, t.name
		ORDER BY 4 DESC, 3 DESC, 2
		LIMIT 200`)
	if err != nil {
		return out, fmt.Errorf("shared usage per organization: %w", err)
	}
	defer func() { _ = orgs.Close() }()
	for orgs.Next() {
		var (
			u  sensorapp.SharedOrgUsage
			id string
		)
		if err := orgs.Scan(&id, &u.TenantName, &u.Queued, &u.Running, &u.Completed, &u.Failed); err != nil {
			return out, fmt.Errorf("scan shared usage: %w", err)
		}
		if u.TenantID, err = shared.IDFromString(id); err != nil {
			return out, err
		}
		out.Organizations = append(out.Organizations, u)
	}
	return out, orgs.Err()
}

const sharedJobColumns = `c.id, c.tenant_id, COALESCE(t.name, ''), c.type, ` + sharedJobTool + `, c.status,
	COALESCE(c.platform_sensor_id, CASE WHEN s.scope = 'instance' THEN c.sensor_id END), COALESCE(ps.name, s2.name, ''),
	c.created_at, c.started_at, c.completed_at`

const sharedJobFrom = `
	FROM commands c
	LEFT JOIN tenants t ON t.id = c.tenant_id
	LEFT JOIN sensors s ON s.id = c.sensor_id
	LEFT JOIN sensors ps ON ps.id = c.platform_sensor_id AND ps.scope = 'instance'
	LEFT JOIN sensors s2 ON s2.id = c.sensor_id AND s2.scope = 'instance'`

func scanSharedJob(row interface{ Scan(...any) error }, extra ...any) (sensorapp.SharedJob, error) {
	var (
		j                  sensorapp.SharedJob
		id, tid            string
		sensorID           sql.NullString
		started, completed sql.NullTime
	)
	dest := append([]any{&id, &tid, &j.TenantName, &j.Type, &j.Tool, &j.Status, &sensorID, &j.SensorName,
		&j.CreatedAt, &started, &completed}, extra...)
	if err := row.Scan(dest...); err != nil {
		return j, err
	}
	var err error
	if j.ID, err = shared.IDFromString(id); err != nil {
		return j, err
	}
	if j.TenantID, err = shared.IDFromString(tid); err != nil {
		return j, err
	}
	if sensorID.Valid {
		if sid, err := shared.IDFromString(sensorID.String); err == nil {
			j.SensorID = &sid
		}
	}
	if started.Valid {
		t := started.Time
		j.StartedAt = &t
	}
	if completed.Valid {
		t := completed.Time
		j.CompletedAt = &t
	}
	return j, nil
}

// ListSharedJobs returns shared job metadata, newest first.
func (r *SharedFleetRepository) ListSharedJobs(ctx context.Context, f sensorapp.SharedJobFilter, page pagination.Pagination) (pagination.Result[sensorapp.SharedJob], error) {
	conds := []string{"c.is_platform_job"}
	var args []any
	if f.SensorID != nil {
		args = append(args, f.SensorID.String())
		conds = append(conds, fmt.Sprintf("(c.platform_sensor_id = $%d OR c.sensor_id = $%d)", len(args), len(args)))
	}
	if f.TenantID != nil {
		args = append(args, f.TenantID.String())
		conds = append(conds, fmt.Sprintf("c.tenant_id = $%d", len(args)))
	}
	if f.Status != "" {
		args = append(args, f.Status)
		conds = append(conds, fmt.Sprintf("c.status = $%d", len(args)))
	}
	where := " WHERE " + strings.Join(conds, " AND ")
	var total int64
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM commands c`+where, args...).Scan(&total); err != nil {
		return pagination.Result[sensorapp.SharedJob]{}, fmt.Errorf("count shared jobs: %w", err)
	}
	q := `SELECT ` + sharedJobColumns + sharedJobFrom + where +
		fmt.Sprintf(" ORDER BY c.created_at DESC, c.id LIMIT %d OFFSET %d", page.PerPage, (page.Page-1)*page.PerPage)
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return pagination.Result[sensorapp.SharedJob]{}, fmt.Errorf("list shared jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	items := []sensorapp.SharedJob{}
	for rows.Next() {
		j, err := scanSharedJob(rows)
		if err != nil {
			return pagination.Result[sensorapp.SharedJob]{}, fmt.Errorf("scan shared job: %w", err)
		}
		items = append(items, j)
	}
	if err := rows.Err(); err != nil {
		return pagination.Result[sensorapp.SharedJob]{}, err
	}
	return pagination.NewResult(items, total, page), nil
}

// GetSharedJob returns one shared job's metadata and payload.
func (r *SharedFleetRepository) GetSharedJob(ctx context.Context, id shared.ID) (sensorapp.SharedJob, json.RawMessage, error) {
	var payload []byte
	j, err := scanSharedJob(r.db.QueryRowContext(ctx, `SELECT `+sharedJobColumns+`, c.payload`+sharedJobFrom+
		` WHERE c.id = $1 AND c.is_platform_job`, id.String()), &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return sensorapp.SharedJob{}, nil, fmt.Errorf("%w: shared job not found", shared.ErrNotFound)
	}
	if err != nil {
		return sensorapp.SharedJob{}, nil, fmt.Errorf("get shared job: %w", err)
	}
	return j, payload, nil
}

// GetSharedSensorState returns an instance sensor's name and status.
func (r *SharedFleetRepository) GetSharedSensorState(ctx context.Context, id shared.ID) (string, string, error) {
	var name, status string
	err := r.db.QueryRowContext(ctx, `SELECT name, status FROM sensors WHERE id = $1 AND scope = 'instance'`, id.String()).Scan(&name, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", fmt.Errorf("%w: shared sensor not found", shared.ErrNotFound)
	}
	if err != nil {
		return "", "", fmt.Errorf("read shared sensor: %w", err)
	}
	return name, status, nil
}

// SetSharedSensorStatus sets an instance sensor's status unless it is
// retired.
func (r *SharedFleetRepository) SetSharedSensorStatus(ctx context.Context, id shared.ID, status, message string) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE sensors SET status = $2, status_message = $3, updated_at = $4
		WHERE id = $1 AND scope = 'instance' AND status <> 'revoked'`, id.String(), status, message, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("set shared sensor status: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sensorapp.ErrSharedSensorRetired
	}
	return nil
}
