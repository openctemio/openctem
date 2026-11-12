package postgres

// Lookup jobs (pkg/domain/lookupjob): open questions the platform asks its
// instance-scope sensors for one organization. Reads and deletes by the
// asker carry the tenant; a sensor claims and finishes by job id and its own
// sensor id only, so it can neither read another job nor move a job to
// another tenant.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/server/pkg/domain/lookupjob"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// LookupJobRepository implements lookupjob.Repository.
type LookupJobRepository struct{ db *DB }

var _ lookupjob.Repository = (*LookupJobRepository)(nil)

// NewLookupJobRepository creates the repository.
func NewLookupJobRepository(db *DB) *LookupJobRepository { return &LookupJobRepository{db: db} }

const lookupJobColumns = `id, tenant_id, capability, tool, target, input, status, sensor_id, claimed_at,
	result, error_code, created_at, expires_at, done_at`

// Create inserts an open job.
func (r *LookupJobRepository) Create(ctx context.Context, j *lookupjob.Job) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO sensor_lookup_jobs (id, tenant_id, capability, tool, target, input, status, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'open', $7, $8)`,
		j.ID.String(), j.TenantID.String(), j.Capability, j.Tool, j.Target, []byte(j.Input), j.CreatedAt, j.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create lookup job: %w", err)
	}
	return nil
}

// Claim takes the oldest open, unexpired job of one of capabilities.
func (r *LookupJobRepository) Claim(ctx context.Context, sensorID shared.ID, capabilities []string, now time.Time) (*lookupjob.Job, error) {
	row := r.db.QueryRowContext(ctx, `
		UPDATE sensor_lookup_jobs j
		SET status = 'claimed', sensor_id = $1, claimed_at = $2
		WHERE j.id = (
			SELECT id FROM sensor_lookup_jobs
			WHERE status = 'open' AND expires_at > $2 AND capability = ANY($3::text[])
			ORDER BY created_at
			LIMIT 1
			FOR UPDATE SKIP LOCKED)
		RETURNING `+lookupJobColumns,
		sensorID.String(), now, pq.Array(capabilities))
	j, err := scanLookupJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil //nolint:nilnil // no job is not an error
	}
	return j, err
}

// Finish records the outcome of a job the sensor claimed, once.
func (r *LookupJobRepository) FinishForPlatform(ctx context.Context, id, sensorID shared.ID, status string, result json.RawMessage, code string, now time.Time) (bool, error) {
	var res any
	if len(result) > 0 {
		res = []byte(result)
	}
	out, err := r.db.ExecContext(ctx, `
		UPDATE sensor_lookup_jobs
		SET status = $3, result = $4, error_code = $5, done_at = $6
		WHERE id = $1 AND sensor_id = $2 AND status = 'claimed'`,
		id.String(), sensorID.String(), status, res, code, now)
	if err != nil {
		return false, fmt.Errorf("finish lookup job: %w", err)
	}
	n, err := out.RowsAffected()
	return n == 1, err
}

// Get returns a job of the tenant.
func (r *LookupJobRepository) Get(ctx context.Context, tenantID, id shared.ID) (*lookupjob.Job, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+lookupJobColumns+` FROM sensor_lookup_jobs
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String())
	j, err := scanLookupJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, lookupjob.ErrNotFound
	}
	return j, err
}

// Delete removes a job of the tenant.
func (r *LookupJobRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sensor_lookup_jobs WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("delete lookup job: %w", err)
	}
	return nil
}

// Purge removes jobs created before t (any tenant: housekeeping of rows no
// asker reads any more).
func (r *LookupJobRepository) Purge(ctx context.Context, before time.Time) (int64, error) {
	out, err := r.db.ExecContext(ctx, `DELETE FROM sensor_lookup_jobs WHERE created_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("purge lookup jobs: %w", err)
	}
	return out.RowsAffected()
}

// EligibleSensorExists: an active, reachable instance-scope sensor (no
// organization) reporting the capability, seen since since.
func (r *LookupJobRepository) EligibleSensorExists(ctx context.Context, capability string, since time.Time) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM sensors
			WHERE scope = 'instance' AND tenant_id IS NULL
			  AND status = 'active'
			  AND health IN `+sensorDispatchableHealthSQL+`
			  AND last_seen_at >= $2
			  AND $1 = ANY(effective_capabilities))`, capability, since).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check lookup sensors: %w", err)
	}
	return ok, nil
}

func scanLookupJob(row interface{ Scan(...any) error }) (*lookupjob.Job, error) {
	var (
		j                 lookupjob.Job
		id, tenant        string
		sensorID          sql.NullString
		claimedAt, doneAt sql.NullTime
		input, result     []byte
	)
	if err := row.Scan(&id, &tenant, &j.Capability, &j.Tool, &j.Target, &input, &j.Status, &sensorID, &claimedAt,
		&result, &j.ErrorCode, &j.CreatedAt, &j.ExpiresAt, &doneAt); err != nil {
		return nil, err
	}
	var err error
	if j.ID, err = shared.IDFromString(id); err != nil {
		return nil, err
	}
	if j.TenantID, err = shared.IDFromString(tenant); err != nil {
		return nil, err
	}
	if sensorID.Valid {
		sid, err := shared.IDFromString(sensorID.String)
		if err != nil {
			return nil, err
		}
		j.SensorID = &sid
	}
	if claimedAt.Valid {
		t := claimedAt.Time
		j.ClaimedAt = &t
	}
	if doneAt.Valid {
		t := doneAt.Time
		j.DoneAt = &t
	}
	j.Input = input
	if len(result) > 0 {
		j.Result = result
	}
	return &j, nil
}
