package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/ingestjob"
	"github.com/openctemio/api/pkg/domain/shared"
)

// IngestJobRepository implements ingestjob.Repository on PostgreSQL (RFC-005).
type IngestJobRepository struct {
	db *DB
}

// NewIngestJobRepository constructs an IngestJobRepository.
func NewIngestJobRepository(db *DB) *IngestJobRepository {
	return &IngestJobRepository{db: db}
}

const ingestJobColumns = `
	id, tenant_id, agent_id, report_id, source_type, payload, payload_sha,
	status, attempts, max_attempts, priority, result, error, locked_by, locked_at,
	available_at, created_at, updated_at`

// Enqueue inserts a pending job, or returns the existing one on idempotency
// conflict (tenant_id, report_id, payload_sha).
func (r *IngestJobRepository) Enqueue(ctx context.Context, job *ingestjob.Job) (*ingestjob.Job, bool, error) {
	query := `
		INSERT INTO ingest_jobs (
			id, tenant_id, agent_id, report_id, source_type, payload, payload_sha,
			status, attempts, max_attempts, priority, available_at, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (tenant_id, report_id, payload_sha) DO NOTHING
		RETURNING ` + ingestJobColumns

	row := r.db.QueryRowContext(ctx, query,
		job.ID().String(),
		job.TenantID().String(),
		nullIDPtr(job.AgentID()),
		job.ReportID(),
		job.SourceType(),
		job.Payload(),
		job.PayloadSHA(),
		job.Status().String(),
		job.Attempts(),
		job.MaxAttempts(),
		job.Priority(),
		job.AvailableAt(),
		job.CreatedAt(),
		job.UpdatedAt(),
	)

	stored, err := scanIngestJobRow(row)
	if err == nil {
		return stored, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, fmt.Errorf("enqueue ingest job: %w", err)
	}

	// Conflict: a job with this idempotency key already exists. Return it.
	existing, getErr := r.getByIdempotencyKey(ctx, job.TenantID(), job.ReportID(), job.PayloadSHA())
	if getErr != nil {
		return nil, false, fmt.Errorf("fetch existing ingest job: %w", getErr)
	}
	return existing, false, nil
}

func (r *IngestJobRepository) getByIdempotencyKey(ctx context.Context, tenantID shared.ID, reportID string, sha []byte) (*ingestjob.Job, error) {
	query := `SELECT ` + ingestJobColumns + `
		FROM ingest_jobs
		WHERE tenant_id = $1 AND report_id = $2 AND payload_sha = $3`
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), reportID, sha)
	return scanIngestJobRow(row)
}

// ClaimBatch claims up to limit due pending jobs for workerID, marking them
// processing.
//
// Claiming is per-tenant weighted-fair (RFC-005 §3.4): jobs are ranked
// round-robin across tenants (each tenant's oldest due job before any tenant's
// second), so a single tenant flooding the queue cannot starve others. Because
// Postgres forbids FOR UPDATE alongside the window function used for ranking,
// this is a two-phase claim: (1) pick fair candidate ids (no lock), then
// (2) lock-and-claim that subset with FOR UPDATE SKIP LOCKED so concurrent
// workers/replicas still claim disjoint sets without blocking.
func (r *IngestJobRepository) ClaimBatch(ctx context.Context, workerID string, limit int) ([]*ingestjob.Job, error) {
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()

	// Phase 1: fair candidate ranking. rn=1 is each tenant's oldest due job;
	// ordering by rn first interleaves tenants round-robin.
	candidateQuery := `
		SELECT id FROM (
			SELECT id,
				ROW_NUMBER() OVER (PARTITION BY tenant_id ORDER BY priority DESC, available_at ASC) AS rn,
				priority, available_at
			FROM ingest_jobs
			WHERE status = 'pending' AND available_at <= $1
		) ranked
		ORDER BY rn ASC, priority DESC, available_at ASC
		LIMIT $2`

	rows, err := tx.QueryContext(ctx, candidateQuery, now, limit)
	if err != nil {
		return nil, fmt.Errorf("select claim candidates: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if scanErr := rows.Scan(&id); scanErr != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan candidate id: %w", scanErr)
		}
		ids = append(ids, id)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterate candidate ids: %w", rowsErr)
	}
	_ = rows.Close()

	if len(ids) == 0 {
		return nil, nil
	}

	// Phase 2: lock the candidate subset (still pending, not locked elsewhere)
	// and claim it. The inner FOR UPDATE SKIP LOCKED keeps claims disjoint and
	// non-blocking across workers/replicas.
	updateQuery := `
		UPDATE ingest_jobs
		SET status = 'processing', attempts = attempts + 1,
			locked_by = $1, locked_at = $2, updated_at = $2
		WHERE id IN (
			SELECT id FROM ingest_jobs
			WHERE id = ANY($3) AND status = 'pending'
			FOR UPDATE SKIP LOCKED
		)
		RETURNING ` + ingestJobColumns

	updated, err := tx.QueryContext(ctx, updateQuery, workerID, now, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("lock claimed jobs: %w", err)
	}
	defer func() { _ = updated.Close() }()

	jobs, err := scanIngestJobRows(updated)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit claim: %w", err)
	}
	return jobs, nil
}

// Complete marks a job completed with its result counts.
func (r *IngestJobRepository) Complete(ctx context.Context, id ingestjob.ID, result []byte) error {
	const query = `
		UPDATE ingest_jobs
		SET status = 'completed', result = $2, error = NULL,
			locked_by = NULL, locked_at = NULL, updated_at = NOW()
		WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id.String(), result)
	if err != nil {
		return fmt.Errorf("complete ingest job: %w", err)
	}
	return nil
}

// Fail reschedules a job for retry (status pending, gated by availableAt) or
// marks it dead when retries are exhausted.
func (r *IngestJobRepository) Fail(ctx context.Context, id ingestjob.ID, errMsg string, availableAt time.Time, dead bool) error {
	status := ingestjob.StatusPending
	if dead {
		status = ingestjob.StatusDead
	}
	const query = `
		UPDATE ingest_jobs
		SET status = $2, error = $3, available_at = $4,
			locked_by = NULL, locked_at = NULL, updated_at = NOW()
		WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id.String(), status.String(), errMsg, availableAt)
	if err != nil {
		return fmt.Errorf("fail ingest job: %w", err)
	}
	return nil
}

// GetByID fetches a tenant-scoped job.
func (r *IngestJobRepository) GetByID(ctx context.Context, tenantID, id ingestjob.ID) (*ingestjob.Job, error) {
	query := `SELECT ` + ingestJobColumns + `
		FROM ingest_jobs WHERE tenant_id = $1 AND id = $2`
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	job, err := scanIngestJobRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get ingest job: %w", err)
	}
	return job, nil
}

// CountPendingByTenant counts a tenant's not-yet-terminal jobs.
func (r *IngestJobRepository) CountPendingByTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	const query = `
		SELECT COUNT(*) FROM ingest_jobs
		WHERE tenant_id = $1 AND status IN ('pending', 'processing')`
	var n int
	if err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count pending ingest jobs: %w", err)
	}
	return n, nil
}

// ReleaseStale resets jobs stuck in processing past the lease back to pending.
func (r *IngestJobRepository) ReleaseStale(ctx context.Context, olderThan time.Duration) (int, error) {
	cutoff := time.Now().Add(-olderThan)
	const query = `
		UPDATE ingest_jobs
		SET status = 'pending', locked_by = NULL, locked_at = NULL, updated_at = NOW()
		WHERE status = 'processing' AND locked_at < $1`
	res, err := r.db.ExecContext(ctx, query, cutoff)
	if err != nil {
		return 0, fmt.Errorf("release stale ingest jobs: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// --- scanning ---

type rowScanner interface {
	Scan(dest ...any) error
}

func scanIngestJobRow(s rowScanner) (*ingestjob.Job, error) {
	var (
		idStr, tenantStr           string
		agentStr                   sql.NullString
		reportID, sourceType       string
		payload, payloadSHA        []byte
		statusStr                  string
		attempts, maxAttempts, pri int
		result                     []byte
		lastError, lockedBy        sql.NullString
		lockedAt                   sql.NullTime
		availableAt                time.Time
		createdAt, updatedAt       time.Time
	)
	if err := s.Scan(
		&idStr, &tenantStr, &agentStr, &reportID, &sourceType, &payload, &payloadSHA,
		&statusStr, &attempts, &maxAttempts, &pri, &result, &lastError, &lockedBy, &lockedAt,
		&availableAt, &createdAt, &updatedAt,
	); err != nil {
		return nil, err
	}

	id, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("parse ingest job id: %w", err)
	}
	tenantID, err := shared.IDFromString(tenantStr)
	if err != nil {
		return nil, fmt.Errorf("parse ingest job tenant id: %w", err)
	}
	var agentID *shared.ID
	if agentStr.Valid {
		a, parseErr := shared.IDFromString(agentStr.String)
		if parseErr == nil {
			agentID = &a
		}
	}
	var lockedAtPtr *time.Time
	if lockedAt.Valid {
		t := lockedAt.Time
		lockedAtPtr = &t
	}

	return ingestjob.FromRow(
		id, tenantID, agentID, reportID, sourceType, payload, payloadSHA,
		ingestjob.Status(statusStr), attempts, maxAttempts, pri, result,
		lastError.String, lockedBy.String, lockedAtPtr,
		availableAt, createdAt, updatedAt,
	), nil
}

func scanIngestJobRows(rows *sql.Rows) ([]*ingestjob.Job, error) {
	var jobs []*ingestjob.Job
	for rows.Next() {
		job, err := scanIngestJobRow(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ingest jobs: %w", err)
	}
	return jobs, nil
}
