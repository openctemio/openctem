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
	id, tenant_id, sensor_id, report_id, source_type, payload, payload_sha,
	status, attempts, max_attempts, priority, result, error, locked_by, locked_at,
	available_at, created_at, updated_at,
	protocol, ingest_report_id, segment_seq, content_digest, media_type`

// Enqueue inserts a pending job, or returns the existing one on idempotency
// conflict (tenant_id, report_id, payload_sha).
func (r *IngestJobRepository) Enqueue(ctx context.Context, job *ingestjob.Job) (*ingestjob.Job, bool, error) {
	query := `
		INSERT INTO ingest_jobs (
			id, tenant_id, sensor_id, report_id, source_type, payload, payload_sha,
			status, attempts, max_attempts, priority, available_at, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (tenant_id, report_id, payload_sha) DO NOTHING
		RETURNING ` + ingestJobColumns

	row := r.db.QueryRowContext(ctx, query,
		job.ID().String(),
		job.TenantID().String(),
		nullIDPtr(job.SensorID()),
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

// CountPending returns the global number of not-yet-terminal jobs.
func (r *IngestJobRepository) CountPending(ctx context.Context) (int, error) {
	const query = `SELECT COUNT(*) FROM ingest_jobs WHERE status IN ('pending', 'processing')`
	var n int
	if err := r.db.QueryRowContext(ctx, query).Scan(&n); err != nil {
		return 0, fmt.Errorf("count pending ingest jobs (global): %w", err)
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
		sensorStr                  sql.NullString
		reportID, sourceType       string
		payload, payloadSHA        []byte
		statusStr                  string
		attempts, maxAttempts, pri int
		result                     []byte
		lastError, lockedBy        sql.NullString
		lockedAt                   sql.NullTime
		availableAt                time.Time
		createdAt, updatedAt       time.Time
		protocol, segmentSeq       sql.NullInt64
		reportRef                  sql.NullString
		contentDigest, mediaType   sql.NullString
	)
	if err := s.Scan(
		&idStr, &tenantStr, &sensorStr, &reportID, &sourceType, &payload, &payloadSHA,
		&statusStr, &attempts, &maxAttempts, &pri, &result, &lastError, &lockedBy, &lockedAt,
		&availableAt, &createdAt, &updatedAt,
		&protocol, &reportRef, &segmentSeq, &contentDigest, &mediaType,
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
	var sensorID *shared.ID
	if sensorStr.Valid {
		a, parseErr := shared.IDFromString(sensorStr.String)
		if parseErr == nil {
			sensorID = &a
		}
	}
	var lockedAtPtr *time.Time
	if lockedAt.Valid {
		t := lockedAt.Time
		lockedAtPtr = &t
	}

	job := ingestjob.FromRow(
		id, tenantID, sensorID, reportID, sourceType, payload, payloadSHA,
		ingestjob.Status(statusStr), attempts, maxAttempts, pri, result,
		lastError.String, lockedBy.String, lockedAtPtr,
		availableAt, createdAt, updatedAt,
	)
	if protocol.Valid && protocol.Int64 == ingestjob.ProtocolV2 && reportRef.Valid {
		ref, err := shared.IDFromString(reportRef.String)
		if err != nil {
			return nil, fmt.Errorf("parse ingest job report ref: %w", err)
		}
		seg := &ingestjob.V2Segment{ReportRef: ref, ContentDigest: contentDigest.String, MediaType: mediaType.String}
		if segmentSeq.Valid {
			n := int(segmentSeq.Int64)
			seg.Seq = &n
		}
		job.SetV2(seg)
	}
	return job, nil
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

// --- protocol v2 (RFC-026) ---

var _ ingestjob.V2Repository = (*IngestJobRepository)(nil)

// EnqueueV2 inserts a v2 segment or commit job, or returns the job the report
// already has for that segment (created=false).
func (r *IngestJobRepository) EnqueueV2(ctx context.Context, job *ingestjob.Job) (*ingestjob.Job, bool, error) {
	seg := job.V2()
	if seg == nil {
		return nil, false, errors.New("enqueue v2 ingest job: job has no v2 binding")
	}
	conflict := `ON CONFLICT (ingest_report_id, segment_seq)
		WHERE ingest_report_id IS NOT NULL AND segment_seq IS NOT NULL DO NOTHING`
	if seg.IsCommit() {
		conflict = `ON CONFLICT (ingest_report_id)
		WHERE ingest_report_id IS NOT NULL AND segment_seq IS NULL DO NOTHING`
	}
	var seq any
	if seg.Seq != nil {
		seq = *seg.Seq
	}
	query := `
		INSERT INTO ingest_jobs (
			id, tenant_id, sensor_id, report_id, source_type, payload, payload_sha,
			status, attempts, max_attempts, priority, available_at, created_at, updated_at,
			protocol, ingest_report_id, segment_seq, content_digest, media_type
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		` + conflict + `
		RETURNING ` + ingestJobColumns
	row := r.db.QueryRowContext(ctx, query,
		job.ID().String(), job.TenantID().String(), nullIDPtr(job.SensorID()),
		job.ReportID(), job.SourceType(), job.Payload(), job.PayloadSHA(),
		job.Status().String(), job.Attempts(), job.MaxAttempts(), job.Priority(),
		job.AvailableAt(), job.CreatedAt(), job.UpdatedAt(),
		ingestjob.ProtocolV2, seg.ReportRef.String(), seq, seg.ContentDigest, seg.MediaType,
	)
	stored, err := scanIngestJobRow(row)
	if err == nil {
		return stored, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, fmt.Errorf("enqueue v2 ingest job: %w", err)
	}
	var existing *ingestjob.Job
	if seg.IsCommit() {
		existing, err = scanIngestJobRow(r.db.QueryRowContext(ctx, `SELECT `+ingestJobColumns+`
			FROM ingest_jobs WHERE ingest_report_id = $1 AND segment_seq IS NULL`, seg.ReportRef.String()))
	} else {
		existing, err = r.GetV2Segment(ctx, seg.ReportRef, *seg.Seq)
	}
	if err != nil {
		return nil, false, fmt.Errorf("fetch existing v2 ingest job: %w", err)
	}
	return existing, false, nil
}

// GetV2Segment returns the job of one segment of a report.
func (r *IngestJobRepository) GetV2Segment(ctx context.Context, reportRef shared.ID, seq int) (*ingestjob.Job, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+ingestJobColumns+`
		FROM ingest_jobs WHERE ingest_report_id = $1 AND segment_seq = $2`, reportRef.String(), seq)
	job, err := scanIngestJobRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get v2 segment job: %w", err)
	}
	return job, nil
}

// V2SegmentDigests returns segment number -> stored content digest.
func (r *IngestJobRepository) V2SegmentDigests(ctx context.Context, reportRef shared.ID) (map[int]string, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT segment_seq, content_digest FROM ingest_jobs
		WHERE ingest_report_id = $1 AND segment_seq IS NOT NULL`, reportRef.String())
	if err != nil {
		return nil, fmt.Errorf("list v2 segment digests: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[int]string{}
	for rows.Next() {
		var (
			seq    int
			digest sql.NullString
		)
		if err := rows.Scan(&seq, &digest); err != nil {
			return nil, fmt.Errorf("scan v2 segment digest: %w", err)
		}
		out[seq] = digest.String
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate v2 segment digests: %w", err)
	}
	return out, nil
}

// RequeueDeadV2 gives a report's dead jobs a fresh retry budget.
func (r *IngestJobRepository) RequeueDeadV2(ctx context.Context, reportRef shared.ID) (int, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE ingest_jobs
		SET status = 'pending', attempts = 0, error = NULL, available_at = NOW(),
			locked_by = NULL, locked_at = NULL, updated_at = NOW()
		WHERE ingest_report_id = $1 AND status = 'dead'`, reportRef.String())
	if err != nil {
		return 0, fmt.Errorf("requeue dead v2 jobs: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ClearV2Payloads empties the segment payloads of a finished report. Every
// segment has an outcome by then; a segment job the worker still holds (the
// one that finalized) is not re-run, because the processor skips segments of
// a completed report.
func (r *IngestJobRepository) ClearV2Payloads(ctx context.Context, reportRef shared.ID) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE ingest_jobs SET payload = ''::bytea, updated_at = NOW()
		WHERE ingest_report_id = $1 AND segment_seq IS NOT NULL AND octet_length(payload) > 0`, reportRef.String())
	if err != nil {
		return fmt.Errorf("clear v2 payloads: %w", err)
	}
	return nil
}

// GetV2Commit returns the commit job of a report.
func (r *IngestJobRepository) GetV2Commit(ctx context.Context, reportRef shared.ID) (*ingestjob.Job, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+ingestJobColumns+`
		FROM ingest_jobs WHERE ingest_report_id = $1 AND segment_seq IS NULL`, reportRef.String())
	job, err := scanIngestJobRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get v2 commit job: %w", err)
	}
	return job, nil
}
