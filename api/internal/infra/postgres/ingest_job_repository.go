package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// IngestJobRepository implements ingestjob.Repository on PostgreSQL (RFC-005).
type IngestJobRepository struct {
	db *DB
	// maxRunning caps a tenant's processing jobs (0: the default).
	maxRunning int
}

// NewIngestJobRepository constructs an IngestJobRepository.
func NewIngestJobRepository(db *DB) *IngestJobRepository {
	return &IngestJobRepository{db: db}
}

const ingestJobColumns = `
	id, tenant_id, sensor_id, report_id, source_type, payload, payload_sha,
	status, attempts, max_attempts, priority, result, error, locked_by, locked_at,
	available_at, created_at, updated_at,
	protocol, ingest_report_id, segment_seq, content_digest, media_type,
	kind, source_ref, submitted_by, public_error, lane, scope_key`

// Enqueue inserts a pending job, or returns the existing one on idempotency
// conflict (tenant_id, report_id, payload_sha).
func (r *IngestJobRepository) Enqueue(ctx context.Context, job *ingestjob.Job) (*ingestjob.Job, bool, error) {
	query := `
		INSERT INTO ingest_jobs (
			id, tenant_id, sensor_id, report_id, source_type, payload, payload_sha,
			status, attempts, max_attempts, priority, available_at, created_at, updated_at,
			lane, scope_key
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NULLIF($16, ''))
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
		int(job.Lane()),
		job.ScopeKey(),
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

// DefaultMaxRunningPerTenant bounds a tenant's processing jobs when no cap
// is configured.
const DefaultMaxRunningPerTenant = 4

// SetMaxRunningPerTenant caps how many jobs of one tenant are processing at
// once (<= 0 keeps DefaultMaxRunningPerTenant).
func (r *IngestJobRepository) SetMaxRunningPerTenant(n int) { r.maxRunning = n }

func (r *IngestJobRepository) runningCap() int {
	if r.maxRunning <= 0 {
		return DefaultMaxRunningPerTenant
	}
	return r.maxRunning
}

// ClaimBatch claims up to limit due pending jobs for workerID, marking them
// processing (docs/rfcs/RFC-122-ingest-receipts.md, "Fairness and limits").
//
// Order: lane first (urgent, interactive, bulk), then round-robin across
// tenants within a lane (each tenant's oldest due job before any tenant's
// second), then age. Guards:
//   - attempts < max_attempts: a job whose attempts ran out is never claimed
//     again (a payload that kills the worker, its lease expired);
//   - one processing job per scope_key: a candidate whose scope has a
//     running job is skipped, a batch takes at most one job per scope, and
//     the unique partial index ux_ingest_jobs_scope_running makes a
//     concurrent claim of the same scope by another worker fail, in which
//     case that job is skipped;
//   - a tenant has at most the running cap of jobs processing, so one
//     tenant cannot hold every worker.
//
// Postgres forbids FOR UPDATE alongside window functions, so the claim is
// two-phase: (1) pick fair candidate ids without locks, (2) claim each one
// under FOR UPDATE SKIP LOCKED in its own savepoint.
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
	candidateQuery := `
		WITH running AS (
			SELECT tenant_id, count(*) AS n FROM ingest_jobs WHERE status = 'processing' GROUP BY tenant_id
		), ranked AS (
			SELECT j.id, j.lane, j.available_at,
				ROW_NUMBER() OVER (PARTITION BY j.tenant_id ORDER BY j.lane, j.priority DESC, j.available_at) AS rn,
				ROW_NUMBER() OVER (PARTITION BY COALESCE(j.scope_key, j.id::text) ORDER BY j.lane, j.available_at) AS sn,
				COALESCE(rt.n, 0) AS tenant_running
			FROM ingest_jobs j
			LEFT JOIN running rt ON rt.tenant_id = j.tenant_id
			WHERE j.status = 'pending' AND j.available_at <= $1 AND j.attempts < j.max_attempts
			  AND (j.scope_key IS NULL OR NOT EXISTS (
				SELECT 1 FROM ingest_jobs p WHERE p.status = 'processing' AND p.scope_key = j.scope_key))
		)
		SELECT id FROM ranked
		WHERE sn = 1 AND rn <= $3 - tenant_running
		ORDER BY lane, rn, available_at
		LIMIT $2`

	rows, err := tx.QueryContext(ctx, candidateQuery, now, limit, r.runningCap())
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

	jobs := make([]*ingestjob.Job, 0, len(ids))
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `SAVEPOINT ingest_claim`); err != nil {
			return nil, fmt.Errorf("claim savepoint: %w", err)
		}
		job, err := scanIngestJobRow(tx.QueryRowContext(ctx, `
			UPDATE ingest_jobs
			SET status = 'processing', attempts = attempts + 1,
				locked_by = $1, locked_at = $2, updated_at = $2
			WHERE id = (
				SELECT id FROM ingest_jobs
				WHERE id = $3 AND status = 'pending' AND attempts < max_attempts
				FOR UPDATE SKIP LOCKED
			)
			RETURNING `+ingestJobColumns, workerID, now, id))
		switch {
		case err == nil:
			jobs = append(jobs, job)
		case errors.Is(err, sql.ErrNoRows):
			// Claimed by another worker meanwhile.
		case isUniqueViolation(err):
			// Another worker started a job of the same scope meanwhile.
			if _, rbErr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT ingest_claim`); rbErr != nil {
				return nil, fmt.Errorf("claim rollback: %w", rbErr)
			}
			continue
		default:
			return nil, fmt.Errorf("claim ingest job: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `RELEASE SAVEPOINT ingest_claim`); err != nil {
			return nil, fmt.Errorf("claim release savepoint: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit claim: %w", err)
	}
	return jobs, nil
}

// Complete marks a job completed with its result counts.
func (r *IngestJobRepository) Complete(ctx context.Context, id ingestjob.ID, result []byte) error {
	// An upload's envelope (who uploaded, from where) is not kept once it
	// is applied.
	const query = `
		UPDATE ingest_jobs
		SET status = 'completed', result = $2, error = NULL,
			payload = CASE WHEN kind <> 'sensor' THEN convert_to('{}', 'UTF8') ELSE payload END,
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
func (r *IngestJobRepository) Fail(ctx context.Context, id ingestjob.ID, errMsg, publicErr string, availableAt time.Time, dead bool) error {
	status := ingestjob.StatusPending
	if dead {
		status = ingestjob.StatusDead
	}
	const query = `
		UPDATE ingest_jobs
		SET status = $2, error = $3, available_at = $4, public_error = NULLIF($5, ''),
			locked_by = NULL, locked_at = NULL, updated_at = NOW()
		WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id.String(), status.String(), errMsg, availableAt, publicErr)
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

// ReleaseStale resets jobs stuck in processing past the lease back to
// pending; a job with no attempts left (its lease expiry was its last
// attempt) is marked dead with apply_failed and returned in dead.
func (r *IngestJobRepository) ReleaseStale(ctx context.Context, olderThan time.Duration) (int, []*ingestjob.Job, error) {
	cutoff := time.Now().Add(-olderThan)
	rows, err := r.db.QueryContext(ctx, `
		UPDATE ingest_jobs j
		SET status = CASE WHEN j.attempts >= j.max_attempts THEN 'dead' ELSE 'pending' END,
			public_error = CASE WHEN j.attempts >= j.max_attempts THEN $2 ELSE j.public_error END,
			error = CASE WHEN j.attempts >= j.max_attempts THEN 'the lease expired on the last attempt' ELSE j.error END,
			locked_by = NULL, locked_at = NULL, updated_at = NOW()
		WHERE j.id IN (
			SELECT id FROM ingest_jobs WHERE status = 'processing' AND locked_at < $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING `+ingestJobColumns, cutoff, ingestjob.ErrorApplyFailed)
	if err != nil {
		return 0, nil, fmt.Errorf("release stale ingest jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	jobs, err := scanIngestJobRows(rows)
	if err != nil {
		return 0, nil, err
	}
	released := 0
	var dead []*ingestjob.Job
	for _, j := range jobs {
		if j.Status() == ingestjob.StatusDead {
			dead = append(dead, j)
		} else {
			released++
		}
	}
	return released, dead, nil
}

// TenantDepth counts a tenant's unfinished jobs and the jobs it finished
// since the given time (back-pressure at accept).
func (r *IngestJobRepository) TenantDepth(ctx context.Context, tenantID shared.ID, finishedSince time.Time) (int, int, error) {
	var unfinished, finished int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FILTER (WHERE status IN ('pending', 'processing')),
		       COUNT(*) FILTER (WHERE status = 'completed' AND updated_at >= $2)
		FROM ingest_jobs
		WHERE tenant_id = $1 AND (status IN ('pending', 'processing') OR updated_at >= $2)`,
		tenantID.String(), finishedSince).Scan(&unfinished, &finished)
	if err != nil {
		return 0, 0, fmt.Errorf("ingest queue depth: %w", err)
	}
	return unfinished, finished, nil
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
		kind                       string
		sourceRef, submittedBy     sql.NullString
		publicError                sql.NullString
		lane                       int
		scopeKey                   sql.NullString
	)
	if err := s.Scan(
		&idStr, &tenantStr, &sensorStr, &reportID, &sourceType, &payload, &payloadSHA,
		&statusStr, &attempts, &maxAttempts, &pri, &result, &lastError, &lockedBy, &lockedAt,
		&availableAt, &createdAt, &updatedAt,
		&protocol, &reportRef, &segmentSeq, &contentDigest, &mediaType,
		&kind, &sourceRef, &submittedBy, &publicError, &lane, &scopeKey,
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
	job.SetUpload(ingestjob.Kind(kind), sourceRef.String, submittedBy.String, publicError.String)
	job.Route(ingestjob.Lane(lane), scopeKey.String)
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
			protocol, ingest_report_id, segment_seq, content_digest, media_type, lane, scope_key
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, NULLIF($21, ''))
		` + conflict + `
		RETURNING ` + ingestJobColumns
	row := r.db.QueryRowContext(ctx, query,
		job.ID().String(), job.TenantID().String(), nullIDPtr(job.SensorID()),
		job.ReportID(), job.SourceType(), job.Payload(), job.PayloadSHA(),
		job.Status().String(), job.Attempts(), job.MaxAttempts(), job.Priority(),
		job.AvailableAt(), job.CreatedAt(), job.UpdatedAt(),
		ingestjob.ProtocolV2, seg.ReportRef.String(), seq, seg.ContentDigest, seg.MediaType,
		int(job.Lane()), job.ScopeKey(),
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
	_, err := execWithTimeout(ctx, r.db.DB, timeoutBatch, `
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

// --- CI results and file imports (RFC-122) ---

var _ ingestjob.UploadRepository = (*IngestJobRepository)(nil)

// EnqueueUpload inserts a pending upload job, or returns the job the tenant
// already has for the same report id and digest (created=false).
func (r *IngestJobRepository) EnqueueUpload(ctx context.Context, job *ingestjob.Job) (*ingestjob.Job, bool, error) {
	if !job.Kind().IsUpload() {
		return nil, false, errors.New("enqueue upload job: not an upload kind")
	}
	query := `
		INSERT INTO ingest_jobs (
			id, tenant_id, report_id, source_type, payload, payload_sha,
			status, attempts, max_attempts, priority, available_at, created_at, updated_at,
			kind, source_ref, submitted_by, lane, scope_key
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NULLIF($15, ''), NULLIF($16, ''), $17, NULLIF($18, ''))
		ON CONFLICT (tenant_id, report_id, payload_sha) DO NOTHING
		RETURNING ` + ingestJobColumns
	row := r.db.QueryRowContext(ctx, query,
		job.ID().String(), job.TenantID().String(), job.ReportID(), job.SourceType(),
		job.Payload(), job.PayloadSHA(), job.Status().String(), job.Attempts(), job.MaxAttempts(),
		job.Priority(), job.AvailableAt(), job.CreatedAt(), job.UpdatedAt(),
		string(job.Kind()), job.SourceRef(), job.SubmittedBy(), int(job.Lane()), job.ScopeKey(),
	)
	stored, err := scanIngestJobRow(row)
	if err == nil {
		return stored, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, false, fmt.Errorf("enqueue upload job: %w", err)
	}
	existing, err := r.getByIdempotencyKey(ctx, job.TenantID(), job.ReportID(), job.PayloadSHA())
	if err != nil {
		return nil, false, fmt.Errorf("fetch existing upload job: %w", err)
	}
	return existing, false, nil
}

// FindRecentUpload returns the newest upload job of kind the principal sent
// with this digest since the given time, unless it failed for good.
func (r *IngestJobRepository) FindRecentUpload(ctx context.Context, tenantID shared.ID, kind ingestjob.Kind,
	submittedBy string, digest []byte, since time.Time) (*ingestjob.Job, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+ingestJobColumns+`
		FROM ingest_jobs
		WHERE tenant_id = $1 AND kind = $2 AND submitted_by = $3 AND payload_sha = $4
		  AND created_at >= $5 AND status <> 'dead'
		ORDER BY created_at DESC
		LIMIT 1`, tenantID.String(), string(kind), submittedBy, digest, since)
	job, err := scanIngestJobRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find recent upload job: %w", err)
	}
	return job, nil
}

// SourceState counts a source's unfinished and dead jobs.
func (r *IngestJobRepository) SourceState(ctx context.Context, tenantID shared.ID, kind ingestjob.Kind, sourceRef string) (int, int, error) {
	var pending, dead int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FILTER (WHERE status IN ('pending', 'processing')),
		       COUNT(*) FILTER (WHERE status = 'dead')
		FROM ingest_jobs
		WHERE tenant_id = $1 AND kind = $2 AND source_ref = $3`,
		tenantID.String(), string(kind), sourceRef).Scan(&pending, &dead)
	if err != nil {
		return 0, 0, fmt.Errorf("upload source state: %w", err)
	}
	return pending, dead, nil
}

// GetUploadByKey returns the tenant's job with this report id and digest.
func (r *IngestJobRepository) GetUploadByKey(ctx context.Context, tenantID shared.ID, reportID string, digest []byte) (*ingestjob.Job, error) {
	job, err := r.getByIdempotencyKey(ctx, tenantID, reportID, digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get upload job by key: %w", err)
	}
	return job, nil
}

// RequeueDeadUpload returns a dead upload job to pending with a fresh retry
// budget when its stored report is still there.
func (r *IngestJobRepository) RequeueDeadUpload(ctx context.Context, tenantID, id shared.ID) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE ingest_jobs
		SET status = 'pending', attempts = 0, error = NULL, public_error = NULL, result = NULL,
			available_at = NOW(), locked_by = NULL, locked_at = NULL, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND status = 'dead' AND kind <> 'sensor'
		  AND EXISTS (SELECT 1 FROM ingest_payloads p WHERE p.tenant_id = $1 AND p.job_id = $2)`,
		tenantID.String(), id.String())
	if err != nil {
		return false, fmt.Errorf("requeue dead upload job: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// BySource returns the newest job of kind for sourceRef of the tenant.
func (r *IngestJobRepository) BySource(ctx context.Context, tenantID shared.ID, kind ingestjob.Kind, sourceRef string) (*ingestjob.Job, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+ingestJobColumns+`
		FROM ingest_jobs WHERE tenant_id = $1 AND kind = $2 AND source_ref = $3
		ORDER BY created_at DESC LIMIT 1`, tenantID.String(), string(kind), sourceRef)
	job, err := scanIngestJobRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get upload job by source: %w", err)
	}
	return job, nil
}

// --- retention (RFC-122 "Queue hygiene") ---

// PurgePayloadsForPlatform deletes stored upload parts nobody will open:
// expired ones, those of a finished (completed) job, and those an upload
// staged without ever getting a job (older than an hour). At most limit
// rows. Platform-wide (the retention job).
func (r *IngestJobRepository) PurgePayloadsForPlatform(ctx context.Context, now time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM ingest_payloads WHERE (job_id, part) IN (
			SELECT p.job_id, p.part FROM ingest_payloads p
			LEFT JOIN ingest_jobs j ON j.id = p.job_id
			WHERE p.expires_at < $1
			   OR j.status = 'completed'
			   OR (j.id IS NULL AND p.created_at < $1 - interval '1 hour')
			LIMIT $2)`, now, limit)
	if err != nil {
		return 0, fmt.Errorf("purge ingest payloads: %w", err)
	}
	return res.RowsAffected()
}

// PurgeFinishedJobsForPlatform deletes finished jobs (completed or dead)
// last updated before the cutoff that belong to no report (the jobs of a
// report go with it). At most limit rows.
func (r *IngestJobRepository) PurgeFinishedJobsForPlatform(ctx context.Context, before time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM ingest_jobs WHERE id IN (
			SELECT id FROM ingest_jobs
			WHERE status IN ('completed', 'dead') AND updated_at < $1 AND ingest_report_id IS NULL
			LIMIT $2)`, before, limit)
	if err != nil {
		return 0, fmt.Errorf("purge ingest jobs: %w", err)
	}
	return res.RowsAffected()
}

// PurgeFinishedReportsForPlatform deletes finished protocol v2 reports
// (completed, failed, expired) last updated before the cutoff, with their
// jobs (ON DELETE CASCADE). At most limit rows.
func (r *IngestJobRepository) PurgeFinishedReportsForPlatform(ctx context.Context, before time.Time, limit int) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM ingest_reports WHERE id IN (
			SELECT id FROM ingest_reports
			WHERE state IN ('completed', 'failed', 'expired') AND updated_at < $1
			LIMIT $2)`, before, limit)
	if err != nil {
		return 0, fmt.Errorf("purge ingest reports: %w", err)
	}
	return res.RowsAffected()
}

// EnqueueSideEffects stores the after-commit side effects of an ingest
// batch as one job (kind side_effects, interactive lane: people wait on the
// notifications and tickets they start).
func (r *IngestJobRepository) EnqueueSideEffects(ctx context.Context, tenantID shared.ID, payload []byte) error {
	id := shared.NewID()
	sum := sha256.Sum256(append([]byte(id.String()), payload...))
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO ingest_jobs (id, tenant_id, report_id, source_type, payload, payload_sha, status, attempts,
			max_attempts, priority, available_at, created_at, updated_at, kind, lane)
		VALUES ($1, $2, $3, 'side_effects', $4, $5, 'pending', 0, $6, 0, NOW(), NOW(), NOW(), 'side_effects', $7)`,
		id.String(), tenantID.String(), "fx:"+id.String(), payload, sum[:], ingestjob.DefaultMaxAttempts, int(ingestjob.LaneInteractive))
	if err != nil {
		return fmt.Errorf("enqueue side effects: %w", err)
	}
	return nil
}
