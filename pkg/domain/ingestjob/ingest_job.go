// Package ingestjob provides the domain entities for the asynchronous ingest
// queue (RFC-005). An ingest job is a persisted, raw agent payload waiting to
// be processed by a bounded worker pool, decoupling accept (fast, in the HTTP
// request) from process (async).
package ingestjob

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ID identifies an ingest job.
type ID = shared.ID

// Status is the processing state of an ingest job.
type Status string

const (
	// StatusPending — waiting to be claimed by a worker.
	StatusPending Status = "pending"
	// StatusProcessing — claimed and being processed.
	StatusProcessing Status = "processing"
	// StatusCompleted — processed successfully (result holds counts).
	StatusCompleted Status = "completed"
	// StatusFailed — failed but eligible for retry (available_at gates backoff).
	StatusFailed Status = "failed"
	// StatusDead — exhausted retries; needs manual attention.
	StatusDead Status = "dead"
)

// String returns the status string.
func (s Status) String() string { return string(s) }

// IsTerminal reports whether no further processing will occur.
func (s Status) IsTerminal() bool {
	return s == StatusCompleted || s == StatusDead
}

// Job is a queued raw ingest payload.
type Job struct {
	id          ID
	tenantID    shared.ID
	agentID     *shared.ID
	reportID    string
	sourceType  string
	payload     []byte
	payloadSHA  []byte
	status      Status
	attempts    int
	maxAttempts int
	priority    int
	result      []byte // JSON ingest counts, set on completion
	lastError   string
	lockedBy    string
	lockedAt    *time.Time
	availableAt time.Time
	createdAt   time.Time
	updatedAt   time.Time
}

// NewJob builds a pending job for the given decompressed payload, computing its
// content hash for idempotency. agentID may be nil for non-agent sources.
func NewJob(tenantID shared.ID, agentID *shared.ID, reportID, sourceType string, payload []byte) *Job {
	now := time.Now()
	sum := sha256.Sum256(payload)
	return &Job{
		id:          shared.NewID(),
		tenantID:    tenantID,
		agentID:     agentID,
		reportID:    reportID,
		sourceType:  sourceType,
		payload:     payload,
		payloadSHA:  sum[:],
		status:      StatusPending,
		attempts:    0,
		maxAttempts: DefaultMaxAttempts,
		priority:    0,
		availableAt: now,
		createdAt:   now,
		updatedAt:   now,
	}
}

// DefaultMaxAttempts is the retry ceiling before a job is marked dead.
const DefaultMaxAttempts = 5

// Accessors.
func (j *Job) ID() ID                 { return j.id }
func (j *Job) TenantID() shared.ID    { return j.tenantID }
func (j *Job) AgentID() *shared.ID    { return j.agentID }
func (j *Job) ReportID() string       { return j.reportID }
func (j *Job) SourceType() string     { return j.sourceType }
func (j *Job) Payload() []byte        { return j.payload }
func (j *Job) PayloadSHA() []byte     { return j.payloadSHA }
func (j *Job) Status() Status         { return j.status }
func (j *Job) Attempts() int          { return j.attempts }
func (j *Job) MaxAttempts() int       { return j.maxAttempts }
func (j *Job) Priority() int          { return j.priority }
func (j *Job) Result() []byte         { return j.result }
func (j *Job) LastError() string      { return j.lastError }
func (j *Job) LockedBy() string       { return j.lockedBy }
func (j *Job) LockedAt() *time.Time   { return j.lockedAt }
func (j *Job) AvailableAt() time.Time { return j.availableAt }
func (j *Job) CreatedAt() time.Time   { return j.createdAt }
func (j *Job) UpdatedAt() time.Time   { return j.updatedAt }

// Backoff returns the retry delay for the given attempt count: exponential
// (30s, 60s, 120s, …) capped at 10 minutes.
func Backoff(attempts int) time.Duration {
	const base = 30 * time.Second
	const maxDelay = 10 * time.Minute
	d := base
	for i := 1; i < attempts && d < maxDelay; i++ {
		d *= 2
	}
	if d > maxDelay {
		d = maxDelay
	}
	return d
}

// FromRow rehydrates a Job from persisted columns. Used by the repository.
func FromRow(
	id, tenantID ID,
	agentID *shared.ID,
	reportID, sourceType string,
	payload, payloadSHA []byte,
	status Status,
	attempts, maxAttempts, priority int,
	result []byte,
	lastError, lockedBy string,
	lockedAt *time.Time,
	availableAt, createdAt, updatedAt time.Time,
) *Job {
	return &Job{
		id: id, tenantID: tenantID, agentID: agentID,
		reportID: reportID, sourceType: sourceType,
		payload: payload, payloadSHA: payloadSHA,
		status: status, attempts: attempts, maxAttempts: maxAttempts, priority: priority,
		result: result, lastError: lastError, lockedBy: lockedBy, lockedAt: lockedAt,
		availableAt: availableAt, createdAt: createdAt, updatedAt: updatedAt,
	}
}

// Repository persists and claims ingest jobs.
type Repository interface {
	// Enqueue inserts a pending job. If a job with the same idempotency key
	// (tenant_id, report_id, payload_sha) already exists, no new row is created
	// and the existing job is returned with created=false.
	Enqueue(ctx context.Context, job *Job) (stored *Job, created bool, err error)

	// ClaimBatch atomically claims up to limit due pending jobs for the worker,
	// marking them processing and incrementing attempts. Uses FOR UPDATE SKIP
	// LOCKED so replicas claim disjoint sets, and partitions fairly across
	// tenants so one tenant cannot monopolize the workers.
	ClaimBatch(ctx context.Context, workerID string, limit int) ([]*Job, error)

	// Complete marks a job completed and stores its result counts (JSON).
	Complete(ctx context.Context, id ID, result []byte) error

	// Fail records an error and either reschedules the job for retry at
	// availableAt (status pending) or marks it dead when retries are exhausted.
	Fail(ctx context.Context, id ID, errMsg string, availableAt time.Time, dead bool) error

	// GetByID fetches a job scoped to its tenant (status polling).
	GetByID(ctx context.Context, tenantID, id ID) (*Job, error)

	// CountPendingByTenant returns how many pending/processing jobs a tenant has
	// (for accept-path queue-depth backpressure).
	CountPendingByTenant(ctx context.Context, tenantID shared.ID) (int, error)

	// CountPending returns the global number of not-yet-terminal jobs across all
	// tenants (for the queue-depth metric).
	CountPending(ctx context.Context) (int, error)

	// ReleaseStale resets jobs stuck in processing (worker crash) back to
	// pending when their lock is older than olderThan. Returns the count reset.
	ReleaseStale(ctx context.Context, olderThan time.Duration) (int, error)
}
