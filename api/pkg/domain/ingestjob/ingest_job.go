// Package ingestjob provides the domain entities for the asynchronous ingest
// queue (RFC-005). An ingest job is a persisted, raw sensor payload waiting to
// be processed by a bounded worker pool, decoupling accept (fast, in the HTTP
// request) from process (async).
package ingestjob

import (
	"context"
	"crypto/sha256"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
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
	sensorID    *shared.ID
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

	// v2 is set for protocol v2 results jobs (RFC-026); nil for v1.
	v2 *V2Segment
}

// ProtocolV2 is the ingest_jobs.protocol value of a v2 results job.
const ProtocolV2 = 2

// V2Segment ties a job to a v2 results report (RFC-026). A job with a nil Seq
// is the report's commit step; any other job carries one segment.
type V2Segment struct {
	// ReportRef is the ingest_reports primary key.
	ReportRef shared.ID
	// Seq is the segment number, nil for the commit step.
	Seq *int
	// ContentDigest is the canonical sha-256 Content-Digest of the bytes the
	// sensor sent (empty for the commit step).
	ContentDigest string
	MediaType     string
}

// IsCommit reports whether the job is the report's commit step.
func (s *V2Segment) IsCommit() bool { return s != nil && s.Seq == nil }

// NewV2Job builds a pending protocol v2 job: one segment (payload = the
// decoded, validated CTIS document) or, with seg.Seq nil, the commit step
// (empty payload). The job's report_id column gets "<report>/<seq>" or
// "<report>/commit", so the v1 idempotency index can never match two
// different segments. <report> is the stored report's own id
// (seg.ReportRef), unique across sensors; reportUUID, the id the sensor
// chose, is used only when no report is named. Two sensors of a tenant
// that pick the same report id (or one that copies another's) therefore
// never collide on the tenant-wide idempotency index.
func NewV2Job(tenantID shared.ID, sensorID *shared.ID, reportUUID string, seg V2Segment, payload []byte) *Job {
	suffix := "commit"
	if seg.Seq != nil {
		suffix = strconv.Itoa(*seg.Seq)
	}
	if payload == nil {
		payload = []byte{} // the commit step carries no payload; the column is NOT NULL
	}
	prefix := reportUUID
	if !seg.ReportRef.IsZero() {
		prefix = seg.ReportRef.String()
	}
	j := NewJob(tenantID, sensorID, prefix+"/"+suffix, "", payload)
	j.v2 = &seg
	return j
}

// DelayUntil makes a not-yet-stored job unclaimable before t.
func (j *Job) DelayUntil(t time.Time) { j.availableAt = t }

// V2 returns the v2 report binding, or nil for a v1 job.
func (j *Job) V2() *V2Segment { return j.v2 }

// SetV2 attaches the v2 binding when rehydrating a job (repository use).
func (j *Job) SetV2(seg *V2Segment) { j.v2 = seg }

// NewJob builds a pending job for the given decompressed payload, computing its
// content hash for idempotency. sensorID may be nil for non-sensor sources.
func NewJob(tenantID shared.ID, sensorID *shared.ID, reportID, sourceType string, payload []byte) *Job {
	now := time.Now()
	sum := sha256.Sum256(payload)
	return &Job{
		id:          shared.NewID(),
		tenantID:    tenantID,
		sensorID:    sensorID,
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
func (j *Job) SensorID() *shared.ID   { return j.sensorID }
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
	sensorID *shared.ID,
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
		id: id, tenantID: tenantID, sensorID: sensorID,
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

// V2Repository is the protocol v2 side of the ingest queue (RFC-026). It is
// kept apart from Repository so v1 fakes need not implement it.
type V2Repository interface {
	// EnqueueV2 inserts a v2 segment or commit job. When the report already
	// has a job for that segment (or its commit), nothing is inserted and the
	// existing job is returned with created=false.
	EnqueueV2(ctx context.Context, job *Job) (stored *Job, created bool, err error)
	// GetV2Segment returns the job of segment seq of a report.
	GetV2Segment(ctx context.Context, reportRef shared.ID, seq int) (*Job, error)
	// V2SegmentDigests returns the stored digest of every segment of a report.
	V2SegmentDigests(ctx context.Context, reportRef shared.ID) (map[int]string, error)
	// RequeueDeadV2 returns a report's dead jobs to pending with a fresh
	// retry budget, for a sensor that re-sends a failed report.
	RequeueDeadV2(ctx context.Context, reportRef shared.ID) (int, error)
	// ClearV2Payloads drops the stored payloads of a finished report's
	// segments: the digests stay for replay checks, the bytes are not needed.
	// The processor never re-runs a segment of a completed report.
	ClearV2Payloads(ctx context.Context, reportRef shared.ID) error
}
