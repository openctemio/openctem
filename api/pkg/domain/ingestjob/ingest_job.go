// Package ingestjob provides the domain entities for the asynchronous ingest
// queue (RFC-005). An ingest job is a persisted, raw sensor payload waiting to
// be processed by a bounded worker pool, decoupling accept (fast, in the HTTP
// request) from process (async).
package ingestjob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	// kind is what the job applies; sourceRef the CI run or upload receipt
	// it belongs to; submittedBy the principal that sent it; publicError the
	// fixed code a client sees when it failed for good.
	kind        Kind
	sourceRef   string
	submittedBy string
	publicError string

	// lane orders the claim; scopeKey serialises the jobs that write one
	// asset scope (at most one processing per key).
	lane     Lane
	scopeKey string
}

// Lane orders the claim: urgent before interactive before bulk, fair across
// tenants within a lane. The server decides it, never the report.
type Lane int

const (
	// LaneUrgent: a report with a KEV or critical finding from a trusted
	// channel (a CI run).
	LaneUrgent Lane = 0
	// LaneInteractive: someone waits on it (a person's import, a CI gate).
	LaneInteractive Lane = 1
	// LaneBulk: scheduled sensor runs (the default).
	LaneBulk Lane = 2
)

// String names the lane (metrics, logs).
func (l Lane) String() string {
	switch l {
	case LaneUrgent:
		return "urgent"
	case LaneInteractive:
		return "interactive"
	default:
		return "bulk"
	}
}

// MaxScopeKey bounds a scope key (the column width).
const MaxScopeKey = 160

// ScopeKey builds the scope key of a tenant's asset scope: "<tenant>:<part>:...".
func ScopeKey(tenantID shared.ID, parts ...string) string {
	k := tenantID.String()
	for _, p := range parts {
		k += ":" + p
	}
	if len(k) > MaxScopeKey {
		sum := sha256.Sum256([]byte(k))
		k = tenantID.String() + ":h:" + hex.EncodeToString(sum[:16])
	}
	return k
}

// Lane returns the job's lane (bulk unless set).
func (j *Job) Lane() Lane { return j.lane }

// ScopeKey returns the job's scope key ("" for none).
func (j *Job) ScopeKey() string { return j.scopeKey }

// Route sets the lane and scope key of a not-yet-stored job (also used when
// rehydrating a job).
func (j *Job) Route(lane Lane, scopeKey string) *Job {
	if lane < LaneUrgent || lane > LaneBulk {
		lane = LaneBulk
	}
	j.lane, j.scopeKey = lane, scopeKey
	return j
}

// Kind is what a job applies.
type Kind string

const (
	// KindSensor is a sensor report (protocol v1 or v2).
	KindSensor Kind = "sensor"
	// KindCIResults is a CI run's uploaded results (RFC-051).
	KindCIResults Kind = "ci_results"
	// KindFindingImport is a POST /findings/imports upload (RFC-122).
	KindFindingImport Kind = "finding_import"
)

// IsUpload reports whether the job is a CI or import upload: its raw report
// is in ingest_payloads and its payload column holds only the envelope.
func (k Kind) IsUpload() bool { return k == KindCIResults || k == KindFindingImport }

// NewUploadJob builds a pending CI results or import job. envelope is the
// small JSON the processor needs besides the raw report (which is stored
// sealed in ingest_payloads, never in the job row); digest is the SHA-256
// of the raw report, the job's idempotency hash, so the same bytes for the
// same reportID are one job.
func NewUploadJob(id, tenantID shared.ID, kind Kind, sourceRef, submittedBy, reportID string, envelope, digest []byte) *Job {
	now := time.Now()
	if envelope == nil {
		envelope = []byte("{}")
	}
	return &Job{
		id: id, tenantID: tenantID, reportID: reportID, sourceType: string(kind),
		payload: envelope, payloadSHA: append([]byte(nil), digest...),
		status: StatusPending, maxAttempts: DefaultMaxAttempts,
		availableAt: now, createdAt: now, updatedAt: now,
		kind: kind, sourceRef: sourceRef, submittedBy: submittedBy, lane: LaneInteractive,
	}
}

// PermanentError is a job error a retry cannot fix (an unreadable report,
// a report outside the run's repository, a run already judged). The worker
// marks the job dead at once and shows Code to the client.
type PermanentError struct {
	Code string
	Err  error
}

func (e *PermanentError) Error() string {
	if e.Err == nil {
		return e.Code
	}
	return e.Code + ": " + e.Err.Error()
}

func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent wraps err as a permanent job error with a fixed public code.
func Permanent(code string, err error) error { return &PermanentError{Code: code, Err: err} }

// Public error codes of a job that failed for good.
const (
	// ErrorApplyFailed: the retries ran out.
	ErrorApplyFailed = "apply_failed"
)

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
	// The segments and the commit of one report run one at a time.
	if !seg.ReportRef.IsZero() {
		j.scopeKey = ScopeKey(tenantID, "report", seg.ReportRef.String())
	}
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
		lane:        LaneBulk,
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
func (j *Job) SourceRef() string      { return j.sourceRef }
func (j *Job) SubmittedBy() string    { return j.submittedBy }
func (j *Job) PublicError() string    { return j.publicError }

// Kind returns what the job applies (a sensor report when unset).
func (j *Job) Kind() Kind {
	if j.kind == "" {
		return KindSensor
	}
	return j.kind
}

// SetUpload attaches the upload columns when rehydrating a job (repository
// use).
func (j *Job) SetUpload(kind Kind, sourceRef, submittedBy, publicError string) {
	j.kind, j.sourceRef, j.submittedBy, j.publicError = kind, sourceRef, submittedBy, publicError
}

// Backoff returns the retry delay for the given attempt count: exponential
// (30s, 60s, 120s, …) capped at 10 minutes.
func Backoff(attempts int) time.Duration { return backoff(attempts, 30*time.Second, 10*time.Minute) }

// BackoffFor is the retry delay of a job of kind k: an upload someone waits
// on (a CI gate, a person) retries after 2s, 4s, 8s ... capped at one
// minute; a sensor report keeps Backoff.
func BackoffFor(k Kind, attempts int) time.Duration {
	if k.IsUpload() {
		return backoff(attempts, 2*time.Second, time.Minute)
	}
	return Backoff(attempts)
}

func backoff(attempts int, base, maxDelay time.Duration) time.Duration {
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
		availableAt: availableAt, createdAt: createdAt, updatedAt: updatedAt, lane: LaneBulk,
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
	// availableAt (status pending) or marks it dead when retries are
	// exhausted. publicErr is the fixed code a client sees on a dead job
	// (empty for a retry).
	Fail(ctx context.Context, id ID, errMsg, publicErr string, availableAt time.Time, dead bool) error

	// GetByID fetches a job scoped to its tenant (status polling).
	GetByID(ctx context.Context, tenantID, id ID) (*Job, error)

	// CountPendingByTenant returns how many pending/processing jobs a tenant has
	// (for accept-path queue-depth backpressure).
	CountPendingByTenant(ctx context.Context, tenantID shared.ID) (int, error)

	// CountPending returns the global number of not-yet-terminal jobs across all
	// tenants (for the queue-depth metric).
	CountPending(ctx context.Context) (int, error)

	// ReleaseStale resets jobs stuck in processing (worker crash) back to
	// pending when their lock is older than olderThan. A job with no attempts
	// left is marked dead instead (a payload that crashes the worker is not
	// retried for ever) and returned in dead. Returns the count reset.
	ReleaseStale(ctx context.Context, olderThan time.Duration) (released int, dead []*Job, err error)
}

// UploadRepository is the CI results and file import side of the queue.
type UploadRepository interface {
	// EnqueueUpload inserts a pending upload job. When the tenant already
	// has a job with the same report id and digest, nothing is inserted and
	// that job is returned with created=false.
	EnqueueUpload(ctx context.Context, job *Job) (stored *Job, created bool, err error)
	// FindRecentUpload returns the newest job of kind the principal sent
	// with this digest since the given time that did not fail for good, or
	// shared.ErrNotFound.
	FindRecentUpload(ctx context.Context, tenantID shared.ID, kind Kind, submittedBy string, digest []byte, since time.Time) (*Job, error)
	// GetUploadByKey returns the tenant's job with this report id and
	// digest (the idempotency key), or shared.ErrNotFound.
	GetUploadByKey(ctx context.Context, tenantID shared.ID, reportID string, digest []byte) (*Job, error)
	// RequeueDeadUpload gives a dead upload job of the tenant a fresh retry
	// budget, when its stored report is still there. It reports whether
	// the job was requeued.
	RequeueDeadUpload(ctx context.Context, tenantID, id shared.ID) (bool, error)
	// BySource returns the newest job of kind for sourceRef of the tenant,
	// or shared.ErrNotFound.
	BySource(ctx context.Context, tenantID shared.ID, kind Kind, sourceRef string) (*Job, error)
	// SourceState counts the tenant's jobs of kind for sourceRef that are
	// not finished (pending or processing) and that failed for good.
	SourceState(ctx context.Context, tenantID shared.ID, kind Kind, sourceRef string) (pending, dead int, err error)
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
