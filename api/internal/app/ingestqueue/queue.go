// Package ingestqueue accepts CI results and file imports fast and hands
// them to the ingest worker (docs/rfcs/RFC-122-ingest-receipts.md, "Accept
// fast, apply async").
//
// An upload is stored as sealed parts (ingestpayload) and one job on the
// existing ingest_jobs queue (ingestjob, kind ci_results or finding_import).
// The HTTP request answers 202 with a receipt as soon as both are stored;
// the worker opens the parts, applies them and deletes them.
//
// Threat model: the raw report is stored before secrets in it are masked,
// so it is sealed with a key derived per tenant and bound to its tenant,
// job and part (a row moved to another tenant does not open); it is never
// served back. The tenant always comes from the authenticated caller (the
// run token, the session), never from the report. Parts are deleted once
// applied, and the janitor removes what a failed or abandoned upload left.
package ingestqueue

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestpayload"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Jobs is the slice of the ingest job repository the queue needs.
type Jobs interface {
	ingestjob.UploadRepository
	GetByID(ctx context.Context, tenantID, id ingestjob.ID) (*ingestjob.Job, error)
}

// Queue stores uploads and reads them back for the worker.
type Queue struct {
	jobs     Jobs
	payloads ingestpayload.Repository
	sealer   *ingestpayload.Sealer
	now      func() time.Time
	// depth and limit are the back-pressure at accept (Admit); limit 0
	// disables it.
	depth DepthReader
	limit int
}

// Admit runs the back-pressure check for a tenant (see SetBackpressure).
func (q *Queue) Admit(ctx context.Context, tenantID shared.ID) error {
	if err := q.ready(); err != nil {
		return err
	}
	return Admit(ctx, q.depth, tenantID, q.limit, q.now())
}

// SetBackpressure refuses a new upload of a tenant with limit unfinished
// jobs (429 with Retry-After) and any upload when the depth cannot be read
// (fail closed). limit <= 0 disables the check.
func (q *Queue) SetBackpressure(depth DepthReader, limit int) { q.depth, q.limit = depth, limit }

// New builds a queue. Every argument is required: without a sealer nothing
// is accepted (raw reports are never stored in plaintext).
func New(jobs Jobs, payloads ingestpayload.Repository, sealer *ingestpayload.Sealer) *Queue {
	return &Queue{jobs: jobs, payloads: payloads, sealer: sealer, now: time.Now}
}

// ErrUnavailable: the queue is not configured; the upload is refused.
var ErrUnavailable = errors.New("the ingest queue is not available")

func (q *Queue) ready() error {
	if q == nil || q.jobs == nil || q.payloads == nil || q.sealer == nil {
		return ErrUnavailable
	}
	return nil
}

// StagePart seals and stores one part of an upload that is still being
// received. The job row is enqueued after the last part (Enqueue); parts of
// an upload that never gets a job are removed by the janitor.
func (q *Queue) StagePart(ctx context.Context, tenantID, jobID shared.ID, part int, name string, body []byte) error {
	if err := q.ready(); err != nil {
		return err
	}
	p, err := q.sealer.Seal(tenantID, jobID, part, name, body)
	if err != nil {
		return err
	}
	p.ExpiresAt = q.now().Add(ingestpayload.FailedRetention)
	return q.payloads.Put(ctx, p)
}

// Commit stores the job of staged parts.
//
// When the tenant already has the same upload (the same report id and
// digest: a retry), the staged parts are dropped and that job is returned
// with created=false; one that failed only because its retries ran out is
// given a fresh budget (admit runs first). Otherwise admit runs (the caller's
// last check: a CI run's report slot) and the job is enqueued; an admit
// error drops the staged parts and is returned.
func (q *Queue) Commit(ctx context.Context, job *ingestjob.Job, admit func() error) (*ingestjob.Job, bool, error) {
	if err := q.ready(); err != nil {
		return nil, false, err
	}
	existing, err := q.jobs.GetUploadByKey(ctx, job.TenantID(), job.ReportID(), job.PayloadSHA())
	switch {
	case err == nil:
		q.Discard(context.WithoutCancel(ctx), job.TenantID(), job.ID())
		if existing.Status() == ingestjob.StatusDead && existing.PublicError() == ingestjob.ErrorApplyFailed {
			if admit != nil {
				if err := admit(); err != nil {
					return nil, false, err
				}
			}
			if _, err := q.jobs.RequeueDeadUpload(ctx, existing.TenantID(), existing.ID()); err != nil {
				return nil, false, err
			}
			if fresh, err := q.jobs.GetByID(ctx, existing.TenantID(), existing.ID()); err == nil {
				existing = fresh
			}
		}
		return existing, false, nil
	case !errors.Is(err, shared.ErrNotFound):
		q.Discard(context.WithoutCancel(ctx), job.TenantID(), job.ID())
		return nil, false, err
	}
	// A new upload only: a retry of a stored one is answered whatever the
	// queue holds.
	if err := Admit(ctx, q.depth, job.TenantID(), q.limit, q.now()); err != nil {
		q.Discard(context.WithoutCancel(ctx), job.TenantID(), job.ID())
		return nil, false, err
	}
	if admit != nil {
		if err := admit(); err != nil {
			q.Discard(context.WithoutCancel(ctx), job.TenantID(), job.ID())
			return nil, false, err
		}
	}
	stored, created, err := q.jobs.EnqueueUpload(ctx, job)
	if err != nil {
		q.Discard(context.WithoutCancel(ctx), job.TenantID(), job.ID())
		return nil, false, err
	}
	if !created && stored.ID() != job.ID() {
		q.Discard(context.WithoutCancel(ctx), job.TenantID(), job.ID())
	}
	return stored, created, nil
}

// Discard drops the staged parts of an upload that will not be enqueued.
// Best effort: the janitor removes what is left.
func (q *Queue) Discard(ctx context.Context, tenantID, jobID shared.ID) {
	if q == nil || q.payloads == nil {
		return
	}
	_ = q.payloads.DeleteJob(ctx, tenantID, jobID)
}

// Recent returns the newest upload of kind the principal sent with this
// digest within window that did not fail for good (a retry without an
// Idempotency-Key), or nil.
func (q *Queue) Recent(ctx context.Context, tenantID shared.ID, kind ingestjob.Kind, principal string, digest []byte,
	window time.Duration) (*ingestjob.Job, error) {
	if err := q.ready(); err != nil {
		return nil, err
	}
	job, err := q.jobs.FindRecentUpload(ctx, tenantID, kind, principal, digest, q.now().Add(-window))
	if errors.Is(err, shared.ErrNotFound) {
		return nil, nil
	}
	return job, err
}

// Get returns an upload job of the tenant of the given kind; another
// tenant's job, or a job of another kind, is shared.ErrNotFound.
func (q *Queue) Get(ctx context.Context, tenantID, id shared.ID, kind ingestjob.Kind) (*ingestjob.Job, error) {
	if err := q.ready(); err != nil {
		return nil, err
	}
	job, err := q.jobs.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if job.TenantID() != tenantID || job.Kind() != kind {
		return nil, shared.ErrNotFound
	}
	return job, nil
}

// BySource returns the newest upload job of kind for sourceRef of the
// tenant, or shared.ErrNotFound.
func (q *Queue) BySource(ctx context.Context, tenantID shared.ID, kind ingestjob.Kind, sourceRef string) (*ingestjob.Job, error) {
	if err := q.ready(); err != nil {
		return nil, err
	}
	return q.jobs.BySource(ctx, tenantID, kind, sourceRef)
}

// SourceState counts a source's unfinished and dead upload jobs.
func (q *Queue) SourceState(ctx context.Context, tenantID shared.ID, kind ingestjob.Kind, sourceRef string) (pending, dead int, err error) {
	if err := q.ready(); err != nil {
		return 0, 0, err
	}
	return q.jobs.SourceState(ctx, tenantID, kind, sourceRef)
}

// OpenedPart is one part of an upload, opened.
type OpenedPart struct {
	Part int
	Name string
	Body []byte
}

// Parts opens the stored parts of a job. A part that does not open fails
// the job for good (ingestjob.Permanent): retrying cannot fix it.
func (q *Queue) Parts(ctx context.Context, job *ingestjob.Job) ([]OpenedPart, error) {
	if err := q.ready(); err != nil {
		return nil, err
	}
	parts, err := q.payloads.List(ctx, job.TenantID(), job.ID())
	if err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return nil, ingestjob.Permanent(ErrorPayloadMissing, errors.New("the upload's stored report is gone"))
	}
	out := make([]OpenedPart, 0, len(parts))
	for _, p := range parts {
		body, err := q.sealer.Open(p)
		if err != nil {
			return nil, ingestjob.Permanent(ErrorPayloadMissing, fmt.Errorf("part %d: %w", p.Part, err))
		}
		out = append(out, OpenedPart{Part: p.Part, Name: p.Name, Body: body})
	}
	return out, nil
}

// Done deletes the parts of an applied job.
func (q *Queue) Done(ctx context.Context, job *ingestjob.Job) error {
	if err := q.ready(); err != nil {
		return err
	}
	return q.payloads.DeleteJob(ctx, job.TenantID(), job.ID())
}

// ErrorPayloadMissing is the public code of a job whose stored report is
// gone or does not open.
const ErrorPayloadMissing = "payload_unavailable"

// Status is the public state of an upload job.
type Status string

// Upload states a client sees.
const (
	StatusQueued     Status = "queued"
	StatusProcessing Status = "processing"
	StatusApplied    Status = "applied"
	StatusFailed     Status = "failed"
)

// StatusOf maps a job's state to what a client sees: a job waiting for a
// retry is still queued; a dead job failed.
func StatusOf(job *ingestjob.Job) Status {
	switch job.Status() {
	case ingestjob.StatusProcessing:
		return StatusProcessing
	case ingestjob.StatusCompleted:
		return StatusApplied
	case ingestjob.StatusDead:
		return StatusFailed
	default:
		return StatusQueued
	}
}

// Wait polls a job until it is finished or wait elapses, and returns its
// last state. ctx bounds it too.
func (q *Queue) Wait(ctx context.Context, tenantID, id shared.ID, kind ingestjob.Kind, wait time.Duration) (*ingestjob.Job, error) {
	deadline := q.now().Add(wait)
	for {
		job, err := q.Get(ctx, tenantID, id, kind)
		if err != nil {
			return nil, err
		}
		if job.Status().IsTerminal() || !q.now().Before(deadline) {
			return job, nil
		}
		if err := sleep(ctx, min(PollInterval, time.Until(deadline))); err != nil {
			return job, nil //nolint:nilerr // the caller's deadline: answer with the state seen
		}
	}
}

// PollInterval is how often Wait reads a job's state.
const PollInterval = 250 * time.Millisecond

// MaxWait bounds a long poll so its answer fits the server's write timeout.
const MaxWait = 10 * time.Second

// ClampWait parses a ?wait= value in seconds (or a Go duration) and bounds
// it to [0, MaxWait].
func ClampWait(raw string) time.Duration {
	if raw == "" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		n, convErr := strconv.Atoi(raw)
		if convErr != nil {
			return 0
		}
		d = time.Duration(n) * time.Second
	}
	return max(0, min(d, MaxWait))
}

var sleep = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
