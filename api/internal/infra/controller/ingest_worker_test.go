package controller

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type completeCall struct {
	id     ingestjob.ID
	result []byte
}
type failCall struct {
	id     ingestjob.ID
	msg    string
	public string
	dead   bool
}

type stubQueue struct {
	batches       [][]*ingestjob.Job // returned by successive ClaimBatch calls
	claimIdx      int
	completes     []completeCall
	fails         []failCall
	releaseStale  int
	releaseStaleN int
	staleDead     []*ingestjob.Job

	mu          sync.Mutex
	renews      int
	renewErr    error
	completeErr error
}

func (q *stubQueue) ClaimBatch(_ context.Context, _ string, _ int) ([]*ingestjob.Job, error) {
	if q.claimIdx >= len(q.batches) {
		return nil, nil
	}
	b := q.batches[q.claimIdx]
	q.claimIdx++
	return b, nil
}
func (q *stubQueue) Complete(_ context.Context, id ingestjob.ID, _ int, result []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.completes = append(q.completes, completeCall{id, result})
	return q.completeErr
}
func (q *stubQueue) Fail(_ context.Context, id ingestjob.ID, _ int, msg, public string, _ time.Time, dead bool) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.fails = append(q.fails, failCall{id, msg, public, dead})
	return nil
}
func (q *stubQueue) Renew(_ context.Context, _ shared.ID, _ ingestjob.ID, _ int) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.renews++
	return q.renewErr
}
func (q *stubQueue) ReleaseStale(_ context.Context, _ time.Duration) (int, []*ingestjob.Job, error) {
	q.releaseStale++
	return q.releaseStaleN, q.staleDead, nil
}
func (q *stubQueue) CountPending(_ context.Context) (int, error) { return 0, nil }

type stubProcessor struct {
	result []byte
	err    error
}

func (p *stubProcessor) Process(_ context.Context, _ *ingestjob.Job) ([]byte, error) {
	return p.result, p.err
}

func newJob(t *testing.T) *ingestjob.Job {
	t.Helper()
	return ingestjob.NewJob(shared.NewID(), nil, "scan-1", "trivy", []byte(`{"version":"1.0"}`))
}

func TestIngestWorker_Success_Completes(t *testing.T) {
	q := &stubQueue{batches: [][]*ingestjob.Job{{newJob(t)}}}
	p := &stubProcessor{result: []byte(`{"findings_created":1}`)}
	c := NewIngestWorkerController(q, p, &IngestWorkerControllerConfig{})

	n, err := c.Reconcile(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("Reconcile = %d, err=%v (want 1)", n, err)
	}
	if len(q.completes) != 1 || len(q.fails) != 0 {
		t.Fatalf("completes=%d fails=%d (want 1/0)", len(q.completes), len(q.fails))
	}
	if string(q.completes[0].result) != `{"findings_created":1}` {
		t.Fatalf("unexpected result stored: %s", q.completes[0].result)
	}
	if q.releaseStale == 0 {
		t.Fatal("expected ReleaseStale to be called each reconcile")
	}
}

func TestIngestWorker_Error_Retries(t *testing.T) {
	// Fresh job (attempts 0 < max 5) → fail with retry, not dead.
	q := &stubQueue{batches: [][]*ingestjob.Job{{newJob(t)}}}
	p := &stubProcessor{err: errors.New("boom")}
	c := NewIngestWorkerController(q, p, &IngestWorkerControllerConfig{})

	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile err=%v", err)
	}
	if len(q.fails) != 1 || len(q.completes) != 0 {
		t.Fatalf("fails=%d completes=%d (want 1/0)", len(q.fails), len(q.completes))
	}
	if q.fails[0].dead {
		t.Fatal("fresh job should retry (dead=false)")
	}
	if q.fails[0].msg != "boom" {
		t.Fatalf("error msg = %q, want boom", q.fails[0].msg)
	}
}

func TestIngestWorker_Error_DeadAtMaxAttempts(t *testing.T) {
	// Job already at the attempt ceiling → dead.
	now := time.Now()
	exhausted := ingestjob.FromRow(
		shared.NewID(), shared.NewID(), nil, "scan-1", "trivy",
		[]byte(`{}`), []byte("sha"), ingestjob.StatusProcessing,
		5, 5, 0, nil, "", "", nil, now, now, now,
	)
	q := &stubQueue{batches: [][]*ingestjob.Job{{exhausted}}}
	p := &stubProcessor{err: errors.New("still failing")}
	c := NewIngestWorkerController(q, p, &IngestWorkerControllerConfig{})

	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile err=%v", err)
	}
	if len(q.fails) != 1 || !q.fails[0].dead {
		t.Fatalf("expected one dead fail, got fails=%v", q.fails)
	}
}

func TestIngestWorker_DrainsMultipleBatches(t *testing.T) {
	q := &stubQueue{batches: [][]*ingestjob.Job{
		{newJob(t), newJob(t)},
		{newJob(t)},
	}}
	p := &stubProcessor{result: []byte(`{}`)}
	c := NewIngestWorkerController(q, p, &IngestWorkerControllerConfig{})

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile err=%v", err)
	}
	if n != 3 || len(q.completes) != 3 {
		t.Fatalf("processed=%d completes=%d (want 3/3)", n, len(q.completes))
	}
}

// deadLetterProcessor records the jobs it is told failed for good.
type deadLetterProcessor struct {
	stubProcessor
	dead []string
}

func (p *deadLetterProcessor) DeadLetter(_ context.Context, _ *ingestjob.Job, code string) {
	p.dead = append(p.dead, code)
}

// A permanent error (an unreadable upload) is dead at its first attempt,
// with its fixed code for the client, and the processor is told.
func TestIngestWorker_PermanentErrorIsDeadAtOnce(t *testing.T) {
	q := &stubQueue{batches: [][]*ingestjob.Job{{newJob(t)}}}
	p := &deadLetterProcessor{stubProcessor: stubProcessor{err: ingestjob.Permanent("unreadable", errors.New("bad xml"))}}
	c := NewIngestWorkerController(q, p, &IngestWorkerControllerConfig{})
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(q.fails) != 1 || !q.fails[0].dead || q.fails[0].public != "unreadable" {
		t.Fatalf("fails = %+v", q.fails)
	}
	if len(p.dead) != 1 || p.dead[0] != "unreadable" {
		t.Fatalf("dead letters = %v", p.dead)
	}
}

// A transient error retries without a public code; once the attempts run
// out the job is dead with apply_failed.
func TestIngestWorker_ExhaustedRetriesAreApplyFailed(t *testing.T) {
	job := ingestjob.FromRow(shared.NewID(), shared.NewID(), nil, "r", "", []byte("{}"), make([]byte, 32),
		ingestjob.StatusProcessing, ingestjob.DefaultMaxAttempts, ingestjob.DefaultMaxAttempts, 0, nil, "", "", nil,
		time.Now(), time.Now(), time.Now())
	q := &stubQueue{batches: [][]*ingestjob.Job{{newJob(t)}, {job}}}
	p := &deadLetterProcessor{stubProcessor: stubProcessor{err: errors.New("db down")}}
	c := NewIngestWorkerController(q, p, &IngestWorkerControllerConfig{})
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(q.fails) != 2 || q.fails[0].dead || q.fails[0].public != "" || !q.fails[1].dead || q.fails[1].public != ingestjob.ErrorApplyFailed {
		t.Fatalf("fails = %+v", q.fails)
	}
	if len(p.dead) != 1 {
		t.Fatalf("dead letters = %v", p.dead)
	}
}

// A job whose lease expired on its last attempt is dead-lettered once.
func TestIngestWorker_StaleDeadJobsAreDeadLettered(t *testing.T) {
	q := &stubQueue{staleDead: []*ingestjob.Job{newJob(t)}}
	p := &deadLetterProcessor{}
	c := NewIngestWorkerController(q, p, &IngestWorkerControllerConfig{})
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(p.dead) != 1 || p.dead[0] != ingestjob.ErrorApplyFailed {
		t.Fatalf("dead letters = %v", p.dead)
	}
}

// funcProcessor runs fn as the job's processing.
type funcProcessor func(ctx context.Context, job *ingestjob.Job) ([]byte, error)

func (f funcProcessor) Process(ctx context.Context, job *ingestjob.Job) ([]byte, error) {
	return f(ctx, job)
}

// A job that runs longer than the lease keeps it by renewing, and completes:
// the worker's own timeout tracks the renewed lease, not the first one.
func TestIngestWorker_LongJobRenewsItsLeaseAndCompletes(t *testing.T) {
	q := &stubQueue{batches: [][]*ingestjob.Job{{newJob(t)}}}
	p := funcProcessor(func(ctx context.Context, _ *ingestjob.Job) ([]byte, error) {
		select {
		case <-time.After(400 * time.Millisecond): // > 4x the lease
			return []byte(`{}`), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	c := NewIngestWorkerController(q, p, &IngestWorkerControllerConfig{
		LeaseTimeout: 90 * time.Millisecond, RenewEvery: 30 * time.Millisecond, MaxJobDuration: time.Minute})
	if got, want := c.ReconcileTimeout(), 90*time.Millisecond+time.Minute; got != want {
		t.Fatalf("ReconcileTimeout = %v, want %v", got, want)
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.ReconcileTimeout())
	defer cancel()
	if _, err := c.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.completes) != 1 || len(q.fails) != 0 {
		t.Fatalf("completes=%d fails=%d (want 1/0)", len(q.completes), len(q.fails))
	}
	if q.renews < 3 {
		t.Fatalf("renewed %d times, want several", q.renews)
	}
}

// A worker that lost its lease stops the work and writes nothing: neither
// Complete nor Fail, and no dead letter.
func TestIngestWorker_LostLeaseStopsAndWritesNothing(t *testing.T) {
	q := &stubQueue{batches: [][]*ingestjob.Job{{newJob(t)}}, renewErr: ingestjob.ErrLeaseLost}
	stopped := false
	p := funcProcessor(func(ctx context.Context, _ *ingestjob.Job) ([]byte, error) {
		select {
		case <-ctx.Done():
			stopped = true
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return []byte(`{}`), nil
		}
	})
	c := NewIngestWorkerController(q, p, &IngestWorkerControllerConfig{
		LeaseTimeout: 90 * time.Millisecond, RenewEvery: 20 * time.Millisecond})
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !stopped {
		t.Fatal("the work was not canceled")
	}
	if len(q.completes) != 0 || len(q.fails) != 0 {
		t.Fatalf("a worker without the lease wrote: completes=%d fails=%d", len(q.completes), len(q.fails))
	}
}

// A Complete refused for a lost lease is not retried or reported as done.
func TestIngestWorker_CompleteRefusedForLostLease(t *testing.T) {
	q := &stubQueue{batches: [][]*ingestjob.Job{{newJob(t)}}, completeErr: ingestjob.ErrLeaseLost}
	c := NewIngestWorkerController(q, &stubProcessor{result: []byte(`{}`)}, &IngestWorkerControllerConfig{})
	if n, err := c.Reconcile(context.Background()); err != nil || n != 1 {
		t.Fatalf("Reconcile = %d, %v", n, err)
	}
	if len(q.fails) != 0 {
		t.Fatalf("fails = %d", len(q.fails))
	}
}

// The hard cap ends a job however often its lease is renewed.
func TestIngestWorker_HardCapCancelsTheJob(t *testing.T) {
	q := &stubQueue{batches: [][]*ingestjob.Job{{newJob(t)}}}
	p := funcProcessor(func(ctx context.Context, _ *ingestjob.Job) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	c := NewIngestWorkerController(q, p, &IngestWorkerControllerConfig{
		LeaseTimeout: time.Minute, RenewEvery: 10 * time.Millisecond, MaxJobDuration: 80 * time.Millisecond})
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(q.fails) != 1 || len(q.completes) != 0 {
		t.Fatalf("fails=%d completes=%d (want 1/0)", len(q.fails), len(q.completes))
	}
	if q.renews == 0 {
		t.Fatal("the lease was not renewed while the job ran")
	}
}
