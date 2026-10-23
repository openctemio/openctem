package controller

import (
	"context"
	"errors"
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
}

func (q *stubQueue) ClaimBatch(_ context.Context, _ string, _ int) ([]*ingestjob.Job, error) {
	if q.claimIdx >= len(q.batches) {
		return nil, nil
	}
	b := q.batches[q.claimIdx]
	q.claimIdx++
	return b, nil
}
func (q *stubQueue) Complete(_ context.Context, id ingestjob.ID, result []byte) error {
	q.completes = append(q.completes, completeCall{id, result})
	return nil
}
func (q *stubQueue) Fail(_ context.Context, id ingestjob.ID, msg, public string, _ time.Time, dead bool) error {
	q.fails = append(q.fails, failCall{id, msg, public, dead})
	return nil
}
func (q *stubQueue) ReleaseStale(_ context.Context, _ time.Duration) (int, error) {
	q.releaseStale++
	return q.releaseStaleN, nil
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
