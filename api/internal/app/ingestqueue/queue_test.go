package ingestqueue

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestpayload"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type memJobs struct {
	byKey    map[string]*ingestjob.Job
	requeued int
}

func key(j *ingestjob.Job) string {
	return j.TenantID().String() + "/" + j.ReportID() + "/" + string(j.PayloadSHA())
}

func (m *memJobs) EnqueueUpload(_ context.Context, job *ingestjob.Job) (*ingestjob.Job, bool, error) {
	if m.byKey == nil {
		m.byKey = map[string]*ingestjob.Job{}
	}
	if j, ok := m.byKey[key(job)]; ok {
		return j, false, nil
	}
	m.byKey[key(job)] = job
	return job, true, nil
}
func (m *memJobs) GetUploadByKey(_ context.Context, tenantID shared.ID, reportID string, digest []byte) (*ingestjob.Job, error) {
	if j, ok := m.byKey[tenantID.String()+"/"+reportID+"/"+string(digest)]; ok {
		return j, nil
	}
	return nil, shared.ErrNotFound
}
func (m *memJobs) RequeueDeadUpload(context.Context, shared.ID, shared.ID) (bool, error) {
	m.requeued++
	return true, nil
}
func (m *memJobs) FindRecentUpload(context.Context, shared.ID, ingestjob.Kind, string, []byte, time.Time) (*ingestjob.Job, error) {
	return nil, shared.ErrNotFound
}
func (m *memJobs) BySource(context.Context, shared.ID, ingestjob.Kind, string) (*ingestjob.Job, error) {
	return nil, shared.ErrNotFound
}
func (m *memJobs) SourceState(context.Context, shared.ID, ingestjob.Kind, string) (int, int, error) {
	return 0, 0, nil
}
func (m *memJobs) GetByID(_ context.Context, tenantID, id shared.ID) (*ingestjob.Job, error) {
	for _, j := range m.byKey {
		if j.ID() == id && j.TenantID() == tenantID {
			return j, nil
		}
	}
	return nil, shared.ErrNotFound
}

type memPayloads struct {
	parts map[shared.ID][]*ingestpayload.Part
}

func (m *memPayloads) Put(_ context.Context, p *ingestpayload.Part) error {
	if m.parts == nil {
		m.parts = map[shared.ID][]*ingestpayload.Part{}
	}
	m.parts[p.JobID] = append(m.parts[p.JobID], p)
	return nil
}
func (m *memPayloads) List(_ context.Context, tenantID, jobID shared.ID) ([]*ingestpayload.Part, error) {
	var out []*ingestpayload.Part
	for _, p := range m.parts[jobID] {
		if p.TenantID == tenantID {
			out = append(out, p)
		}
	}
	return out, nil
}
func (m *memPayloads) DeleteJob(_ context.Context, _, jobID shared.ID) error {
	delete(m.parts, jobID)
	return nil
}

func newTestQueue(t *testing.T) (*Queue, *memJobs, *memPayloads) {
	t.Helper()
	s, err := ingestpayload.NewSealer(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	j, p := &memJobs{}, &memPayloads{}
	return New(j, p, s), j, p
}

func uploadJob(tenant shared.ID, digest byte) *ingestjob.Job {
	return ingestjob.NewUploadJob(shared.NewID(), tenant, ingestjob.KindCIResults, "run", "run:x", "ci:run", nil, bytes.Repeat([]byte{digest}, 32))
}

func TestCommitStoresOnceAndDropsARetrysParts(t *testing.T) {
	q, jobs, payloads := newTestQueue(t)
	ctx := context.Background()
	tenant := shared.NewID()
	first := uploadJob(tenant, 1)
	if err := q.StagePart(ctx, tenant, first.ID(), 0, "r", []byte("report")); err != nil {
		t.Fatal(err)
	}
	admits := 0
	admit := func() error { admits++; return nil }
	stored, created, err := q.Commit(ctx, first, admit)
	if err != nil || !created || stored.ID() != first.ID() || admits != 1 {
		t.Fatalf("first commit: %v %v %v admits %d", stored, created, err, admits)
	}
	retry := uploadJob(tenant, 1)
	_ = q.StagePart(ctx, tenant, retry.ID(), 0, "r", []byte("report"))
	stored, created, err = q.Commit(ctx, retry, admit)
	if err != nil || created || stored.ID() != first.ID() {
		t.Fatalf("retry commit: %v %v %v", stored, created, err)
	}
	if admits != 1 {
		t.Fatalf("a retry took another slot (%d admits)", admits)
	}
	if _, ok := payloads.parts[retry.ID()]; ok {
		t.Fatal("the retry's staged parts were kept")
	}
	if len(jobs.byKey) != 1 {
		t.Fatalf("%d jobs", len(jobs.byKey))
	}
}

func TestCommitAdmitRefusalStoresNothing(t *testing.T) {
	q, jobs, payloads := newTestQueue(t)
	ctx := context.Background()
	tenant := shared.NewID()
	job := uploadJob(tenant, 2)
	_ = q.StagePart(ctx, tenant, job.ID(), 0, "r", []byte("report"))
	refused := errors.New("run judged")
	if _, _, err := q.Commit(ctx, job, func() error { return refused }); !errors.Is(err, refused) {
		t.Fatalf("err = %v", err)
	}
	if len(jobs.byKey) != 0 || len(payloads.parts) != 0 {
		t.Fatalf("stored %d jobs, %d parts after a refusal", len(jobs.byKey), len(payloads.parts))
	}
}

// A retry of an upload whose retries ran out gets a fresh budget; one that
// failed for a reason a retry cannot fix stays failed.
func TestCommitRequeuesOnlyExhaustedUploads(t *testing.T) {
	ctx := context.Background()
	for code, want := range map[string]int{ingestjob.ErrorApplyFailed: 1, "unreadable": 0} {
		q, jobs, _ := newTestQueue(t)
		tenant := shared.NewID()
		dead := ingestjob.FromRow(shared.NewID(), tenant, nil, "ci:run", "ci_results", []byte("{}"), bytes.Repeat([]byte{4}, 32),
			ingestjob.StatusDead, 5, 5, 0, nil, "", "", nil, time.Now(), time.Now(), time.Now())
		dead.SetUpload(ingestjob.KindCIResults, "run", "run:x", code)
		jobs.byKey = map[string]*ingestjob.Job{key(dead): dead}
		retry := uploadJob(tenant, 4)
		if _, _, err := q.Commit(ctx, retry, nil); err != nil {
			t.Fatal(err)
		}
		if jobs.requeued != want {
			t.Errorf("%s: requeued %d, want %d", code, jobs.requeued, want)
		}
	}
}

// Parts open only for their own tenant and job; a part that does not open
// fails the job for good.
func TestPartsOpenOnlyForTheirJob(t *testing.T) {
	q, _, payloads := newTestQueue(t)
	ctx := context.Background()
	tenant := shared.NewID()
	job := uploadJob(tenant, 5)
	_ = q.StagePart(ctx, tenant, job.ID(), 0, "r", []byte("report"))
	parts, err := q.Parts(ctx, job)
	if err != nil || len(parts) != 1 || string(parts[0].Body) != "report" {
		t.Fatalf("parts %v err %v", parts, err)
	}
	// The same sealed bytes filed under another job do not open.
	other := uploadJob(tenant, 6)
	moved := *payloads.parts[job.ID()][0]
	moved.JobID = other.ID()
	payloads.parts[other.ID()] = []*ingestpayload.Part{&moved}
	_, err = q.Parts(ctx, other)
	var perm *ingestjob.PermanentError
	if !errors.As(err, &perm) || perm.Code != ErrorPayloadMissing {
		t.Fatalf("moved part: %v", err)
	}
	// No parts at all: permanent too.
	if _, err := q.Parts(ctx, uploadJob(tenant, 7)); !errors.As(err, &perm) {
		t.Fatalf("missing parts: %v", err)
	}
}

func TestQueueWithoutSealerRefuses(t *testing.T) {
	q := New(&memJobs{}, &memPayloads{}, nil)
	if err := q.StagePart(context.Background(), shared.NewID(), shared.NewID(), 0, "", nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	var nilQ *Queue
	if _, _, err := nilQ.Commit(context.Background(), uploadJob(shared.NewID(), 1), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil queue: %v", err)
	}
}

func TestClampWait(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"": 0, "3": 3 * time.Second, "2s": 2 * time.Second, "60": MaxWait, "-5": 0, "abc": 0, "10x": 0,
	} {
		if got := ClampWait(in); got != want {
			t.Errorf("ClampWait(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestStatusOf(t *testing.T) {
	mk := func(s ingestjob.Status) *ingestjob.Job {
		return ingestjob.FromRow(shared.NewID(), shared.NewID(), nil, "", "", nil, nil, s, 1, 5, 0, nil, "", "", nil,
			time.Now(), time.Now(), time.Now())
	}
	for s, want := range map[ingestjob.Status]Status{
		ingestjob.StatusPending: StatusQueued, ingestjob.StatusFailed: StatusQueued, ingestjob.StatusProcessing: StatusProcessing,
		ingestjob.StatusCompleted: StatusApplied, ingestjob.StatusDead: StatusFailed,
	} {
		if got := StatusOf(mk(s)); got != want {
			t.Errorf("%s: %s, want %s", s, got, want)
		}
	}
}
