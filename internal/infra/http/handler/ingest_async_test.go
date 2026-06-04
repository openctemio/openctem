package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/ingestjob"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// stubIngestJobRepo records calls for the async handler tests.
type stubIngestJobRepo struct {
	pending   int
	enqueued  []*ingestjob.Job
	enqueueFn func(*ingestjob.Job) (*ingestjob.Job, bool, error)
	getFn     func(shared.ID) (*ingestjob.Job, error)
}

func (s *stubIngestJobRepo) Enqueue(_ context.Context, job *ingestjob.Job) (*ingestjob.Job, bool, error) {
	s.enqueued = append(s.enqueued, job)
	if s.enqueueFn != nil {
		return s.enqueueFn(job)
	}
	return job, true, nil
}
func (s *stubIngestJobRepo) ClaimBatch(_ context.Context, _ string, _ int) ([]*ingestjob.Job, error) {
	return nil, nil
}
func (s *stubIngestJobRepo) Complete(_ context.Context, _ ingestjob.ID, _ []byte) error { return nil }
func (s *stubIngestJobRepo) Fail(_ context.Context, _ ingestjob.ID, _ string, _ time.Time, _ bool) error {
	return nil
}
func (s *stubIngestJobRepo) GetByID(_ context.Context, _, id ingestjob.ID) (*ingestjob.Job, error) {
	if s.getFn != nil {
		return s.getFn(id)
	}
	return nil, shared.ErrNotFound
}
func (s *stubIngestJobRepo) CountPendingByTenant(_ context.Context, _ shared.ID) (int, error) {
	return s.pending, nil
}
func (s *stubIngestJobRepo) ReleaseStale(_ context.Context, _ time.Duration) (int, error) {
	return 0, nil
}

func newAsyncHandler(repo ingestjob.Repository, maxPending int) *IngestHandler {
	h := NewIngestHandler(nil, nil, logger.NewNop())
	h.SetAsyncIngest(repo, maxPending)
	return h
}

func reqWithAgent(t *testing.T, body string) (*http.Request, *agent.Agent) {
	t.Helper()
	tid := shared.NewID()
	agt := &agent.Agent{ID: shared.NewID(), TenantID: &tid, Status: agent.AgentStatusActive}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/agent/ingest", strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), agentContextKey, agt))
	return r, agt
}

func TestIngestCTIS_Async_Enqueues202(t *testing.T) {
	repo := &stubIngestJobRepo{}
	h := newAsyncHandler(repo, 100)
	r, _ := reqWithAgent(t, `{"version":"1.0","metadata":{"id":"scan-async-1"}}`)
	w := httptest.NewRecorder()

	h.IngestCTIS(w, r)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	if len(repo.enqueued) != 1 {
		t.Fatalf("expected 1 enqueue, got %d", len(repo.enqueued))
	}
	var resp AsyncIngestResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad 202 body: %v", err)
	}
	if resp.JobID == "" || resp.Status != string(ingestjob.StatusPending) {
		t.Fatalf("unexpected 202 body: %+v", resp)
	}
	if resp.ReportID != "scan-async-1" {
		t.Fatalf("report id = %q, want scan-async-1", resp.ReportID)
	}
}

func TestIngestCTIS_Async_QueueFull429(t *testing.T) {
	repo := &stubIngestJobRepo{pending: 100}
	h := newAsyncHandler(repo, 100)
	r, _ := reqWithAgent(t, `{"version":"1.0"}`)
	w := httptest.NewRecorder()

	h.IngestCTIS(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header on 429")
	}
	if len(repo.enqueued) != 0 {
		t.Fatal("must not enqueue when the queue is full")
	}
}

func TestIngestCTIS_Async_InvalidPayload400(t *testing.T) {
	repo := &stubIngestJobRepo{}
	h := newAsyncHandler(repo, 0) // 0 disables the depth check
	r, _ := reqWithAgent(t, `not json`)
	w := httptest.NewRecorder()

	h.IngestCTIS(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestGetIngestJob_ReturnsStatus(t *testing.T) {
	now := time.Now()
	repo := &stubIngestJobRepo{getFn: func(id ingestjob.ID) (*ingestjob.Job, error) {
		return ingestjob.FromRow(
			id, shared.NewID(), nil, "scan-7", "trivy", []byte("{}"), []byte("sha"),
			ingestjob.StatusCompleted, 1, 5, 0, []byte(`{"findings_created":4}`), "", "", nil,
			now, now, now,
		), nil
	}}
	h := newAsyncHandler(repo, 100)

	tid := shared.NewID()
	agt := &agent.Agent{ID: shared.NewID(), TenantID: &tid, Status: agent.AgentStatusActive}
	jobID := shared.NewID().String()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/agent/ingest/jobs/"+jobID, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", jobID)
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, agentContextKey, agt)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	h.GetIngestJob(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp IngestJobStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad body: %v", err)
	}
	if resp.Status != string(ingestjob.StatusCompleted) || string(resp.Result) != `{"findings_created":4}` {
		t.Fatalf("unexpected status body: %+v", resp)
	}
}
