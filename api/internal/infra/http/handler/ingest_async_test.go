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

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
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
func (s *stubIngestJobRepo) CountPending(_ context.Context) (int, error) {
	return s.pending, nil
}
func (s *stubIngestJobRepo) ReleaseStale(_ context.Context, _ time.Duration) (int, error) {
	return 0, nil
}

func newAsyncHandler(repo ingestjob.Repository, maxPending int) *IngestHandler {
	// A service with no stores: the unsolicited gate (RFC-040 §5.3) runs and,
	// with no result policy store, lets the report be queued (warn).
	svc := ingest.NewService(nil, nil, nil, nil, nil, nil, nil, nil, logger.NewNop())
	h := NewIngestHandler(svc, nil, logger.NewNop())
	h.SetAsyncIngest(repo, maxPending)
	return h
}

func reqWithSensor(t *testing.T, body string) (*http.Request, *sensor.Sensor) {
	t.Helper()
	tid := shared.NewID()
	agt := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid, Status: sensor.SensorStatusActive}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/agent/ingest", strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), sensorContextKey, agt))
	return r, agt
}

func TestIngestCTIS_Async_Enqueues202(t *testing.T) {
	repo := &stubIngestJobRepo{}
	h := newAsyncHandler(repo, 100)
	r, _ := reqWithSensor(t, `{"version":"1.0","metadata":{"id":"scan-async-1"}}`)
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
	r, _ := reqWithSensor(t, `{"version":"1.0"}`)
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
	r, _ := reqWithSensor(t, `not json`)
	w := httptest.NewRecorder()

	h.IngestCTIS(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestGetIngestJob_ReturnsStatus(t *testing.T) {
	now := time.Now()
	tid := shared.NewID()
	agt := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid, Status: sensor.SensorStatusActive}
	repo := &stubIngestJobRepo{getFn: func(id ingestjob.ID) (*ingestjob.Job, error) {
		return ingestjob.FromRow(
			id, tid, &agt.ID, "scan-7", "trivy", []byte("{}"), []byte("sha"),
			ingestjob.StatusCompleted, 1, 5, 0, []byte(`{"findings_created":4}`), "", "", nil,
			now, now, now,
		), nil
	}}
	h := newAsyncHandler(repo, 100)
	jobID := shared.NewID().String()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/agent/ingest/jobs/"+jobID, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", jobID)
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, sensorContextKey, agt)
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

func TestClientWantsSync(t *testing.T) {
	cases := []struct {
		name   string
		url    string
		prefer string
		want   bool
	}{
		{"default async", "/x", "", false},
		{"sync=true", "/x?sync=true", "", true},
		{"sync=1", "/x?sync=1", "", true},
		{"sync=false", "/x?sync=false", "", false},
		{"prefer header", "/x", "respond-sync", true},
		{"prefer mixed case", "/x", "Respond-Sync", true},
		{"prefer other", "/x", "wait", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, c.url, nil)
			if c.prefer != "" {
				r.Header.Set("Prefer", c.prefer)
			}
			if got := clientWantsSync(r); got != c.want {
				t.Fatalf("clientWantsSync(%q, Prefer=%q) = %v, want %v", c.url, c.prefer, got, c.want)
			}
		})
	}
}

// RFC-040 §5.3: a sensor reads only the ingest jobs it queued. Another
// sensor's job (same tenant) and a job no sensor queued are not found.
func TestGetIngestJob_OtherSensorsJobNotFound(t *testing.T) {
	now := time.Now()
	tid := shared.NewID()
	other := shared.NewID()
	for name, owner := range map[string]*shared.ID{"another sensor": &other, "no sensor": nil} {
		t.Run(name, func(t *testing.T) {
			repo := &stubIngestJobRepo{getFn: func(id ingestjob.ID) (*ingestjob.Job, error) {
				return ingestjob.FromRow(
					id, tid, owner, "scan-8", "trivy", []byte("{}"), []byte("sha"),
					ingestjob.StatusCompleted, 1, 5, 0, []byte(`{"findings_created":4}`), "", "", nil,
					now, now, now,
				), nil
			}}
			h := newAsyncHandler(repo, 100)
			agt := &sensor.Sensor{ID: shared.NewID(), TenantID: &tid, Status: sensor.SensorStatusActive}
			jobID := shared.NewID().String()
			r := httptest.NewRequest(http.MethodGet, "/api/v1/agent/ingest/jobs/"+jobID, nil)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("id", jobID)
			ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
			ctx = context.WithValue(ctx, sensorContextKey, agt)
			w := httptest.NewRecorder()
			h.GetIngestJob(w, r.WithContext(ctx))
			if w.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
			}
		})
	}
}
