package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func postRunResults(t *testing.T, h *CIRunnerHandler, run *cirun.Run, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/ci/runs/"+run.ID.String()+"/results", bytes.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), ciRunContextKey{}, run))
	w := httptest.NewRecorder()
	h.UploadResults(w, r)
	return w
}

func exportRun() *cirun.Run {
	return &cirun.Run{ID: shared.NewID(), TenantID: shared.NewID(), RepositoryAssetID: shared.NewID(),
		Repository: "github.com/acme/api", Branch: "main", CommitSHA: strings.Repeat("a", 40)}
}

const ddExport = `{"findings": [
 {"title": "SQLi", "severity": "High", "description": "d", "endpoints": [{"host": "shop.example.com", "protocol": "https"}]},
 {"title": "In code", "severity": "Medium", "description": "d", "file_path": "src/app.py", "line": 3}
]}`

// An upload is stored and answered 202 with its id and Location; a tool
// export and a CTIS report are told apart before they are queued (the
// worker converts an export).
func TestCIUpload_AcceptedWithLocation(t *testing.T) {
	ctisBody := `{"version":"1.4","metadata":{"timestamp":"2026-10-05T00:00:00Z"},"assets":[{"id":"r","type":"repository","value":"github.com/acme/api"}],"findings":[]}`
	for name, tc := range map[string]struct {
		body   string
		export bool
	}{
		"ctis report": {ctisBody, false},
		"tool export": {ddExport, true},
	} {
		t.Run(name, func(t *testing.T) {
			svc := &fakeCIService{}
			run := exportRun()
			w := postRunResults(t, NewCIRunnerHandler(svc, logger.NewNop()), run, []byte(tc.body))
			if w.Code != http.StatusAccepted {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			var resp CIUploadAccepted
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			want := "/api/v1/ci/runs/" + run.ID.String() + "/results/" + resp.UploadID
			if resp.Status != "queued" || resp.Location != want || w.Header().Get("Location") != want {
				t.Fatalf("response %+v, Location %q", resp, w.Header().Get("Location"))
			}
			if len(svc.exports) != 1 || svc.exports[0] != tc.export {
				t.Fatalf("export flags %v, want [%v]", svc.exports, tc.export)
			}
		})
	}
}

// Refusals the service decides at accept keep their status.
func TestCIUpload_AcceptRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"invalid report":   {cirunapp.ErrInvalidReport, http.StatusBadRequest},
		"out of scope":     {cirunapp.ErrReportOutOfScope, http.StatusBadRequest},
		"run judged":       {cirun.ErrRunEvaluated, http.StatusConflict},
		"report cap":       {cirun.ErrRunReportCap, http.StatusConflict},
		"queue not wired":  {cirunapp.ErrUploadsUnavailable, http.StatusServiceUnavailable},
		"store failed (5)": {context.DeadlineExceeded, http.StatusInternalServerError},
	} {
		t.Run(name, func(t *testing.T) {
			svc := &fakeCIService{acceptErr: tc.err}
			w := postRunResults(t, NewCIRunnerHandler(svc, logger.NewNop()), exportRun(), []byte(ddExport))
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// A run's Idempotency-Key needs the durable store: without one the request
// is refused (fail closed), never accepted twice.
func TestCIUpload_IdempotencyKeyWithoutStoreRefused(t *testing.T) {
	svc := &fakeCIService{}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/ci/runs/x/results", strings.NewReader(ddExport))
	run := exportRun()
	r = r.WithContext(context.WithValue(r.Context(), ciRunContextKey{}, run))
	r.Header.Set("Idempotency-Key", "k-1")
	w := httptest.NewRecorder()
	NewCIRunnerHandler(svc, logger.NewNop()).UploadResults(w, r)
	if w.Code != http.StatusServiceUnavailable || len(svc.accepted) != 0 {
		t.Fatalf("status %d, accepted %d", w.Code, len(svc.accepted))
	}
}

// The verdict answers 503 with Retry-After while the run's uploads are
// being applied.
func TestCIEvaluate_UploadsPendingIs503(t *testing.T) {
	h := NewCIRunnerHandler(&fakeCIService{}, logger.NewNop())
	w := httptest.NewRecorder()
	h.writeErr(w, "evaluate CI run", cirunapp.ErrUploadsPending)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" || !strings.Contains(w.Body.String(), "INGEST_PENDING") {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body.String())
	}
}

// The state of an upload of another run (or tenant) is 404.
func TestCIUploadStatus_OtherRunIs404(t *testing.T) {
	h := NewCIRunnerHandler(&fakeCIService{}, logger.NewNop())
	run := exportRun()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/ci/runs/x/results/y", nil)
	r.SetPathValue("report_id", shared.NewID().String())
	r = r.WithContext(context.WithValue(r.Context(), ciRunContextKey{}, run))
	w := httptest.NewRecorder()
	h.UploadStatus(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d", w.Code)
	}
}
