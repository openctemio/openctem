package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/feedsync"
	"github.com/openctemio/openctem/api/internal/app/threat"
	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeStatusRepo struct {
	threatintel.SyncStatusRepository
	all []*threatintel.SyncStatus
}

func (r *fakeStatusRepo) GetAll(context.Context) ([]*threatintel.SyncStatus, error) {
	return r.all, nil
}

type fakeIntelRepo struct {
	threatintel.ThreatIntelRepository
	st *fakeStatusRepo
}

func (r *fakeIntelRepo) SyncStatus() threatintel.SyncStatusRepository { return r.st }

func failedStatus() *threatintel.SyncStatus {
	st := threatintel.NewSyncStatus("vulnfeed", 1)
	st.MarkSyncFailedWith("vulnfeed fetch keyset.dsse.json: status 404 from https://example.com/x", "publisher_empty", map[string]string{"host": "example.com"})
	return st
}

// The tenant route returns state and freshness, never the raw error text of a
// failed fetch; the admin route does.
func TestSyncStatuses_TenantRouteHidesRawError(t *testing.T) {
	svc := threat.NewIntelService(&fakeIntelRepo{st: &fakeStatusRepo{all: []*threatintel.SyncStatus{failedStatus()}}}, logger.NewNop())
	h := NewThreatIntelHandler(svc, nil, logger.NewNop())

	rec := httptest.NewRecorder()
	h.GetSyncStatusesTenant(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	var tenant []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tenant); err != nil || len(tenant) != 1 {
		t.Fatalf("%v %s", err, rec.Body.String())
	}
	if tenant[0]["state"] != "waiting_for_publisher" {
		t.Fatalf("state = %v", tenant[0]["state"])
	}
	for _, k := range []string{"last_error", "error_code", "error_params", "detail", "failing_since"} {
		if _, ok := tenant[0][k]; ok {
			t.Fatalf("tenant route returns %q: %s", k, rec.Body.String())
		}
	}
	if strings.Contains(rec.Body.String(), "example.com") || strings.Contains(rec.Body.String(), "404") {
		t.Fatalf("host or status leaked: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.GetSyncStatuses(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	var admin []SyncStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &admin); err != nil || len(admin) != 1 {
		t.Fatalf("%v %s", err, rec.Body.String())
	}
	a0 := admin[0]
	if a0.ErrorCode != "publisher_empty" || a0.ErrorParams["host"] != "example.com" || !strings.Contains(a0.LastError, "status 404") {
		t.Fatalf("admin view: %+v", a0)
	}
	if a0.Detail == nil || a0.IntervalSeconds != 1200 {
		t.Fatalf("admin detail/interval: %+v", a0)
	}
}

type fakeRunner struct {
	known   map[string]bool
	started []string
	outcome feedsync.Outcome
	err     error
}

func (f *fakeRunner) Has(s string) bool { return f.known[s] }
func (f *fakeRunner) Trigger(s string) (feedsync.Outcome, error) {
	if f.err != nil {
		return "", f.err
	}
	f.started = append(f.started, s)
	return f.outcome, nil
}

func enabledStatus(source string, enabled bool) *threatintel.SyncStatus {
	st := threatintel.NewSyncStatus(source, 24)
	st.SetEnabled(enabled)
	return st
}

func triggerHandler(t *testing.T, runner *fakeRunner, configured bool, statuses ...*threatintel.SyncStatus) *ThreatIntelHandler {
	t.Helper()
	svc := threat.NewIntelService(&fakeIntelRepo{st: &fakeStatusRepo{all: statuses}}, logger.NewNop())
	return NewThreatIntelHandler(svc, nil, logger.NewNop()).SetFeedRunner(runner, configured)
}

func triggerSync(h *ThreatIntelHandler, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.TriggerSync(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	return rec
}

func results(t *testing.T, rec *httptest.ResponseRecorder) []TriggerResult {
	t.Helper()
	var out struct {
		Results []TriggerResult `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
	return out.Results
}

// Sync now queues the work and answers 202 at once; the vulnfeed source is
// accepted and "all" includes it.
func TestTriggerSync_QueuesAndAnswers202(t *testing.T) {
	runner := &fakeRunner{known: map[string]bool{"epss": true, "kev": true, "vulnfeed": true}, outcome: feedsync.Queued}
	h := triggerHandler(t, runner, true, enabledStatus("epss", true), enabledStatus("kev", true), enabledStatus("vulnfeed", true))

	rec := triggerSync(h, `{"source":"vulnfeed"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	if r := results(t, rec); len(r) != 1 || r[0].Source != "vulnfeed" || r[0].Status != "queued" {
		t.Fatalf("results %+v", r)
	}

	runner.started = nil
	rec = triggerSync(h, ``)
	if rec.Code != http.StatusAccepted || len(results(t, rec)) != 3 || len(runner.started) != 3 {
		t.Fatalf("all: %d %v", rec.Code, runner.started)
	}

	runner.outcome = feedsync.AlreadyRunning
	if r := results(t, triggerSync(h, `{"source":"kev"}`)); r[0].Status != "already_running" {
		t.Fatalf("running: %+v", r)
	}
}

func TestTriggerSync_Refusals(t *testing.T) {
	runner := &fakeRunner{known: map[string]bool{"epss": true, "kev": true, "vulnfeed": true}, outcome: feedsync.Queued}
	h := triggerHandler(t, runner, false, enabledStatus("epss", false), enabledStatus("kev", true), enabledStatus("vulnfeed", true))

	if rec := triggerSync(h, `{"source":"nope"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown source: %d", rec.Code)
	}
	if rec := triggerSync(h, `{bad`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad body: %d", rec.Code)
	}
	// Switched off, or no root key: not started, and said so.
	if rec := triggerSync(h, `{"source":"epss"}`); rec.Code != http.StatusConflict {
		t.Fatalf("disabled: %d", rec.Code)
	}
	if rec := triggerSync(h, `{"source":"vulnfeed"}`); rec.Code != http.StatusConflict {
		t.Fatalf("not configured: %d", rec.Code)
	}
	// All: the others still start; the skipped ones carry a reason.
	rec := triggerSync(h, `{"source":"all"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("all: %d", rec.Code)
	}
	reasons := map[string]string{}
	for _, r := range results(t, rec) {
		reasons[r.Source] = r.Status + ":" + r.Reason
	}
	if reasons["epss"] != "skipped:disabled" || reasons["vulnfeed"] != "skipped:not_configured" || reasons["kev"] != "queued:" {
		t.Fatalf("reasons %v", reasons)
	}
	if len(runner.started) != 1 || runner.started[0] != "kev" {
		t.Fatalf("started %v", runner.started)
	}
}

func TestTriggerSync_RateLimited(t *testing.T) {
	runner := &fakeRunner{known: map[string]bool{"kev": true}, err: &feedsync.TooSoonError{RetryAfter: 9 * time.Second}}
	h := triggerHandler(t, runner, true, enabledStatus("kev", true))
	rec := triggerSync(h, `{"source":"kev"}`)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "10" {
		t.Fatalf("%d retry-after %q", rec.Code, rec.Header().Get("Retry-After"))
	}
}
