package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/threat"
	"github.com/openctemio/openctem/api/internal/app/vulnfeed"
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

type fakeBundles struct {
	res vulnfeed.Result
	err error
}

func (f fakeBundles) Sync(context.Context) (vulnfeed.Result, error) { return f.res, f.err }

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

func triggerSync(h *ThreatIntelHandler, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.TriggerSync(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	return rec
}

// A failed feed is 200 with success=false for that feed, never 206, and the
// vulnfeed source is accepted.
func TestTriggerSync_VulnfeedAcceptedAndFailureReported(t *testing.T) {
	h := NewThreatIntelHandler(nil, nil, logger.NewNop())
	if rec := triggerSync(h, `{"source":"vulnfeed"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("without a bundle syncer: %d", rec.Code)
	}

	h.SetBundleSyncer(fakeBundles{err: errors.New("vulnfeed fetch keyset.dsse.json: status 404")})
	rec := triggerSync(h, `{"source":"vulnfeed"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out struct {
		Results []SyncResultResponse `json:"results"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Results) != 1 {
		t.Fatalf("%v %s", err, rec.Body.String())
	}
	if r := out.Results[0]; r.Source != "vulnfeed" || r.Success || r.Error == "" {
		t.Fatalf("result: %+v", r)
	}

	h.SetBundleSyncer(fakeBundles{res: vulnfeed.Result{Ran: true, CVEs: 12}})
	rec = triggerSync(h, `{"source":"vulnfeed"}`)
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if r := out.Results[0]; !r.Success || r.RecordsSynced != 12 {
		t.Fatalf("ok result: %+v", r)
	}

	if rec := triggerSync(h, `{"source":"nope"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown source: %d", rec.Code)
	}
}
