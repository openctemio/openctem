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
	st.MarkSyncFailed("vulnfeed fetch keyset.dsse.json: status 404 from https://example.com/x")
	return st
}

// The tenant route returns state and freshness, never the raw error text of a
// failed fetch; the admin route does.
func TestSyncStatuses_TenantRouteHidesRawError(t *testing.T) {
	svc := threat.NewIntelService(&fakeIntelRepo{st: &fakeStatusRepo{all: []*threatintel.SyncStatus{failedStatus()}}}, logger.NewNop())
	h := NewThreatIntelHandler(svc, nil, logger.NewNop())

	for name, tc := range map[string]struct {
		fn   http.HandlerFunc
		want bool
	}{"tenant": {h.GetSyncStatusesTenant, false}, "admin": {h.GetSyncStatuses, true}} {
		rec := httptest.NewRecorder()
		tc.fn(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		var out []SyncStatusResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out) != 1 {
			t.Fatalf("%s: %v %s", name, err, rec.Body.String())
		}
		if got := out[0].LastError != ""; got != tc.want {
			t.Fatalf("%s: last_error present = %v, want %v (%q)", name, got, tc.want, out[0].LastError)
		}
		if !tc.want && strings.Contains(rec.Body.String(), "example.com") {
			t.Fatalf("%s: host leaked: %s", name, rec.Body.String())
		}
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
