package handler

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	coverageapp "github.com/openctemio/openctem/api/internal/app/coverage"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	covdom "github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type stubDiscovery struct {
	runErr  error
	ran     int
	aborted int
	tenant  shared.ID
}

func (s *stubDiscovery) Overview(_ context.Context, t shared.ID) (*coverageapp.Overview, error) {
	s.tenant = t
	return &coverageapp.Overview{Stages: []covdom.StageSummary{covdom.SummarizeStage(covdom.StageAssetDiscovery,
		[]covdom.CapabilityDiscovery{{Capability: "discover.subdomains", Pairs: 3, Covered: 1, PausedReason: "=cmd|x"}}, false)}}, nil
}

func (s *stubDiscovery) Run(_ context.Context, t shared.ID, stages []covdom.DiscoveryStage) (*coverageapp.RunResult, error) {
	s.tenant = t
	if s.runErr != nil {
		return nil, s.runErr
	}
	s.ran++
	return &coverageapp.RunResult{Started: stages, NextPassWithin: time.Minute}, nil
}

func (s *stubDiscovery) AbortAll(_ context.Context, t shared.ID) (*coverageapp.AbortResult, error) {
	s.tenant = t
	s.aborted++
	return &coverageapp.AbortResult{Canceled: 2}, nil
}

type stubScope struct{ scope *shared.DataScope }

func (s stubScope) ResolveStrict(context.Context, shared.ID) (*shared.DataScope, error) {
	return s.scope, nil
}

func discoveryRequest(t *testing.T, h *EASMDiscoveryHandler, tenant shared.ID, method, path string, fn http.HandlerFunc, stage string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
	if stage != "" {
		rc := chi.NewRouteContext()
		rc.URLParams.Add("stage", stage)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rc)
	}
	rec := httptest.NewRecorder()
	fn(rec, req.WithContext(ctx))
	return rec
}

func TestEASMDiscoveryHandler_RestrictedCallerIsRefused(t *testing.T) {
	tenant := shared.NewID()
	svc := &stubDiscovery{}
	restricted := &shared.DataScope{TenantID: tenant, UserID: shared.NewID()}
	h := NewEASMDiscoveryHandler(svc, stubScope{scope: restricted}, nil, logger.NewNop())
	for name, fn := range map[string]http.HandlerFunc{"overview": h.Overview, "export": h.Export, "run-all": h.RunAll, "abort-all": h.AbortAll} {
		rec := discoveryRequest(t, h, tenant, http.MethodPost, "/", fn, "")
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "DISCOVERY_FULL_DATA_REQUIRED") {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if svc.ran != 0 || svc.aborted != 0 || !svc.tenant.IsZero() {
		t.Fatal("service reached for a restricted caller")
	}
	// No scope resolver: refused (fail closed).
	h = NewEASMDiscoveryHandler(svc, nil, nil, logger.NewNop())
	if rec := discoveryRequest(t, h, tenant, http.MethodGet, "/", h.Overview, ""); rec.Code != http.StatusForbidden {
		t.Errorf("unwired scope = %d", rec.Code)
	}
	// An unrestricted scope (an administrator from whom private program
	// assets are hidden) and a nil scope (owner) are allowed.
	for _, sc := range []*shared.DataScope{nil, {TenantID: tenant, Unrestricted: true}} {
		h = NewEASMDiscoveryHandler(svc, stubScope{scope: sc}, nil, logger.NewNop())
		if rec := discoveryRequest(t, h, tenant, http.MethodGet, "/", h.Overview, ""); rec.Code != http.StatusOK || svc.tenant != tenant {
			t.Errorf("unrestricted = %d %s", rec.Code, rec.Body.String())
		}
	}
}

func TestEASMDiscoveryHandler_RunRefusals(t *testing.T) {
	tenant := shared.NewID()
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{&coverageapp.TooSoonError{Until: time.Now().Add(30 * time.Second)}, http.StatusTooManyRequests, "DISCOVERY_RUN_TOO_SOON"},
		{coverageapp.ErrCoverageOff, http.StatusConflict, "DISCOVERY_COVERAGE_OFF"},
		{coverageapp.ErrLoopOff, http.StatusConflict, "DISCOVERY_LOOP_OFF"},
		{coverageapp.ErrBudgetSpent, http.StatusConflict, "DISCOVERY_BUDGET_SPENT"},
	}
	for _, c := range cases {
		h := NewEASMDiscoveryHandler(&stubDiscovery{runErr: c.err}, stubScope{}, nil, logger.NewNop())
		rec := discoveryRequest(t, h, tenant, http.MethodPost, "/", h.RunStage, "exposure_scan")
		if rec.Code != c.status || !strings.Contains(rec.Body.String(), c.code) {
			t.Errorf("%v = %d %s", c.err, rec.Code, rec.Body.String())
		}
		if c.status == http.StatusTooManyRequests {
			secs, err := strconv.Atoi(rec.Header().Get("Retry-After"))
			if err != nil || secs < 1 || secs > 61 {
				t.Errorf("Retry-After = %q", rec.Header().Get("Retry-After"))
			}
		}
	}
	svc := &stubDiscovery{}
	h := NewEASMDiscoveryHandler(svc, stubScope{}, nil, logger.NewNop())
	if rec := discoveryRequest(t, h, tenant, http.MethodPost, "/", h.RunStage, "bogus"); rec.Code != http.StatusBadRequest || svc.ran != 0 {
		t.Errorf("unknown stage = %d", rec.Code)
	}
	rec := discoveryRequest(t, h, tenant, http.MethodPost, "/", h.RunStage, "validation_scoping")
	if rec.Code != http.StatusAccepted || !strings.Contains(rec.Body.String(), `"started":["validation_scoping"]`) || svc.tenant != tenant {
		t.Errorf("run = %d %s", rec.Code, rec.Body.String())
	}
	if rec := discoveryRequest(t, h, tenant, http.MethodPost, "/", h.AbortAll, ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"canceled":2`) {
		t.Errorf("abort = %d %s", rec.Code, rec.Body.String())
	}
}

func TestEASMDiscoveryHandler_ExportIsCSVSafe(t *testing.T) {
	h := NewEASMDiscoveryHandler(&stubDiscovery{}, stubScope{}, nil, logger.NewNop())
	rec := discoveryRequest(t, h, shared.NewID(), http.MethodGet, "/", h.Export, "")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("export = %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	if err != nil || len(rows) != 2 || rows[0][0] != "stage" || rows[1][3] != "discover.subdomains" || rows[1][4] != "3" {
		t.Fatalf("rows = %v %v", rows, err)
	}
	if strings.HasPrefix(rows[1][11], "=") {
		t.Errorf("formula cell not neutralized: %q", rows[1][11])
	}
}
