package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeCIService struct {
	CIAdminService
	run       *cirun.Run
	exchanged string
	created   bool
}

func (f *fakeCIService) Exchange(_ context.Context, in cirunapp.ExchangeInput) (*cirunapp.ExchangeOutput, error) {
	f.exchanged = in.IDToken
	return nil, cirunapp.ErrExchangeRefused
}

func (f *fakeCIService) Authenticate(_ context.Context, token string) (*cirun.Run, error) {
	if f.run != nil && token == "octci_"+strings.Repeat("a", 43) {
		return f.run, nil
	}
	return nil, cirun.ErrRunNotFound
}

func (f *fakeCIService) UploadReport(context.Context, *cirun.Run, *ctis.Report) (*ingest.Output, error) {
	return &ingest.Output{}, nil
}

func (f *fakeCIService) BaselineDiff(context.Context, *cirun.Run, []string) (*cirunapp.BaselineDiffOutput, error) {
	return &cirunapp.BaselineDiffOutput{}, nil
}

func (f *fakeCIService) Evaluate(context.Context, *cirun.Run, cirunapp.EvaluateInput) (*cirunapp.Verdict, error) {
	return &cirunapp.Verdict{}, nil
}

func (f *fakeCIService) GetRun(_ context.Context, tenantID, id shared.ID) (*cirun.Run, error) {
	if f.run == nil || f.run.TenantID != tenantID || f.run.ID != id {
		return nil, cirun.ErrRunNotFound
	}
	return f.run, nil
}

func (f *fakeCIService) CreateOverride(context.Context, shared.ID, cirunapp.OverrideInput, cirunapp.Actor) (*cirun.GateOverride, error) {
	f.created = true
	return &cirun.GateOverride{}, nil
}

// denyScope is a data-scope enforcer that sees no asset.
type denyScope struct{}

func (denyScope) Resolve(context.Context, shared.ID) (*shared.DataScope, error) {
	return &shared.DataScope{}, nil
}
func (denyScope) AssertAsset(context.Context, shared.ID, shared.ID) error { return shared.ErrNotFound }

func tenantRequest(method, target, body string, tenant shared.ID) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	ctx := context.WithValue(r.Context(), middleware.TenantIDKey, tenant.String())
	return r.WithContext(ctx)
}

// Every refused exchange answers the same 401 and the token never reaches a
// response.
func TestCIExchangeRefusalIsUniform(t *testing.T) {
	svc := &fakeCIService{}
	h := NewCIRunnerHandler(svc, logger.NewNop())
	w := httptest.NewRecorder()
	h.Exchange(w, httptest.NewRequest(http.MethodPost, "/api/v1/ci/oidc/exchange",
		strings.NewReader(`{"tenant_id":"`+shared.NewID().String()+`","id_token":"eyJhbGciOi.secret.sig"}`)))
	if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("refusal = %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("exchange response is cacheable")
	}
	w = httptest.NewRecorder()
	h.Exchange(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"id_token":"x","extra":1}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", w.Code)
	}
}

func TestCIAuthenticateRun(t *testing.T) {
	run := &cirun.Run{ID: shared.NewID(), TenantID: shared.NewID()}
	h := NewCIRunnerHandler(&fakeCIService{run: run}, logger.NewNop())
	var seenTenant string
	next := h.AuthenticateRun(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenTenant = middleware.GetTenantID(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	good := "octci_" + strings.Repeat("a", 43)
	call := func(auth, pathID string) int {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/ci/runs/x/evaluate", nil)
		r.SetPathValue("id", pathID)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		next.ServeHTTP(w, r)
		return w.Code
	}
	if c := call("Bearer "+good, run.ID.String()); c != http.StatusNoContent || seenTenant != run.TenantID.String() {
		t.Fatalf("valid token: %d tenant %q", c, seenTenant)
	}
	cases := map[string]struct {
		auth, id string
		want     int
	}{
		"no token":         {"", run.ID.String(), http.StatusUnauthorized},
		"sensor key shape": {"Bearer octs_" + strings.Repeat("a", 43), run.ID.String(), http.StatusUnauthorized},
		"unknown token":    {"Bearer octci_" + strings.Repeat("b", 43), run.ID.String(), http.StatusUnauthorized},
		"other run":        {"Bearer " + good, shared.NewID().String(), http.StatusNotFound},
		"basic auth":       {"Basic " + good, run.ID.String(), http.StatusUnauthorized},
	}
	for name, tc := range cases {
		if c := call(tc.auth, tc.id); c != tc.want {
			t.Fatalf("%s: %d, want %d", name, c, tc.want)
		}
	}
}

// Runs and overrides follow the data scope: out of scope is 404.
func TestCIAdminDataScope(t *testing.T) {
	tenant := shared.NewID()
	run := &cirun.Run{ID: shared.NewID(), TenantID: tenant, RepositoryAssetID: shared.NewID()}
	svc := &fakeCIService{run: run}

	h := NewCIAdminHandler(svc, nil, logger.NewNop())
	r := tenantRequest(http.MethodGet, "/api/v1/ci/runs/"+run.ID.String(), "", tenant)
	r.SetPathValue("id", run.ID.String())
	w := httptest.NewRecorder()
	h.GetRun(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("unrestricted: %d", w.Code)
	}
	// Another tenant: 404.
	r = tenantRequest(http.MethodGet, "/", "", shared.NewID())
	r.SetPathValue("id", run.ID.String())
	w = httptest.NewRecorder()
	h.GetRun(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant: %d", w.Code)
	}

	scoped := NewCIAdminHandler(svc, denyScope{}, logger.NewNop())
	r = tenantRequest(http.MethodGet, "/", "", tenant)
	r.SetPathValue("id", run.ID.String())
	w = httptest.NewRecorder()
	scoped.GetRun(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("out of scope run: %d", w.Code)
	}
	w = httptest.NewRecorder()
	scoped.CreateOverride(w, tenantRequest(http.MethodPost, "/",
		`{"repository_asset_id":"`+run.RepositoryAssetID.String()+`","commit_sha":"abcdef1","reason":"hotfix for an outage"}`, tenant))
	if w.Code != http.StatusNotFound || svc.created {
		t.Fatalf("out of scope override: %d created=%v", w.Code, svc.created)
	}
}
