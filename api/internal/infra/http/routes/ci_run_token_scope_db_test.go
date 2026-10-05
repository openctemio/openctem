package routes

// A CI run upload token (octci_, RFC-051) is good for its own run's three
// routes and nothing else: over the real route registration, a valid run
// token reaches no tenant data route, no console route, no API-key route and
// no MCP, and the run routes accept no other credential.

import (
	"context"
	"net/http"
	"testing"

	"github.com/openctemio/ctis"

	cirunapp "github.com/openctemio/openctem/api/internal/app/cirun"
	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/domain/cirun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// stubCIRuns authenticates exactly one run token.
type stubCIRuns struct {
	token string
	run   *cirun.Run
}

func (s *stubCIRuns) Exchange(context.Context, cirunapp.ExchangeInput) (*cirunapp.ExchangeOutput, error) {
	return nil, cirunapp.ErrExchangeRefused
}

func (s *stubCIRuns) Authenticate(_ context.Context, token string) (*cirun.Run, error) {
	if token == s.token {
		return s.run, nil
	}
	return nil, cirun.ErrRunNotFound
}

func (s *stubCIRuns) UploadReport(context.Context, *cirun.Run, *ctis.Report) (*ingest.Output, error) {
	return &ingest.Output{}, nil
}

func (s *stubCIRuns) BaselineDiff(context.Context, *cirun.Run, []string) (*cirunapp.BaselineDiffOutput, error) {
	return &cirunapp.BaselineDiffOutput{}, nil
}

func (s *stubCIRuns) Evaluate(_ context.Context, run *cirun.Run, _ cirunapp.EvaluateInput) (*cirunapp.Verdict, error) {
	return &cirunapp.Verdict{RunID: run.ID.String()}, nil
}

func TestCIRunTokenLeastPrivilege_DB(t *testing.T) {
	token, _, err := cirun.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	stub := &stubCIRuns{token: token}
	h := newKeyRESTHarness(t, func(hs *Handlers) {
		hs.CIRunner = handler.NewCIRunnerHandler(stub, logger.NewNop())
		// No service behind the console: a request that got past the
		// session chain would panic, so a 401 is the chain's answer.
		hs.CIAdmin = handler.NewCIAdminHandler(nil, nil, logger.NewNop())
	})
	tenantID := h.tenant(`{}`)
	tid, _ := shared.IDFromString(tenantID)
	stub.run = &cirun.Run{ID: shared.NewID(), TenantID: tid, RepositoryAssetID: shared.NewID(), Status: cirun.StatusRunning}
	runPath := "/api/v1/ci/runs/" + stub.run.ID.String()

	userID := h.member(tenantID, "owner")
	apiKey, _ := h.mint(tenantID, userID, 0, "assets:read", "scans:ci:read", "scans:ci:write")

	bearer := func(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

	// Positive control: the token works on its own run.
	if code, body := h.do(keyReq{method: http.MethodPost, path: runPath + "/evaluate", headers: bearer(token)}); code != http.StatusOK {
		t.Fatalf("run token on its own run: %d %s", code, body)
	}

	denied := []keyReq{
		{method: http.MethodGet, path: "/api/v1/key-probe", headers: bearer(token)},
		{method: http.MethodGet, path: "/api/v1/key-probe/audit", headers: bearer(token)},
		{method: http.MethodGet, path: "/api/v1/key-probe", headers: map[string]string{"X-API-Key": token}},
		{method: http.MethodGet, path: "/api/v1/ci/runs", headers: bearer(token)},
		{method: http.MethodGet, path: runPath, headers: bearer(token)},
		{method: http.MethodGet, path: "/api/v1/ci/trust-configs", headers: bearer(token)},
		{method: http.MethodPost, path: "/api/v1/ci/gate-overrides", headers: bearer(token)},
		{method: http.MethodGet, path: "/api/v1/ci/pipelines", headers: bearer(token)},
		{method: http.MethodGet, path: "/api/v1/api-keys", headers: bearer(token)},
		{method: http.MethodPost, path: "/api/v1/mcp", headers: bearer(token)},
		// The run routes take a run token only: not an API key, not the
		// run token under another header.
		{method: http.MethodPost, path: runPath + "/evaluate", headers: bearer(apiKey)},
		{method: http.MethodPost, path: runPath + "/results", headers: bearer(apiKey)},
		{method: http.MethodPost, path: runPath + "/evaluate", headers: map[string]string{"X-API-Key": token}},
	}
	for _, rq := range denied {
		code, body := h.do(rq)
		if code != http.StatusUnauthorized {
			t.Errorf("%s %s: %d %s, want 401", rq.method, rq.path, code, body)
		}
	}

	// Another run's path with this run's token: not found.
	other := "/api/v1/ci/runs/" + shared.NewID().String()
	for _, p := range []string{"/evaluate", "/baseline-diff", "/results"} {
		if code, _ := h.do(keyReq{method: http.MethodPost, path: other + p, headers: bearer(token)}); code != http.StatusNotFound {
			t.Errorf("run token on another run%s: %d, want 404", p, code)
		}
	}
}
