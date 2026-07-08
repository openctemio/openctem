package defectdojo

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/app/ingest"
	ddimport "github.com/openctemio/api/internal/infra/importer/defectdojo"
	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

type fakeIntegRepo struct {
	integration.Repository
	list []*integration.Integration
	err  error
}

func (r *fakeIntegRepo) ListByProvider(_ context.Context, _ integration.ID, _ integration.Provider) ([]*integration.Integration, error) {
	return r.list, r.err
}

type fakeIngester struct {
	gotAgent *agent.Agent
	gotInput ingest.Input
	out      *ingest.Output
	err      error
}

func (i *fakeIngester) Ingest(_ context.Context, agt *agent.Agent, in ingest.Input) (*ingest.Output, error) {
	i.gotAgent = agt
	i.gotInput = in
	return i.out, i.err
}

type fakeClient struct {
	findings []ddimport.Finding
	gotBase  string
	gotTok   string
}

func (c *fakeClient) FetchFindings(_ context.Context, _ ddimport.FindingFilter) ([]ddimport.Finding, error) {
	return c.findings, nil
}

func connectedDD(t *testing.T, tenantID shared.ID, baseURL, token string) *integration.Integration {
	t.Helper()
	intg := integration.NewIntegration(shared.NewID(), tenantID, "dd",
		integration.CategorySecurity, integration.ProviderDefectDojo, integration.AuthTypeToken)
	intg.SetBaseURL(baseURL)
	intg.SetCredentials(token) // nil encryptor → identity decrypt (plaintext)
	intg.SetConnected()
	return intg
}

func TestSyncTenant_PullsConvertsIngests_TenantIsolated(t *testing.T) {
	tenantID := shared.NewID()
	repo := &fakeIntegRepo{list: []*integration.Integration{connectedDD(t, tenantID, "https://dd.example.com", "tok123")}}
	ing := &fakeIngester{out: &ingest.Output{FindingsCreated: 2, FindingsUpdated: 1, ReportID: "r-1"}}
	svc := NewSyncService(repo, ing, nil, logger.NewNop())

	fc := &fakeClient{findings: []ddimport.Finding{
		{ID: 1, Title: "a", Severity: "High", HashCode: "h1"},
		{ID: 2, Title: "b", Severity: "Low", HashCode: "h2"},
	}}
	svc.newClient = func(baseURL, token string) findingsClient {
		fc.gotBase, fc.gotTok = baseURL, token
		return fc
	}

	res, err := svc.SyncTenant(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}

	// Creds resolved from the tenant's integration.
	if fc.gotBase != "https://dd.example.com" || fc.gotTok != "tok123" {
		t.Errorf("client built with base=%q tok=%q, want the integration's", fc.gotBase, fc.gotTok)
	}
	// Result reflects pull + ingest.
	if res.FindingsPulled != 2 || res.FindingsCreated != 2 || res.FindingsUpdated != 1 {
		t.Errorf("result = %+v", res)
	}
	// Tenant isolation: ingest ran under a synthetic agent scoped to the
	// AUTHENTICATED tenant.
	if ing.gotAgent == nil || ing.gotAgent.TenantID == nil || *ing.gotAgent.TenantID != tenantID {
		t.Errorf("ingest agent tenant = %v, want %s", ing.gotAgent, tenantID)
	}
	// Auto-resolve safety: import is partial.
	if ing.gotInput.CoverageType != ingest.CoverageTypePartial {
		t.Errorf("coverage = %q, want partial", ing.gotInput.CoverageType)
	}
	// Went through the CTIS converter (defectdojo tool).
	if ing.gotInput.Report == nil || ing.gotInput.Report.Tool == nil || ing.gotInput.Report.Tool.Name != "defectdojo" {
		t.Errorf("report tool wrong: %+v", ing.gotInput.Report)
	}
	if len(ing.gotInput.Report.Findings) != 2 {
		t.Errorf("ingested %d findings, want 2", len(ing.gotInput.Report.Findings))
	}
}

func TestSyncTenant_NoConnectedIntegration(t *testing.T) {
	tenantID := shared.NewID()
	// present but not connected
	pending := integration.NewIntegration(shared.NewID(), tenantID, "dd",
		integration.CategorySecurity, integration.ProviderDefectDojo, integration.AuthTypeToken)
	repo := &fakeIntegRepo{list: []*integration.Integration{pending}}
	svc := NewSyncService(repo, &fakeIngester{}, nil, logger.NewNop())

	_, err := svc.SyncTenant(context.Background(), tenantID)
	if !errors.Is(err, ErrNoDefectDojoIntegration) {
		t.Fatalf("err = %v, want ErrNoDefectDojoIntegration", err)
	}
}

func TestSyncTenant_JSONCredentials(t *testing.T) {
	tenantID := shared.NewID()
	intg := connectedDD(t, tenantID, "https://dd", `{"api_token":"json-tok"}`)
	repo := &fakeIntegRepo{list: []*integration.Integration{intg}}
	svc := NewSyncService(repo, &fakeIngester{out: &ingest.Output{}}, nil, logger.NewNop())

	var gotTok string
	svc.newClient = func(_, token string) findingsClient {
		gotTok = token
		return &fakeClient{}
	}
	if _, err := svc.SyncTenant(context.Background(), tenantID); err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}
	if gotTok != "json-tok" {
		t.Errorf("token = %q, want json-tok (parsed from JSON creds)", gotTok)
	}
}
