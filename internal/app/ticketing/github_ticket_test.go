package ticketing

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// --- fakes -----------------------------------------------------------------

type fakeFindingRepo struct {
	vulnerability.FindingRepository // embed: only override what we use
	finding                         *vulnerability.Finding
	updated                         []string
	updateCalls                     int
}

func (f *fakeFindingRepo) GetByID(_ context.Context, _, _ shared.ID) (*vulnerability.Finding, error) {
	if f.finding == nil {
		return nil, shared.ErrNotFound
	}
	return f.finding, nil
}

func (f *fakeFindingRepo) UpdateWorkItemURIs(_ context.Context, _, _ shared.ID, uris []string) error {
	f.updateCalls++
	f.updated = uris
	return nil
}

type fakeIntegrationRepo struct {
	integration.Repository // embed
	list                   []*integration.Integration
}

func (f *fakeIntegrationRepo) ListByProvider(_ context.Context, _ integration.ID, _ integration.Provider) ([]*integration.Integration, error) {
	return f.list, nil
}

type fakeIssueCreator struct {
	calls    int
	gotTitle string
	gotBody  string
	number   int
	url      string
}

func (f *fakeIssueCreator) CreateIssue(_ context.Context, _, _, title, body string, _ []string) (int, string, error) {
	f.calls++
	f.gotTitle = title
	f.gotBody = body
	return f.number, f.url, nil
}

// --- helpers ---------------------------------------------------------------

func connectedGitHubIntegration(t *testing.T, tenantID shared.ID) *integration.Integration {
	t.Helper()
	intg := integration.NewIntegration(
		shared.NewID(), tenantID, "gh", integration.CategorySCM,
		integration.ProviderGitHub, integration.AuthTypeToken,
	)
	intg.SetCredentials("ghp_plaintexttoken1234567890")
	intg.SetConnected()
	return intg
}

func newTestFinding(t *testing.T, src vulnerability.FindingSource) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(
		shared.NewID(), shared.NewID(), src, "gitleaks",
		vulnerability.SeverityHigh, "msg",
	)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	f.SetTitle("Hardcoded credential")
	f.SetDescription("found token AKIAIOSFODNN7EXAMPLE in source")
	return f
}

func newService(t *testing.T, fr *fakeFindingRepo, ir *fakeIntegrationRepo, ic *fakeIssueCreator) *GitHubTicketService {
	t.Helper()
	s := NewGitHubTicketService(fr, ir, nil, logger.NewNop())
	s.clientFactory = func(_, _ string) (issueCreator, error) { return ic, nil }
	return s
}

// --- tests -----------------------------------------------------------------

func TestGitHubTicket_HappyPath(t *testing.T) {
	tenantID := shared.NewID()
	finding := newTestFinding(t, vulnerability.FindingSourceSAST)
	fr := &fakeFindingRepo{finding: finding}
	ir := &fakeIntegrationRepo{list: []*integration.Integration{connectedGitHubIntegration(t, tenantID)}}
	ic := &fakeIssueCreator{number: 7, url: "https://github.com/octo/repo/issues/7"}
	s := newService(t, fr, ir, ic)

	info, err := s.CreateTicketFromFinding(context.Background(), GitHubTicketInput{
		TenantID:  tenantID.String(),
		FindingID: finding.ID().String(),
		Owner:     "octo",
		Repo:      "repo",
	})
	if err != nil {
		t.Fatalf("CreateTicketFromFinding: %v", err)
	}
	if ic.calls != 1 {
		t.Errorf("CreateIssue called %d times, want 1", ic.calls)
	}
	if info.TicketKey != "#7" {
		t.Errorf("TicketKey = %q, want #7", info.TicketKey)
	}
	if info.TicketURL != ic.url {
		t.Errorf("TicketURL = %q, want %q", info.TicketURL, ic.url)
	}
	// the issue url must have been linked back onto the finding
	if len(fr.updated) != 1 || fr.updated[0] != ic.url {
		t.Errorf("work item uris = %v, want [%s]", fr.updated, ic.url)
	}
	// non-secret finding: description (redacted) must be present in the body
	if !strings.Contains(ic.gotBody, "[REDACTED]") {
		t.Errorf("body should redact the AWS key, got: %q", ic.gotBody)
	}
	if strings.Contains(ic.gotBody, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("body leaked the AWS key: %q", ic.gotBody)
	}
}

func TestGitHubTicket_Idempotent(t *testing.T) {
	tenantID := shared.NewID()
	finding := newTestFinding(t, vulnerability.FindingSourceSAST)
	finding.AddWorkItemURI("https://github.com/octo/repo/issues/3")
	fr := &fakeFindingRepo{finding: finding}
	ir := &fakeIntegrationRepo{list: []*integration.Integration{connectedGitHubIntegration(t, tenantID)}}
	ic := &fakeIssueCreator{number: 99, url: "https://github.com/octo/repo/issues/99"}
	s := newService(t, fr, ir, ic)

	info, err := s.CreateTicketFromFinding(context.Background(), GitHubTicketInput{
		TenantID:  tenantID.String(),
		FindingID: finding.ID().String(),
		Owner:     "octo",
		Repo:      "repo",
	})
	if err != nil {
		t.Fatalf("CreateTicketFromFinding: %v", err)
	}
	if ic.calls != 0 {
		t.Errorf("CreateIssue called %d times, want 0 (idempotent)", ic.calls)
	}
	if info.TicketURL != "https://github.com/octo/repo/issues/3" {
		t.Errorf("expected existing url, got %q", info.TicketURL)
	}
	if info.TicketKey != "#3" {
		t.Errorf("expected #3, got %q", info.TicketKey)
	}
	if fr.updateCalls != 0 {
		t.Errorf("idempotent path must not persist, updateCalls=%d", fr.updateCalls)
	}
}

func TestGitHubTicket_NoConnectedIntegration(t *testing.T) {
	tenantID := shared.NewID()
	finding := newTestFinding(t, vulnerability.FindingSourceSAST)
	fr := &fakeFindingRepo{finding: finding}
	// integration exists but is NOT connected
	intg := integration.NewIntegration(shared.NewID(), tenantID, "gh", integration.CategorySCM,
		integration.ProviderGitHub, integration.AuthTypeToken)
	intg.SetCredentials("tok")
	ir := &fakeIntegrationRepo{list: []*integration.Integration{intg}}
	ic := &fakeIssueCreator{}
	s := newService(t, fr, ir, ic)

	_, err := s.CreateTicketFromFinding(context.Background(), GitHubTicketInput{
		TenantID:  tenantID.String(),
		FindingID: finding.ID().String(),
		Owner:     "octo",
		Repo:      "repo",
	})
	if !errors.Is(err, ErrNoGitHubIntegration) {
		t.Fatalf("expected ErrNoGitHubIntegration, got %v", err)
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("ErrNoGitHubIntegration must wrap shared.ErrValidation (maps to 400)")
	}
	if ic.calls != 0 {
		t.Errorf("CreateIssue should not be called, got %d", ic.calls)
	}
}

func TestGitHubTicket_SecretFindingOmitsRawDescription(t *testing.T) {
	tenantID := shared.NewID()
	finding := newTestFinding(t, vulnerability.FindingSourceSecret)
	finding.SetDescription("raw secret value should NEVER appear: AKIAIOSFODNN7EXAMPLE")
	finding.SetSecretMaskedValue("AKIA****EXAMPLE")
	fr := &fakeFindingRepo{finding: finding}
	ir := &fakeIntegrationRepo{list: []*integration.Integration{connectedGitHubIntegration(t, tenantID)}}
	ic := &fakeIssueCreator{number: 1, url: "https://github.com/octo/repo/issues/1"}
	s := newService(t, fr, ir, ic)

	_, err := s.CreateTicketFromFinding(context.Background(), GitHubTicketInput{
		TenantID:  tenantID.String(),
		FindingID: finding.ID().String(),
		Owner:     "octo",
		Repo:      "repo",
	})
	if err != nil {
		t.Fatalf("CreateTicketFromFinding: %v", err)
	}
	if strings.Contains(ic.gotBody, "raw secret value should NEVER appear") {
		t.Errorf("secret finding body must omit raw description, got: %q", ic.gotBody)
	}
	if strings.Contains(ic.gotBody, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("secret finding body leaked the raw secret: %q", ic.gotBody)
	}
	if !strings.Contains(ic.gotBody, "AKIA****EXAMPLE") {
		t.Errorf("secret finding body should include the masked value, got: %q", ic.gotBody)
	}
}

func TestGitHubTicket_ValidationErrors(t *testing.T) {
	s := newService(t, &fakeFindingRepo{}, &fakeIntegrationRepo{}, &fakeIssueCreator{})
	_, err := s.CreateTicketFromFinding(context.Background(), GitHubTicketInput{
		TenantID:  shared.NewID().String(),
		FindingID: shared.NewID().String(),
		Owner:     "",
		Repo:      "repo",
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty owner should be a validation error, got %v", err)
	}
}
