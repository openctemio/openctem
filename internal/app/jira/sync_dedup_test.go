package jira

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// stubCreateClient records CreateIssue calls; only CreateIssue is on the
// SyncService's Client interface.
type stubCreateClient struct {
	calls int32
}

func (c *stubCreateClient) CreateIssue(_ context.Context, _ CreateIssueInput) (*CreateIssueResult, error) {
	atomic.AddInt32(&c.calls, 1)
	return &CreateIssueResult{Key: "PROJ-999", BrowseURL: "https://x.atlassian.net/browse/PROJ-999"}, nil
}

func (c *stubCreateClient) TestConnection(_ context.Context) error { return nil }

// stubFindingRepo implements only the two methods CreateTicketFromFinding uses;
// the rest of the large interface is satisfied by the embedded nil interface.
type stubFindingRepo struct {
	vulnerability.FindingRepository
	finding      *vulnerability.Finding
	updatedURIs  []string
	updateCalled int32
}

func (r *stubFindingRepo) GetByID(_ context.Context, _, _ shared.ID) (*vulnerability.Finding, error) {
	return r.finding, nil
}
func (r *stubFindingRepo) UpdateWorkItemURIs(_ context.Context, _, _ shared.ID, uris []string) error {
	atomic.AddInt32(&r.updateCalled, 1)
	r.updatedURIs = uris
	return nil
}

func buildFinding(t *testing.T, existingTicketURLs ...string) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceSecret, "gitleaks", vulnerability.SeverityHigh, "hardcoded secret")
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	for _, u := range existingTicketURLs {
		f.AddWorkItemURI(u)
	}
	return f
}

func newSync(repo vulnerability.FindingRepository, client Client) *SyncService {
	return NewSyncService(repo, client, logger.NewNop())
}

// No existing ticket → a Jira issue is created and linked.
func TestCreateTicketFromFinding_CreatesWhenAbsent(t *testing.T) {
	client := &stubCreateClient{}
	repo := &stubFindingRepo{finding: buildFinding(t)}
	s := newSync(repo, client)

	info, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{
		TenantID:   shared.NewID().String(),
		FindingID:  shared.NewID().String(),
		ProjectKey: "PROJ",
	})
	if err != nil {
		t.Fatalf("CreateTicketFromFinding: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("expected 1 CreateIssue call, got %d", client.calls)
	}
	if info.TicketKey != "PROJ-999" {
		t.Fatalf("ticket key = %q, want PROJ-999", info.TicketKey)
	}
}

// Finding already ticketed in the SAME project → no duplicate issue created.
func TestCreateTicketFromFinding_IdempotentSameProject(t *testing.T) {
	client := &stubCreateClient{}
	repo := &stubFindingRepo{
		finding: buildFinding(t, "https://x.atlassian.net/browse/PROJ-123"),
	}
	s := newSync(repo, client)

	info, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{
		TenantID:   shared.NewID().String(),
		FindingID:  shared.NewID().String(),
		ProjectKey: "PROJ",
	})
	if err != nil {
		t.Fatalf("CreateTicketFromFinding: %v", err)
	}
	if client.calls != 0 {
		t.Fatalf("expected NO CreateIssue call (already ticketed), got %d", client.calls)
	}
	if info.TicketKey != "PROJ-123" {
		t.Fatalf("expected existing ticket PROJ-123, got %q", info.TicketKey)
	}
	if repo.updateCalled != 0 {
		t.Fatal("must not re-link when ticket already exists")
	}
}

// A ticket in a DIFFERENT project must not block creating one here.
func TestCreateTicketFromFinding_DifferentProjectStillCreates(t *testing.T) {
	client := &stubCreateClient{}
	repo := &stubFindingRepo{
		finding: buildFinding(t, "https://x.atlassian.net/browse/OTHER-1"),
	}
	s := newSync(repo, client)

	if _, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{
		TenantID:   shared.NewID().String(),
		FindingID:  shared.NewID().String(),
		ProjectKey: "PROJ",
	}); err != nil {
		t.Fatalf("CreateTicketFromFinding: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("expected 1 CreateIssue call for a new project, got %d", client.calls)
	}
}

func TestRedactSecrets(t *testing.T) {
	cases := []struct{ in, mustNotContain, mustContain string }{
		{"key AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE", "[REDACTED]"},
		{"token eyJhbGciOi.eyJzdWIiOiJ.SflKxwRJSMeKKF here", "SflKxwRJSMeKKF", "[REDACTED]"},
		{"password: hunter2supersecret", "hunter2supersecret", "password: [REDACTED]"},
		{"api_key=abcdef1234567890xyz", "abcdef1234567890xyz", "api_key=[REDACTED]"},
	}
	for _, c := range cases {
		got := redactSecrets(c.in)
		if strings.Contains(got, c.mustNotContain) {
			t.Fatalf("redactSecrets(%q) still contains %q: %q", c.in, c.mustNotContain, got)
		}
		if !strings.Contains(got, c.mustContain) {
			t.Fatalf("redactSecrets(%q) = %q, want it to contain %q", c.in, got, c.mustContain)
		}
	}
}

func TestTicketDescription_SecretFinding_SuppressesRawSecret(t *testing.T) {
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceSecret, "gitleaks", vulnerability.SeverityHigh, "AWS key in config")
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	const rawSecret = "AKIAIOSFODNN7EXAMPLE"
	f.SetDescription("Leaked credential: " + rawSecret + " found in config.yaml")
	f.SetSecretMaskedValue("AKI****PLE")

	desc := ticketDescription(f)
	if strings.Contains(desc, rawSecret) {
		t.Fatalf("secret-finding ticket leaked the raw secret: %q", desc)
	}
	if !strings.Contains(desc, "AKI****PLE") {
		t.Fatalf("expected masked value in description: %q", desc)
	}
}

func TestTicketDescription_NonSecretFinding_RedactsTokens(t *testing.T) {
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceDAST, "zap", vulnerability.SeverityMedium, "verbose error")
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	f.SetDescription("Response leaked password: topSecretValue123 in body")

	desc := ticketDescription(f)
	if strings.Contains(desc, "topSecretValue123") {
		t.Fatalf("non-secret ticket should still redact obvious secrets: %q", desc)
	}
}
