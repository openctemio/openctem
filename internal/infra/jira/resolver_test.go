package jira

import (
	"context"
	"errors"
	"testing"
	"time"

	appjira "github.com/openctemio/api/internal/app/jira"
	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// stubIntegrationRepo implements integration.Repository by embedding the
// interface (so unimplemented methods panic if ever called) and overriding
// only ListByProvider, which is the resolver's single dependency.
type stubIntegrationRepo struct {
	integration.Repository
	byProvider []*integration.Integration
	err        error
}

func (s *stubIntegrationRepo) ListByProvider(_ context.Context, _ integration.ID, _ integration.Provider) ([]*integration.Integration, error) {
	return s.byProvider, s.err
}

func newJiraIntegration(t *testing.T, status integration.Status, baseURL, creds string, config map[string]any) *integration.Integration {
	t.Helper()
	id := shared.NewID()
	tenantID := shared.NewID()
	intg := integration.Reconstruct(
		id, tenantID, "Jira", "", integration.CategoryTicketing, integration.ProviderJira,
		status, "", integration.AuthTypeToken, baseURL, creds,
		nil, nil, 60, "", config, nil, integration.Stats{},
		time.Now(), time.Now(), nil,
	)
	return intg
}

func newResolver(repo integration.Repository) *IntegrationClientResolver {
	// nil encryptor → plaintext passthrough, matching dev behaviour.
	return NewIntegrationClientResolver(repo, nil, logger.NewNop())
}

func TestResolve_NoIntegrations_ReturnsSentinel(t *testing.T) {
	r := newResolver(&stubIntegrationRepo{byProvider: nil})
	_, err := r.Resolve(context.Background(), shared.NewID())
	if !errors.Is(err, appjira.ErrNoTicketingIntegration) {
		t.Fatalf("want ErrNoTicketingIntegration, got %v", err)
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("sentinel must wrap ErrValidation for 4xx mapping, got %v", err)
	}
}

func TestResolve_SkipsNonConnected(t *testing.T) {
	disconnected := newJiraIntegration(t, integration.StatusDisconnected,
		"https://acme.atlassian.net", `{"email":"a@b.com","api_token":"tok"}`, nil)
	r := newResolver(&stubIntegrationRepo{byProvider: []*integration.Integration{disconnected}})
	_, err := r.Resolve(context.Background(), shared.NewID())
	if !errors.Is(err, appjira.ErrNoTicketingIntegration) {
		t.Fatalf("disconnected integration must be skipped, got %v", err)
	}
}

func TestResolve_JSONCredentials(t *testing.T) {
	intg := newJiraIntegration(t, integration.StatusConnected,
		"https://acme.atlassian.net", `{"email":"sec@acme.com","api_token":"abc123"}`, nil)
	r := newResolver(&stubIntegrationRepo{byProvider: []*integration.Integration{intg}})
	client, err := r.Resolve(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestResolve_BareTokenWithConfigEmail(t *testing.T) {
	intg := newJiraIntegration(t, integration.StatusConnected,
		"https://acme.atlassian.net", "rawtoken", map[string]any{"email": "sec@acme.com"})
	r := newResolver(&stubIntegrationRepo{byProvider: []*integration.Integration{intg}})
	if _, err := r.Resolve(context.Background(), shared.NewID()); err != nil {
		t.Fatalf("resolve with bare token + config email: %v", err)
	}
}

func TestResolve_BareTokenMissingEmail_Skipped(t *testing.T) {
	intg := newJiraIntegration(t, integration.StatusConnected,
		"https://acme.atlassian.net", "rawtoken", nil)
	r := newResolver(&stubIntegrationRepo{byProvider: []*integration.Integration{intg}})
	_, err := r.Resolve(context.Background(), shared.NewID())
	if !errors.Is(err, appjira.ErrNoTicketingIntegration) {
		t.Fatalf("missing email integration must be skipped → sentinel, got %v", err)
	}
}

func TestResolveCredentials_LegacyPackedForm(t *testing.T) {
	r := newResolver(&stubIntegrationRepo{})
	intg := newJiraIntegration(t, integration.StatusConnected,
		"https://acme.atlassian.net", "sec@acme.com:tok123", nil)
	email, token, err := r.resolveCredentials(intg)
	if err != nil {
		t.Fatalf("resolveCredentials: %v", err)
	}
	if email != "sec@acme.com" || token != "tok123" {
		t.Fatalf("packed form parse wrong: email=%q token=%q", email, token)
	}
}

func TestBuildClient_RejectsNonHTTPSBaseURL(t *testing.T) {
	r := newResolver(&stubIntegrationRepo{})
	intg := newJiraIntegration(t, integration.StatusConnected,
		"http://acme.atlassian.net", `{"email":"a@b.com","api_token":"t"}`, nil)
	if _, err := r.buildClient(intg); err == nil {
		t.Fatal("expected non-https base URL to be rejected")
	}
}
