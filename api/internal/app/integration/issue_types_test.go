package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// oneIntegrationRepo holds one integration of one tenant.
type oneIntegrationRepo struct {
	integrationdom.Repository
	intg    *integrationdom.Integration
	updated int
}

func (r *oneIntegrationRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*integrationdom.Integration, error) {
	if !tenantID.Equals(r.intg.TenantID()) || !id.Equals(r.intg.ID()) {
		return nil, integrationdom.ErrIntegrationNotFound
	}
	return r.intg, nil
}

func (r *oneIntegrationRepo) Update(context.Context, *integrationdom.Integration) error {
	r.updated++
	return nil
}

type checkerStub struct {
	err   error
	calls int
}

func (c *checkerStub) CheckTicketingIssueTypes(context.Context, *integrationdom.Integration) error {
	c.calls++
	return c.err
}

func jiraWithTicketing(ticketing map[string]any, metadata map[string]any) *integrationdom.Integration {
	return integrationdom.Reconstruct(
		shared.NewID(), shared.NewID(), "Jira", "", integrationdom.CategoryTicketing, integrationdom.ProviderJira,
		integrationdom.StatusConnected, "", integrationdom.AuthTypeToken, "https://acme.atlassian.net", "creds",
		nil, nil, 60, "", map[string]any{"ticketing": ticketing}, metadata, integrationdom.Stats{},
		time.Now(), time.Now(), nil,
	)
}

func TestUpdateIntegration_IssueTypesAreCheckedBeforeSave(t *testing.T) {
	ctx := context.Background()
	chosen := map[string]any{"project_key": "SEC", "issue_types": map[string]any{"task": map[string]any{"id": "10043", "name": "Remediation Task"}}}

	// A refused choice is not saved.
	intg := jiraWithTicketing(map[string]any{"project_key": "SEC"}, nil)
	repo := &oneIntegrationRepo{intg: intg}
	svc := NewIntegrationService(repo, nil, nil, logger.NewNop())
	checker := &checkerStub{err: shared.NewDomainError("VALIDATION", "Team is required", shared.ErrValidation)}
	svc.SetTicketingIssueTypeChecker(checker)
	_, err := svc.UpdateIntegration(ctx, intg.ID().String(), intg.TenantID().String(), UpdateIntegrationInput{Config: map[string]any{"ticketing": chosen}})
	if !errors.Is(err, shared.ErrValidation) || repo.updated != 0 || checker.calls != 1 {
		t.Fatalf("refused choice: err=%v updates=%d calls=%d", err, repo.updated, checker.calls)
	}

	// A passing check saves and clears the recorded create refusals.
	intg = jiraWithTicketing(map[string]any{"project_key": "SEC"}, map[string]any{
		"ticketing_health": map[string]any{"task": map[string]any{"fields": []any{"issuetype"}}}, "email": "bot@example.com"})
	repo = &oneIntegrationRepo{intg: intg}
	svc = NewIntegrationService(repo, nil, nil, logger.NewNop())
	checker = &checkerStub{}
	svc.SetTicketingIssueTypeChecker(checker)
	if _, err := svc.UpdateIntegration(ctx, intg.ID().String(), intg.TenantID().String(), UpdateIntegrationInput{Config: map[string]any{"ticketing": chosen}}); err != nil {
		t.Fatal(err)
	}
	if repo.updated != 1 || checker.calls != 1 {
		t.Fatalf("updates=%d calls=%d", repo.updated, checker.calls)
	}
	if _, ok := intg.Metadata()["ticketing_health"]; ok || intg.Metadata()["email"] != "bot@example.com" {
		t.Fatalf("metadata %v: the health is cleared, the rest kept", intg.Metadata())
	}

	// A change that does not touch the project or the types: no Jira call.
	if _, err := svc.UpdateIntegration(ctx, intg.ID().String(), intg.TenantID().String(), UpdateIntegrationInput{Config: map[string]any{
		"ticketing": map[string]any{"project_key": "SEC", "issue_types": chosen["issue_types"], "default_priority": "P2"}}}); err != nil {
		t.Fatal(err)
	}
	if checker.calls != 1 {
		t.Fatalf("checked %d times for a priority change", checker.calls)
	}
}

func TestUpdateIntegration_IssueTypesOfAnotherTenantAreNotFound(t *testing.T) {
	intg := jiraWithTicketing(map[string]any{"project_key": "SEC"}, nil)
	repo := &oneIntegrationRepo{intg: intg}
	svc := NewIntegrationService(repo, nil, nil, logger.NewNop())
	checker := &checkerStub{}
	svc.SetTicketingIssueTypeChecker(checker)
	_, err := svc.UpdateIntegration(context.Background(), intg.ID().String(), shared.NewID().String(), UpdateIntegrationInput{Config: map[string]any{
		"ticketing": map[string]any{"project_key": "SEC", "issue_types": map[string]any{"task": map[string]any{"id": "10043"}}}}})
	if !errors.Is(err, shared.ErrNotFound) || checker.calls != 0 || repo.updated != 0 {
		t.Fatalf("cross-tenant: err=%v calls=%d updates=%d", err, checker.calls, repo.updated)
	}
}
