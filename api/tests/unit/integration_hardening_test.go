package unit

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
	integrationapp "github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A token issued for one host must not follow base_url to another host that
// someone with integrations:manage chose (23b G-M7).
func TestUpdateIntegration_NewHostNeedsNewCredentials(t *testing.T) {
	repo := newMockIntegrationRepo()
	svc := newTestIntegrationService(repo, newMockSCMExtRepo(), newMockEncryptor())
	tenantID := shared.NewID().String()
	created, err := svc.CreateIntegration(context.Background(), validCreateInput(tenantID))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id := created.ID().String()

	attacker := "https://collector.attacker.example"
	_, err = svc.UpdateIntegration(context.Background(), id, tenantID, app.UpdateIntegrationInput{BaseURL: &attacker})
	if !errors.Is(err, integrationapp.ErrCredentialsRequiredForNewHost) || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("host change without credentials: err = %v, want ErrCredentialsRequiredForNewHost", err)
	}
	stored, _ := repo.GetByID(context.Background(), created.ID())
	if stored.BaseURL() != "https://defectdojo.example.com" {
		t.Fatalf("base_url changed despite the refusal: %s", stored.BaseURL())
	}

	// Same host, other path: fine without credentials.
	samePath := "https://defectdojo.example.com/api/v2"
	if _, err := svc.UpdateIntegration(context.Background(), id, tenantID, app.UpdateIntegrationInput{BaseURL: &samePath}); err != nil {
		t.Fatalf("same-host change: %v", err)
	}
	// New host with new credentials: fine.
	newHost, creds := "https://dd.other.example", "new-key"
	if _, err := svc.UpdateIntegration(context.Background(), id, tenantID, app.UpdateIntegrationInput{BaseURL: &newHost, Credentials: &creds}); err != nil {
		t.Fatalf("host change with credentials: %v", err)
	}
}

// A disabled integration stays disabled: a test or a sync result never flips
// it back (23b G-H2); only Enable does.
func TestIntegration_DisabledStaysDisabled(t *testing.T) {
	i := integration.NewIntegration(shared.NewID(), shared.NewID(), "GitHub", integration.CategorySCM, integration.ProviderGitHub, integration.AuthTypeToken)
	i.SetStatus(integration.StatusDisabled)
	i.SetConnected()
	if i.Status() != integration.StatusDisabled {
		t.Fatalf("SetConnected re-enabled a disabled integration: %s", i.Status())
	}
	i.SetError("boom")
	if i.Status() != integration.StatusDisabled || i.StatusMessage() != "boom" {
		t.Fatalf("SetError: status %s message %q", i.Status(), i.StatusMessage())
	}
	i.SetStatus(integration.StatusPending)
	i.SetConnected()
	if i.Status() != integration.StatusConnected {
		t.Fatalf("enabled integration not connected: %s", i.Status())
	}
}

// A viewer listing repositories of a disabled integration neither calls the
// provider with its token nor re-enables it.
func TestListSCMRepositories_DisabledIsRefused(t *testing.T) {
	repo := newMockIntegrationRepo()
	svc := newTestIntegrationService(repo, newMockSCMExtRepo(), newMockEncryptor())
	tenantID := shared.NewID()
	i := integration.NewIntegration(shared.NewID(), tenantID, "GitHub", integration.CategorySCM, integration.ProviderGitHub, integration.AuthTypeToken)
	i.SetStatus(integration.StatusDisabled)
	repo.integrations[i.ID()] = i

	_, err := svc.ListSCMRepositories(context.Background(), app.IntegrationListReposInput{
		IntegrationID: i.ID().String(), TenantID: tenantID.String(), Page: 1, PerPage: 30,
	})
	if !errors.Is(err, integrationapp.ErrIntegrationDisabled) {
		t.Fatalf("list on disabled: err = %v, want ErrIntegrationDisabled", err)
	}
	if i.Status() != integration.StatusDisabled {
		t.Fatalf("status changed by a read: %s", i.Status())
	}
}
