package postgres

import (
	"context"
	"testing"

	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A failure's code is stored and read back by every reader of the row (the
// plain repository and the SCM join), and a success clears it.
func TestIntegrationStatusCode_RoundTrip_DB(t *testing.T) {
	ctx := context.Background()
	db := openIntegrationDB(t)
	repo := NewIntegrationRepository(db)
	scmRepo := NewIntegrationSCMExtensionRepository(db, repo)

	tenantID := shared.NewID()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM integrations WHERE tenant_id = $1`, tenantID.String())
	})
	_, _ = db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'status code test', $2) ON CONFLICT DO NOTHING`,
		tenantID.String(), "sc-"+tenantID.String()[:8])

	intg := integrationdom.NewIntegration(shared.NewID(), tenantID, "GitHub status code", integrationdom.CategorySCM,
		integrationdom.ProviderGitHub, integrationdom.AuthTypeToken)
	intg.SetFailure("INTEGRATION_NO_CREDENTIALS", "This connection has no credentials. Add them to use it.")
	if err := repo.Create(ctx, intg); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repo.GetByID(ctx, intg.ID())
	if err != nil || got.StatusCode() != "INTEGRATION_NO_CREDENTIALS" {
		t.Fatalf("after create: code %q err %v", got.StatusCode(), err)
	}

	got.SetFailure("INTEGRATION_AUTH_FAILED", "The service refused the credentials.")
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	withSCM, err := scmRepo.GetIntegrationWithSCM(ctx, intg.ID())
	if err != nil || withSCM.StatusCode() != "INTEGRATION_AUTH_FAILED" {
		t.Fatalf("scm join: code %q err %v", withSCM.StatusCode(), err)
	}

	got.SetConnected()
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	again, _ := repo.GetByID(ctx, intg.ID())
	if again.StatusCode() != "" {
		t.Fatalf("success must clear the code, got %q", again.StatusCode())
	}
}
