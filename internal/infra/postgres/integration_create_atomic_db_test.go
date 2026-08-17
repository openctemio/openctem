package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"

	appintegration "github.com/openctemio/api/internal/app/integration"
	"github.com/openctemio/api/pkg/crypto"
	integrationdom "github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// CreateIntegration used to insert the integration and its SCM extension as two
// separate statements, compensating with a best-effort s.repo.Delete if the
// extension failed. If that delete also failed, an orphan integration with no
// extension persisted. The create now runs inside one transaction; a failed
// extension insert rolls the integration insert back. This test forces the
// extension insert to fail and asserts no orphan integration remains.

// failingSCMExtRepo wraps the real SCM extension repository but always fails the
// in-transaction insert, simulating a mid-operation extension write error.
type failingSCMExtRepo struct {
	*IntegrationSCMExtensionRepository
}

func (f *failingSCMExtRepo) CreateInTx(_ context.Context, _ *sql.Tx, _ *integrationdom.SCMExtension) error {
	return sql.ErrConnDone // any non-nil error aborts the transaction
}

func openIntegrationDB(t *testing.T) *DB {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping integration create atomicity tests")
	}
	sqlDB, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := sqlDB.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return &DB{DB: sqlDB}
}

func TestIntegrationService_CreateIntegration_RollsBackOnExtensionFailure(t *testing.T) {
	ctx := context.Background()
	db := openIntegrationDB(t)

	tenantID := shared.NewID()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM integrations WHERE tenant_id = $1`, tenantID.String())
	})

	intgRepo := NewIntegrationRepository(db)
	scmRepo := &failingSCMExtRepo{IntegrationSCMExtensionRepository: NewIntegrationSCMExtensionRepository(db, intgRepo)}

	svc := appintegration.NewIntegrationService(intgRepo, scmRepo, crypto.NewNoOpEncryptor(), logger.NewNop())
	svc.SetTransactionDB(db)

	const name = "atomic-scm-integration"
	_, err := svc.CreateIntegration(ctx, appintegration.CreateIntegrationInput{
		TenantID:        tenantID.String(),
		Name:            name,
		Category:        "scm",
		Provider:        "github",
		AuthType:        "token",
		SCMOrganization: "acme",
	})
	if err == nil {
		t.Fatal("expected CreateIntegration to fail when the SCM extension insert fails")
	}

	// The integration insert must have been rolled back — no orphan row.
	var n int
	if qerr := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM integrations WHERE tenant_id = $1 AND name = $2`,
		tenantID.String(), name).Scan(&n); qerr != nil {
		t.Fatalf("count integrations: %v", qerr)
	}
	if n != 0 {
		t.Fatalf("expected 0 integrations after rollback, found %d (orphan persisted)", n)
	}
}
