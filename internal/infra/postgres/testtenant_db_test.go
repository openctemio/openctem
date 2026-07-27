package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// seedTestTenant creates a throwaway tenant and returns its id.
//
// The DB-backed repository tests used to hardcode a tenant UUID that happened to
// exist in a developer's local database. That worked there and nowhere else: on
// a fresh database every insert failed the tenant_id foreign key. The tests were
// invisible for as long as CI skipped them, so nobody noticed.
//
// The tenant is removed on cleanup; rows the test writes go with it via the
// tenant_id cascades.
func seedTestTenant(ctx context.Context, t *testing.T, db *sql.DB) shared.ID {
	t.Helper()

	id := shared.NewID()
	slug := "test-" + id.String()

	_, err := db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		id.String(), "postgres repo test", slug)
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM tenants WHERE id = $1`, id.String())
	})

	return id
}
