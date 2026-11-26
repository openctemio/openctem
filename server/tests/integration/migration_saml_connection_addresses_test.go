package integration

// Migration saml_connection_addresses and the repository on top of it: every
// SAML configuration that existed keeps its address under a frozen legacy key
// (the slug at migration time); a later rename does not move it and the
// organization that takes the old slug cannot reach it; new configurations
// are found by connection id only; a reserved connection id is stable and
// retired with the configuration. Down removes the column and table; up
// again backfills the same keys.
//
// Runs on a private database: everything up to the migration before, seed,
// up, down, up.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/samlprovider"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

func TestMigrationSAMLConnectionAddresses(t *testing.T) {
	const dir = "../../migrations"
	v := testdb.MigrationVersion(t, dir, "saml_connection_addresses")
	db := testdb.PrivateDatabase(t, "migsaml", dir)
	testdb.Migrate(t, db, dir, v, v, true)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const (
		tenantOld   = "a1111111-1111-4111-8111-111111111111" // had SAML before the migration
		tenantTaker = "b2222222-2222-4222-8222-222222222222" // takes the old slug later
		tenantNew   = "c3333333-3333-4333-8333-333333333333" // configures SAML later
		cfgOld      = "e1111111-1111-4111-8111-111111111111"
		cfgTaker    = "e2222222-2222-4222-8222-222222222222"
	)
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Old', 'mig-saml-old'), ($2, 'Taker', 'mig-saml-taker'), ($3, 'New', 'mig-saml-new')`,
		tenantOld, tenantTaker, tenantNew)
	exec(`INSERT INTO saml_providers (id, tenant_id, idp_entity_id, idp_sso_url, idp_certificate, enabled)
		VALUES ($1, $2, 'https://idp.example.com/old', 'https://idp.example.com/sso', 'pem', true)`, cfgOld, tenantOld)

	repo := postgres.NewSAMLProviderRepository(&postgres.DB{DB: db})
	check := func(round string) {
		t.Helper()
		p, err := repo.GetByLegacyPathKey(ctx, "mig-saml-old")
		if err != nil || p.ID().String() != cfgOld || p.PathKey() != "mig-saml-old" {
			t.Fatalf("%s: legacy key: %v %v", round, p, err)
		}
	}

	testdb.Migrate(t, db, dir, v, v, false)
	check("up")

	// The organization renames itself and another one takes the old slug
	// and configures its own SAML: the legacy address still names the first
	// organization's connection, and the new one is found by id only.
	exec(`UPDATE tenants SET slug = 'mig-saml-renamed' WHERE id = $1`, tenantOld)
	exec(`UPDATE tenants SET slug = 'mig-saml-old' WHERE id = $1`, tenantTaker)
	exec(`INSERT INTO saml_providers (id, tenant_id, idp_entity_id, idp_sso_url, idp_certificate, enabled)
		VALUES ($1, $2, 'https://idp.example.com/taker', 'https://idp.example.com/sso', 'pem', true)`, cfgTaker, tenantTaker)
	p, err := repo.GetByLegacyPathKey(ctx, "mig-saml-old")
	if err != nil || p.TenantID().String() != tenantOld {
		t.Fatalf("old slug after takeover resolves to %v (%v), want the original organization", p, err)
	}
	taker, err := repo.GetByIDUnscoped(ctx, shared.MustIDFromString(cfgTaker))
	if err != nil || taker.LegacyPathKey() != "" || taker.PathKey() != cfgTaker {
		t.Fatalf("new configuration: %v %v", taker, err)
	}
	if _, err := repo.GetByLegacyPathKey(ctx, "mig-saml-renamed"); !errors.Is(err, samlprovider.ErrNotFound) {
		t.Errorf("the current slug became an address: %v", err)
	}

	// A reserved id is stable until the configuration is deleted.
	newTenant := shared.MustIDFromString(tenantNew)
	if _, err := repo.GetReservedConnectionID(ctx, newTenant); !errors.Is(err, samlprovider.ErrNotFound) {
		t.Fatalf("a read found a reservation that was never made: %v", err)
	}
	r1, err := repo.ReserveConnectionID(ctx, newTenant)
	if err != nil {
		t.Fatal(err)
	}
	if r2, err := repo.ReserveConnectionID(ctx, newTenant); err != nil || r2 != r1 {
		t.Fatalf("reservation not stable: %s then %s (%v)", r1, r2, err)
	}
	if got, err := repo.GetReservedConnectionID(ctx, newTenant); err != nil || got != r1 {
		t.Fatalf("read of the reservation: %s (%v), want %s", got, err, r1)
	}
	if err := repo.Delete(ctx, newTenant); err != nil {
		t.Fatal(err)
	}
	if r3, err := repo.ReserveConnectionID(ctx, newTenant); err != nil || r3 == r1 {
		t.Fatalf("a retired id was reserved again: %s (%v)", r3, err)
	}

	testdb.Migrate(t, db, dir, v, v, true)
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_name = 'saml_providers' AND column_name = 'legacy_path_key'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("down left the column: %d %v", n, err)
	}
	// Up again: the taker now holds the slug, so a re-run backfills each
	// configuration from the organization's slug at that moment.
	testdb.Migrate(t, db, dir, v, v, false)
	if p, err := repo.GetByLegacyPathKey(ctx, "mig-saml-renamed"); err != nil || p.ID().String() != cfgOld {
		t.Fatalf("up again: %v %v", p, err)
	}
}
