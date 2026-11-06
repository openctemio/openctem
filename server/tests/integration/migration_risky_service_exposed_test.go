package integration

// Migration risky_service_exposed: the exposure type is admitted after up,
// refused after down (down removes the type's exposures first), and every
// type the domain knows stays admitted.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/exposure"
)

func TestMigrationRiskyServiceExposed(t *testing.T) {
	const dir = "../../migrations"
	ctx := context.Background()
	db := testdb.PrivateDatabase(t, "migriskysvc", dir)
	v := testdb.MigrationVersion(t, dir, "risky_service_exposed")
	const tenant = "a1111111-1111-4111-8111-1111111114a1"
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, 'a', 'mig-risky-a')`, tenant); err != nil {
		t.Fatal(err)
	}
	insert := func(fp string, typ exposure.EventType) error {
		_, err := db.ExecContext(ctx, `INSERT INTO exposure_events (tenant_id, event_type, title, fingerprint, source, severity, state)
			VALUES ($1, $2, 't', $3, 'recon_scan', 'high', 'active')`, tenant, string(typ), fp)
		return err
	}
	for i, typ := range exposure.AllEventTypes() {
		if err := insert("fp-all-"+string(rune('a'+i)), typ); err != nil {
			t.Errorf("%s refused: %v", typ, err)
		}
	}
	testdb.Migrate(t, db, dir, v, v, true)
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM exposure_events WHERE event_type = 'risky_service_exposed'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("down kept %d risky exposures (%v)", n, err)
	}
	if err := insert("fp-after-down", exposure.EventTypeRiskyServiceExposed); err == nil {
		t.Fatal("down still admits risky_service_exposed")
	}
	testdb.Migrate(t, db, dir, v, v, false)
	if err := insert("fp-after-up", exposure.EventTypeRiskyServiceExposed); err != nil {
		t.Fatalf("up refuses risky_service_exposed: %v", err)
	}
}
