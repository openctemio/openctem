package rekey

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/crypto"
	apikeydom "github.com/openctemio/openctem/api/pkg/domain/apikey"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Token repositories stamp the current pepper id on every hash they write,
// re-hash only while the stored hash is the expected old one, and count the
// active tokens not under the current pepper (migration 000264). This is what
// `rekey -status` reports before APP_ENCRYPTION_KEY_PREVIOUS is removed.
func TestTokenPepper_StampRehashCount(t *testing.T) {
	sqlDB := freshDB(t)
	db := &postgres.DB{DB: sqlDB}
	ctx := context.Background()
	oldID, newID := crypto.PepperID("old-pepper"), crypto.PepperID("new-pepper")

	tenantID := shared.NewID()
	if _, err := sqlDB.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'p', 'pepper')`, tenantID.String()); err != nil {
		t.Fatal(err)
	}

	// A key and a sensor written before the rotation (old pepper) and one
	// legacy row with no pepper id at all.
	keys := postgres.NewAPIKeyRepository(db)
	keys.SetKeyPepperID(oldID)
	k := apikeydom.NewAPIKey(shared.NewID(), tenantID, "k", "hash-old", "oct_old")
	if err := keys.Create(ctx, k); err != nil {
		t.Fatalf("create key: %v", err)
	}
	sensors := postgres.NewSensorRepository(db)
	sensors.SetKeyPepperID(oldID)
	s, _ := sensordom.NewSensor(tenantID, "s", sensordom.SensorTypeWorker, "", nil, nil, sensordom.ExecutionModeStandalone)
	s.SetAPIKey("sensor-hash-old", "rda_old0")
	if err := sensors.Create(ctx, s); err != nil {
		t.Fatalf("create sensor: %v", err)
	}
	if _, err := sqlDB.Exec(`INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, status)
		VALUES ($1, $2, 'legacy', 'hash-legacy', 'oct_leg', 'active')`, shared.NewID().String(), tenantID.String()); err != nil {
		t.Fatal(err)
	}

	ids := postgres.TokenPepperIDs{APIKey: newID, SCIM: newID, Sensor: newID}
	counts, err := postgres.TokensNotUnderPepper(ctx, db, ids)
	if err != nil {
		t.Fatal(err)
	}
	if counts["api_keys"] != 2 || counts["sensors"] != 1 {
		t.Fatalf("before re-hash: %v, want api_keys=2 sensors=1", counts)
	}

	// Server now runs on the new pepper.
	keys.SetKeyPepperID(newID)
	sensors.SetKeyPepperID(newID)
	if changed, err := keys.RehashKey(ctx, k.ID(), "not-the-stored-hash", "hash-new"); err != nil || changed {
		t.Fatalf("re-hash must compare-and-swap on the stored hash: changed=%v err=%v", changed, err)
	}
	if changed, err := keys.RehashKey(ctx, k.ID(), "hash-old", "hash-new"); err != nil || !changed {
		t.Fatalf("re-hash key: changed=%v err=%v", changed, err)
	}
	if changed, err := sensors.RehashKey(ctx, s.ID, "sensor-hash-old", "sensor-hash-new"); err != nil || !changed {
		t.Fatalf("re-hash sensor: changed=%v err=%v", changed, err)
	}
	if got, err := keys.GetByHash(ctx, "hash-new"); err != nil || got.ID() != k.ID() {
		t.Fatalf("re-hashed key must be found by its new hash: %v", err)
	}

	// A key created under the new pepper is stamped with it.
	k2 := apikeydom.NewAPIKey(shared.NewID(), tenantID, "k2", "hash-k2", "oct_k2")
	if err := keys.Create(ctx, k2); err != nil {
		t.Fatal(err)
	}

	counts, err = postgres.TokensNotUnderPepper(ctx, db, ids)
	if err != nil {
		t.Fatal(err)
	}
	if counts["api_keys"] != 1 || counts["sensors"] != 0 || counts["scim_tokens"] != 0 || counts["sensor_api_keys"] != 0 {
		t.Fatalf("after re-hash: %v, want only the legacy, never-used key left (api_keys=1)", counts)
	}
}
