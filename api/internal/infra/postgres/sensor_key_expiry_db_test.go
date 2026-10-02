package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TestSensorKeyExpiry_RoundTrip exercises the new key_expires_at column against
// the real sensors schema: Create persists it, GetByAPIKeyHash (the auth read
// path, scanSensor) reads it back, and Update rewrites it. A missing scan target
// or a placeholder-numbering slip in either scanner would surface here rather
// than in the auth path at runtime. Skipped unless DATABASE_URL is set.
func TestSensorKeyExpiry_RoundTrip(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping schema-level check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	// Seed a tenant (sensors.tenant_id is NOT NULL REFERENCES tenants). Deleting
	// it CASCADE-removes the sensor, so the test leaves no residue.
	tenantID := shared.NewID()
	slug := "keyexp-" + tenantID.String()[:8]
	if _, err := db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenantID.String(), "key-expiry-test", slug); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	defer func() {
		_, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID.String())
	}()

	repo := NewSensorRepository(&DB{DB: db})

	a, err := sensor.NewSensor(tenantID, "expiry-sensor", sensor.SensorTypeRunner, "", nil, nil, sensor.ExecutionModeStandalone)
	if err != nil {
		t.Fatalf("new sensor: %v", err)
	}
	// Truncate to microseconds — Postgres TIMESTAMPTZ resolution — so the
	// equality assertions below aren't defeated by sub-microsecond drift.
	exp := time.Now().Add(24 * time.Hour).Truncate(time.Microsecond)
	a.SetAPIKeyWithExpiry("hash-keyexp-1", "rda_keyexp1", &exp)

	if err := repo.Create(ctx, a); err != nil {
		t.Fatalf("create sensor: %v", err)
	}

	got, err := repo.GetByAPIKeyHash(ctx, "hash-keyexp-1")
	if err != nil {
		t.Fatalf("get by hash: %v", err)
	}
	if got.KeyExpiresAt == nil {
		t.Fatal("expected KeyExpiresAt to round-trip, got nil")
	}
	if !got.KeyExpiresAt.Equal(exp) {
		t.Errorf("KeyExpiresAt mismatch: got %v, want %v", got.KeyExpiresAt.UTC(), exp.UTC())
	}

	// Change the key with a new expiry (key columns change only through
	// UpdateAPIKey; Update never writes them) and confirm it persists.
	newExp := time.Now().Add(48 * time.Hour).Truncate(time.Microsecond)
	if ok, err := repo.UpdateAPIKey(ctx, got.ID, "hash-keyexp-2", "rda_keyexp2", &newExp, false); err != nil || !ok {
		t.Fatalf("update api key: ok=%v err=%v", ok, err)
	}
	got2, err := repo.GetByAPIKeyHash(ctx, "hash-keyexp-2")
	if err != nil {
		t.Fatalf("get by new hash: %v", err)
	}
	if got2.KeyExpiresAt == nil || !got2.KeyExpiresAt.Equal(newExp) {
		t.Errorf("updated KeyExpiresAt mismatch: got %v, want %v", got2.KeyExpiresAt, newExp.UTC())
	}

	// A never-expiring key (nil) must also round-trip as nil.
	if ok, err := repo.UpdateAPIKey(ctx, got2.ID, "hash-keyexp-3", "rda_keyexp3", nil, false); err != nil || !ok {
		t.Fatalf("update api key (nil expiry): ok=%v err=%v", ok, err)
	}
	got3, err := repo.GetByAPIKeyHash(ctx, "hash-keyexp-3")
	if err != nil {
		t.Fatalf("get by nil-expiry hash: %v", err)
	}
	if got3.KeyExpiresAt != nil {
		t.Errorf("expected nil KeyExpiresAt after SetAPIKey, got %v", got3.KeyExpiresAt)
	}

	// UpdateKeyExpiry on an ACTIVE sensor sets the column.
	guardExp := time.Now().Add(30 * time.Minute).Truncate(time.Microsecond)
	if err := repo.UpdateKeyExpiry(ctx, a.ID, &guardExp); err != nil {
		t.Fatalf("UpdateKeyExpiry (active): %v", err)
	}
	if got, _ := repo.GetByID(ctx, a.ID); got.KeyExpiresAt == nil || !got.KeyExpiresAt.Equal(guardExp) {
		t.Errorf("expected UpdateKeyExpiry to set expiry on active sensor, got %v", got.KeyExpiresAt)
	}

	// Status guard: once the sensor is revoked, UpdateKeyExpiry is a no-op — it
	// must never rewrite a revoked sensor's key (DEFECT 2 fix).
	if _, err := db.ExecContext(ctx, `UPDATE sensors SET status = 'revoked' WHERE id = $1`, a.ID.String()); err != nil {
		t.Fatalf("revoke sensor: %v", err)
	}
	future := time.Now().Add(99 * time.Hour).Truncate(time.Microsecond)
	if err := repo.UpdateKeyExpiry(ctx, a.ID, &future); err != nil {
		t.Fatalf("UpdateKeyExpiry (revoked): %v", err)
	}
	if got, _ := repo.GetByID(ctx, a.ID); got.KeyExpiresAt == nil || got.KeyExpiresAt.Equal(future) {
		t.Errorf("status guard failed: revoked sensor's key_expires_at was rewritten to %v", got.KeyExpiresAt)
	}
}

// An admin request that read the sensor before a key change (rename, activate,
// disable, revoke) must not write the old key columns back when it saves: the
// regenerated key and the expiry that retires a superseded key stay as they
// are. Skipped unless DATABASE_URL is set.
func TestSensorUpdate_DoesNotRevertKeyColumns(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	tenantID := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenantID.String(), "sensor-update-keys", "suk-"+tenantID.String()[:8]); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID.String()) }()

	repo := NewSensorRepository(&DB{DB: db})
	a, err := sensor.NewSensor(tenantID, "suk-sensor", sensor.SensorTypeRunner, "", nil, nil, sensor.ExecutionModeStandalone)
	if err != nil {
		t.Fatalf("new sensor: %v", err)
	}
	a.SetAPIKey("old-hash", "rda_old0001")
	if err := repo.Create(ctx, a); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Request 1 reads the sensor (old key, no expiry).
	stale, err := repo.GetByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	// Meanwhile the key is regenerated with an expiry.
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if ok, err := repo.UpdateAPIKey(ctx, a.ID, "new-hash", "rda_new0001", &exp, false); err != nil || !ok {
		t.Fatalf("UpdateAPIKey: ok=%v err=%v", ok, err)
	}

	// Request 1 now saves its rename from the stale copy.
	stale.Name = "suk-renamed"
	if err := repo.Update(ctx, stale); err != nil {
		t.Fatalf("update: %v", err)
	}

	var hash, prefix, name string
	var expires sql.NullTime
	if err := db.QueryRowContext(ctx,
		`SELECT api_key_hash, api_key_prefix, key_expires_at, name FROM sensors WHERE id = $1`, a.ID.String(),
	).Scan(&hash, &prefix, &expires, &name); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if name != "suk-renamed" {
		t.Errorf("name = %q, want the rename applied", name)
	}
	if hash != "new-hash" || prefix != "rda_new0001" {
		t.Errorf("key reverted by a stale Update: hash=%q prefix=%q", hash, prefix)
	}
	if !expires.Valid || !expires.Time.Equal(exp) {
		t.Errorf("key expiry reverted by a stale Update: %v", expires)
	}
}
