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

	a, err := sensor.NewSensor(tenantID, "expiry-sensor", sensor.SensorTypeWorker, "", nil, sensor.ExecutionModeStandalone)
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
	if got.InlineKeyExpiresAt == nil {
		t.Fatal("expected KeyExpiresAt to round-trip, got nil")
	}
	if !got.InlineKeyExpiresAt.Equal(exp) {
		t.Errorf("KeyExpiresAt mismatch: got %v, want %v", got.InlineKeyExpiresAt.UTC(), exp.UTC())
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
	if got2.InlineKeyExpiresAt == nil || !got2.InlineKeyExpiresAt.Equal(newExp) {
		t.Errorf("updated KeyExpiresAt mismatch: got %v, want %v", got2.InlineKeyExpiresAt, newExp.UTC())
	}

	// A never-expiring key (nil) must also round-trip as nil.
	if ok, err := repo.UpdateAPIKey(ctx, got2.ID, "hash-keyexp-3", "rda_keyexp3", nil, false); err != nil || !ok {
		t.Fatalf("update api key (nil expiry): ok=%v err=%v", ok, err)
	}
	got3, err := repo.GetByAPIKeyHash(ctx, "hash-keyexp-3")
	if err != nil {
		t.Fatalf("get by nil-expiry hash: %v", err)
	}
	if got3.InlineKeyExpiresAt != nil {
		t.Errorf("expected nil KeyExpiresAt after SetAPIKey, got %v", got3.InlineKeyExpiresAt)
	}

	expiry := func() *time.Time {
		t.Helper()
		got, err := repo.GetByID(ctx, a.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		return got.InlineKeyExpiresAt
	}

	// RetireInlineKey is guarded by the presented key's hashes: a key
	// regenerated since authentication (another hash) is left alone; any one
	// of the hashes matching (the key was re-hashed onto a new pepper) is
	// enough.
	grace := time.Now().Add(30 * time.Minute).Truncate(time.Microsecond)
	if ok, err := repo.RetireInlineKey(ctx, a.ID, []string{"hash-keyexp-2", "hash-keyexp-1"}, grace); err != nil || ok {
		t.Fatalf("RetireInlineKey (stale hash): ok=%v err=%v, want a no-op", ok, err)
	}
	if e := expiry(); e != nil {
		t.Errorf("stale-hash retirement changed the expiry to %v", e)
	}

	// The current hash with no expiry: the expiry is set.
	if ok, err := repo.RetireInlineKey(ctx, a.ID, []string{"hash-keyexp-x", "hash-keyexp-3"}, grace); err != nil || !ok {
		t.Fatalf("RetireInlineKey (current): ok=%v err=%v", ok, err)
	}
	if e := expiry(); e == nil || !e.Equal(grace) {
		t.Errorf("expected expiry %v, got %v", grace, e)
	}

	// Never extended: a later moment is a no-op.
	later := grace.Add(time.Hour)
	if ok, err := repo.RetireInlineKey(ctx, a.ID, []string{"hash-keyexp-3"}, later); err != nil || ok {
		t.Fatalf("RetireInlineKey (later): ok=%v err=%v, want a no-op", ok, err)
	}
	if e := expiry(); e == nil || !e.Equal(grace) {
		t.Errorf("retirement extended the expiry: %v, want %v", e, grace)
	}

	// Brought forward: an earlier moment applies, and it touches nothing but
	// the expiry — a revoked sensor stays revoked.
	if _, err := db.ExecContext(ctx, `UPDATE sensors SET status = 'revoked' WHERE id = $1`, a.ID.String()); err != nil {
		t.Fatalf("revoke sensor: %v", err)
	}
	earlier := grace.Add(-10 * time.Minute)
	if ok, err := repo.RetireInlineKey(ctx, a.ID, []string{"hash-keyexp-3"}, earlier); err != nil || !ok {
		t.Fatalf("RetireInlineKey (earlier): ok=%v err=%v", ok, err)
	}
	got4, err := repo.GetByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got4.InlineKeyExpiresAt == nil || !got4.InlineKeyExpiresAt.Equal(earlier) {
		t.Errorf("expected expiry brought forward to %v, got %v", earlier, got4.InlineKeyExpiresAt)
	}
	if got4.Status != sensor.SensorStatusRevoked {
		t.Errorf("retirement changed the status to %q", got4.Status)
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
	a, err := sensor.NewSensor(tenantID, "suk-sensor", sensor.SensorTypeWorker, "", nil, sensor.ExecutionModeStandalone)
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
