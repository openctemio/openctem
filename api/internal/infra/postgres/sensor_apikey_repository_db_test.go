package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// TestSensorAPIKeyRepository_RoundTrip exercises the sensor_api_keys repo against
// the real schema: create → get-by-hash → record-usage → revoke, plus the
// overlap invariant that two active keys for one sensor coexist. Skipped unless
// DATABASE_URL is set.
func TestSensorAPIKeyRepository_RoundTrip(t *testing.T) {
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

	// Seed tenant + sensor (sensor_api_keys.sensor_id REFERENCES sensors; deleting
	// the tenant CASCADEs both away).
	tenantID := shared.NewID()
	slug := "aak-" + tenantID.String()[:8]
	if _, err := db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenantID.String(), "sensor-apikey-test", slug); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID.String()) }()

	sensorRepo := NewSensorRepository(&DB{DB: db})
	a, err := sensordom.NewSensor(tenantID, "aak-sensor", sensordom.SensorTypeRunner, "", nil, nil, sensordom.ExecutionModeStandalone)
	if err != nil {
		t.Fatalf("new sensor: %v", err)
	}
	a.SetAPIKey("inline-hash", "rda_inline12")
	if err := sensorRepo.Create(ctx, a); err != nil {
		t.Fatalf("create sensor: %v", err)
	}

	repo := NewSensorAPIKeyRepository(&DB{DB: db})

	// Create key N.
	kN, _ := sensordom.NewAPIKey(a.ID, "keyN", sensordom.RunnerScopes())
	kN.SetKeyHash("hash-N", "rda_N0000000")
	expN := time.Now().Add(1 * time.Hour).Truncate(time.Microsecond)
	kN.SetExpiration(expN)
	if err := repo.Create(ctx, kN); err != nil {
		t.Fatalf("create key N: %v", err)
	}

	got, err := repo.GetByHash(ctx, "hash-N")
	if err != nil {
		t.Fatalf("get by hash N: %v", err)
	}
	if got.SensorID != a.ID || !got.IsValid() {
		t.Fatalf("round-trip mismatch: sensor=%v valid=%v", got.SensorID, got.IsValid())
	}
	if len(got.Scopes) != len(sensordom.RunnerScopes()) {
		t.Errorf("scopes not round-tripped: %v", got.Scopes)
	}

	// RecordUsage bumps count.
	if err := repo.RecordUsage(ctx, kN.ID, "203.0.113.7"); err != nil {
		t.Fatalf("record usage: %v", err)
	}
	if got, _ = repo.GetByHash(ctx, "hash-N"); got.UseCount != 1 {
		t.Errorf("expected use_count 1, got %d", got.UseCount)
	}

	// Overlap: issue key N+1 while N is still active → two active keys coexist.
	kN1, _ := sensordom.NewAPIKey(a.ID, "keyN+1", sensordom.RunnerScopes())
	kN1.SetKeyHash("hash-N1", "rda_N1000000")
	if err := repo.Create(ctx, kN1); err != nil {
		t.Fatalf("create key N+1: %v", err)
	}
	count, err := repo.CountActiveBySensorID(ctx, a.ID)
	if err != nil {
		t.Fatalf("count active: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 active keys during overlap, got %d", count)
	}

	// Revoke N → GetByHash(N) no longer resolves (active-only), N+1 still works.
	if err := repo.Revoke(ctx, kN.ID, "rotated out"); err != nil {
		t.Fatalf("revoke N: %v", err)
	}
	if _, err := repo.GetByHash(ctx, "hash-N"); err == nil {
		t.Error("expected revoked key to no longer resolve via GetByHash")
	}
	if _, err := repo.GetByHash(ctx, "hash-N1"); err != nil {
		t.Errorf("expected N+1 to still resolve, got %v", err)
	}
}

// RetireKeys is the write that makes a renewal retire what it supersedes.
// Against the real schema: only active, non-revoked keys of the sensor older
// than the new key are capped; a newer key (a concurrent renewal) and other
// sensors' keys are not; an expiry is never extended. Skipped unless
// DATABASE_URL is set.
func TestSensorAPIKeyRepository_RetireKeys(t *testing.T) {
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

	tenantID := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenantID.String(), "sensor-retire-test", "srt-"+tenantID.String()[:8]); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID.String()) }()

	sensorRepo := NewSensorRepository(&DB{DB: db})
	newSensor := func(name, hash string) shared.ID {
		s, err := sensordom.NewSensor(tenantID, name, sensordom.SensorTypeRunner, "", nil, nil, sensordom.ExecutionModeStandalone)
		if err != nil {
			t.Fatalf("new sensor: %v", err)
		}
		s.SetAPIKey(hash, "rda_"+name[:4])
		if err := sensorRepo.Create(ctx, s); err != nil {
			t.Fatalf("create sensor: %v", err)
		}
		return s.ID
	}
	sid := newSensor("srt-a", "inline-a")
	other := newSensor("srt-b", "inline-b")

	repo := NewSensorAPIKeyRepository(&DB{DB: db})
	created := time.Now().Add(-time.Hour)
	key := func(sensorID shared.ID, name string, exp *time.Time) *sensordom.APIKey {
		k, _ := sensordom.NewAPIKey(sensorID, name, sensordom.RunnerScopes())
		k.SetKeyHash("hash-"+name, "rda_"+(name + "________")[:8])
		if exp != nil {
			k.SetExpiration(*exp)
		}
		created = created.Add(time.Minute) // strictly increasing created_at
		k.CreatedAt = created
		if err := repo.Create(ctx, k); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return k
	}
	at := time.Now().Add(15 * time.Minute).Truncate(time.Microsecond)
	long := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Microsecond)
	soon := time.Now().Add(5 * time.Minute).Truncate(time.Microsecond)

	never := key(sid, "never", nil)
	longK := key(sid, "long", &long)
	soonK := key(sid, "soon", &soon)
	revoked := key(sid, "revoked", &long)
	if err := repo.Revoke(ctx, revoked.ID, "test"); err != nil {
		t.Fatal(err)
	}
	successor := key(sid, "successor", &long)
	newer := key(sid, "newer", &long) // a concurrent renewal that finished later
	otherK := key(other, "other", &long)

	n, err := repo.RetireKeys(ctx, sid, &successor.ID, at)
	if err != nil {
		t.Fatalf("RetireKeys: %v", err)
	}
	if n != 2 {
		t.Errorf("retired %d keys, want 2 (never, long)", n)
	}
	expiry := func(id shared.ID) *time.Time {
		k, err := repo.GetByID(ctx, id)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		return k.ExpiresAt
	}
	for _, c := range []struct {
		name string
		id   shared.ID
		want *time.Time
	}{
		{"never-expiring older key", never.ID, &at},
		{"long-lived older key", longK.ID, &at},
		{"older key already expiring sooner (not extended)", soonK.ID, &soon},
		{"revoked key (untouched)", revoked.ID, &long},
		{"the successor itself", successor.ID, &long},
		{"a newer key (concurrent renewal)", newer.ID, &long},
		{"another sensor's key", otherK.ID, &long},
	} {
		got := expiry(c.id)
		if got == nil || !got.Equal(*c.want) {
			t.Errorf("%s: expires_at = %v, want %v", c.name, got, *c.want)
		}
	}

	// The newer renewal's own RetireKeys caps the earlier successor: of two
	// concurrent renewals exactly one key stays long-lived.
	if _, err := repo.RetireKeys(ctx, sid, &newer.ID, at); err != nil {
		t.Fatal(err)
	}
	if got := expiry(successor.ID); got == nil || !got.Equal(at) {
		t.Errorf("older successor: expires_at = %v, want %v", got, at)
	}
	if got := expiry(newer.ID); got == nil || !got.Equal(long) {
		t.Errorf("newest successor: expires_at = %v, want %v", got, long)
	}

	// Without a successor (the inline key was replaced) every active key of
	// the sensor is capped; other sensors are not.
	if _, err := repo.RetireKeys(ctx, sid, nil, at); err != nil {
		t.Fatal(err)
	}
	if got := expiry(newer.ID); got == nil || !got.Equal(at) {
		t.Errorf("newest key without successor: expires_at = %v, want %v", got, at)
	}
	if got := expiry(otherK.ID); got == nil || !got.Equal(long) {
		t.Errorf("another sensor's key changed: %v", got)
	}
}
