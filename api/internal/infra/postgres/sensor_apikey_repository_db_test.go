package postgres

import (
	"context"
	"database/sql"
	"errors"
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
	slug := "aak-" + tenantID.String()[28:]
	if _, err := db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenantID.String(), "sensor-apikey-test", slug); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID.String()) }()

	sensorRepo := NewSensorRepository(&DB{DB: db})
	a, err := sensordom.NewSensor(tenantID, "aak-sensor", sensordom.SensorTypeWorker, "", nil, sensordom.ExecutionModeStandalone)
	if err != nil {
		t.Fatalf("new sensor: %v", err)
	}
	a.SetAPIKey("inline-hash", "rda_inline12")
	if err := sensorRepo.Create(ctx, a); err != nil {
		t.Fatalf("create sensor: %v", err)
	}

	repo := NewSensorAPIKeyRepository(&DB{DB: db})

	// Create key N.
	kN, _ := sensordom.NewAPIKey(a.ID, "keyN", sensordom.WorkerScopes())
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
	if len(got.Scopes) != len(sensordom.WorkerScopes()) {
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
	kN1, _ := sensordom.NewAPIKey(a.ID, "keyN+1", sensordom.WorkerScopes())
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

// RotateKey and ReplaceInlineKey are the writes that make a renewal retire
// what it supersedes. Against the real schema: every other active,
// non-revoked key of the sensor is capped; the new key and other sensors'
// keys are not; an expiry is never extended; the inline key is retired only
// while its hash matches. Skipped unless DATABASE_URL is set.
func TestSensorAPIKeyRepository_RotateKey(t *testing.T) {
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
		tenantID.String(), "sensor-retire-test", "srt-"+tenantID.String()[28:]); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID.String()) }()

	sensorRepo := NewSensorRepository(&DB{DB: db})
	newSensor := func(name, hash string) shared.ID {
		s, err := sensordom.NewSensor(tenantID, name, sensordom.SensorTypeWorker, "", nil, sensordom.ExecutionModeStandalone)
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
	newKey := func(sensorID shared.ID, name string, exp *time.Time) *sensordom.APIKey {
		k, _ := sensordom.NewAPIKey(sensorID, name, sensordom.WorkerScopes())
		k.SetKeyHash("hash-"+name, "rda_"+(name + "________")[:8])
		if exp != nil {
			k.SetExpiration(*exp)
		}
		return k
	}
	key := func(sensorID shared.ID, name string, exp *time.Time) *sensordom.APIKey {
		k := newKey(sensorID, name, exp)
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
	otherK := key(other, "other", &long)
	viaLong := sensordom.PresentedKey{KeyID: &longK.ID, At: time.Now()}
	viaInline := func(hash string) sensordom.PresentedKey {
		return sensordom.PresentedKey{InlineKeyHashes: []string{hash}, At: time.Now()}
	}

	// A successor whose created_at is EARLIER than the keys it supersedes
	// (its clock read happened before theirs) still retires all of them.
	successor := newKey(sid, "successor", &long)
	successor.CreatedAt = time.Now().Add(-time.Hour)
	if err := repo.RotateKey(ctx, successor, viaLong, []string{"stale-hash", "inline-a"}, at); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	expiry := func(id shared.ID) *time.Time {
		k, err := repo.GetByID(ctx, id)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		return k.ExpiresAt
	}
	inlineExpiry := func(id shared.ID) *time.Time {
		var exp sql.NullTime
		if err := db.QueryRowContext(ctx, `SELECT key_expires_at FROM sensors WHERE id = $1`, id.String()).Scan(&exp); err != nil {
			t.Fatal(err)
		}
		return nullTimeValue(exp)
	}
	for _, c := range []struct {
		name string
		id   shared.ID
		want *time.Time
	}{
		{"never-expiring key", never.ID, &at},
		{"long-lived key", longK.ID, &at},
		{"key already expiring sooner (not extended)", soonK.ID, &soon},
		{"revoked key (untouched)", revoked.ID, &long},
		{"the successor itself", successor.ID, &long},
		{"another sensor's key", otherK.ID, &long},
	} {
		got := expiry(c.id)
		if got == nil || !got.Equal(*c.want) {
			t.Errorf("%s: expires_at = %v, want %v", c.name, got, *c.want)
		}
	}
	if got := inlineExpiry(sid); got == nil || !got.Equal(at) {
		t.Errorf("inline key with a matching hash: key_expires_at = %v, want %v", got, at)
	}
	if got := inlineExpiry(other); got != nil {
		t.Errorf("another sensor's inline key changed: %v", got)
	}

	// A later rotation caps the earlier successor: one key stays long-lived.
	next := newKey(sid, "next", &long)
	if err := repo.RotateKey(ctx, next, viaInline("inline-a"), nil, at); err != nil {
		t.Fatal(err)
	}
	if got := expiry(successor.ID); got == nil || !got.Equal(at) {
		t.Errorf("earlier successor: expires_at = %v, want %v", got, at)
	}
	if got := expiry(next.ID); got == nil || !got.Equal(long) {
		t.Errorf("latest successor: expires_at = %v, want %v", got, long)
	}

	// A rotation that fails leaves nothing written: its key is not issued
	// and nothing is retired.
	dup := newKey(sid, "dup", &long)
	dup.ID = next.ID // primary-key violation on insert
	if err := repo.RotateKey(ctx, dup, viaLong, nil, at.Add(-time.Minute)); err == nil {
		t.Fatal("RotateKey with a duplicate id must fail")
	}
	if got := expiry(next.ID); got == nil || !got.Equal(long) {
		t.Errorf("a failed rotation retired the latest key: expires_at = %v", got)
	}

	// Replacing the inline key caps every active key row of the sensor;
	// other sensors are not touched.
	ok, err := repo.ReplaceInlineKey(ctx, sid, viaInline("inline-a"), "inline-a2", "rda_a2", nil, at)
	if err != nil || !ok {
		t.Fatalf("ReplaceInlineKey: ok=%v err=%v", ok, err)
	}
	if got := expiry(next.ID); got == nil || !got.Equal(at) {
		t.Errorf("key row after inline replacement: expires_at = %v, want %v", got, at)
	}
	if got := inlineExpiry(sid); got != nil {
		t.Errorf("replaced inline key: key_expires_at = %v, want none", got)
	}
	if got := expiry(otherK.ID); got == nil || !got.Equal(long) {
		t.Errorf("another sensor's key changed: %v", got)
	}

	// No active sensor: nothing is written.
	if _, err := db.ExecContext(ctx, `UPDATE sensors SET status = 'revoked' WHERE id = $1`, other.String()); err != nil {
		t.Fatal(err)
	}
	if ok, err := repo.ReplaceInlineKey(ctx, other, viaInline("inline-b"), "inline-b2", "rda_b2", nil, at); err != nil || ok {
		t.Fatalf("ReplaceInlineKey on a revoked sensor: ok=%v err=%v, want a no-op", ok, err)
	}
	if got := expiry(otherK.ID); got == nil || !got.Equal(long) {
		t.Errorf("a refused inline replacement retired a key row: %v", got)
	}
	if ok, err := repo.ReplaceInlineKey(ctx, shared.NewID(), viaInline("h"), "h", "p", nil, at); err != nil || ok {
		t.Fatalf("ReplaceInlineKey on a missing sensor: ok=%v err=%v, want a no-op", ok, err)
	}
}

// A renewal re-checks, under the per-sensor lock, the key it authenticated
// with and the sensor's status, and RegenerateKey takes the same lock. After
// a regeneration neither the replaced inline key nor a revoked key row can
// rotate, and a refused rotation writes nothing. Skipped unless DATABASE_URL
// is set.
func TestSensorAPIKeyRepository_RenewalRechecksPresentedKey(t *testing.T) {
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
		tenantID.String(), "sensor-recheck-test", "src-"+tenantID.String()[28:]); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID.String()) }()

	sensorRepo := NewSensorRepository(&DB{DB: db})
	s, err := sensordom.NewSensor(tenantID, "src-a", sensordom.SensorTypeWorker, "", nil, sensordom.ExecutionModeStandalone)
	if err != nil {
		t.Fatal(err)
	}
	s.SetAPIKey("inline-old", "rda_old_")
	if err := sensorRepo.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	sid := s.ID

	repo := NewSensorAPIKeyRepository(&DB{DB: db})
	long := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Microsecond)
	at := time.Now().Add(15 * time.Minute).Truncate(time.Microsecond)
	newKey := func(name string) *sensordom.APIKey {
		k, _ := sensordom.NewAPIKey(sid, name, sensordom.WorkerScopes())
		k.SetKeyHash("hash-"+name, "rda_"+(name + "________")[:8])
		k.SetExpiration(long)
		return k
	}
	activeRows := func() int {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensor_api_keys WHERE sensor_id = $1 AND is_active`, sid.String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	now := func() time.Time { return time.Now() }
	inlineOld := sensordom.PresentedKey{InlineKeyHashes: []string{"inline-old"}, At: now()}

	// A valid presented key rotates.
	row := newKey("row")
	if err := repo.RotateKey(ctx, row, inlineOld, []string{"inline-old"}, at); err != nil {
		t.Fatalf("RotateKey with a valid key: %v", err)
	}
	viaRow := sensordom.PresentedKey{KeyID: &row.ID, At: now()}

	// An expired presented key row is refused.
	if err := repo.RotateKey(ctx, newKey("late"), sensordom.PresentedKey{KeyID: &row.ID, At: long.Add(time.Hour)}, nil, at); !errors.Is(err, sensordom.ErrPresentedKeyInvalid) {
		t.Errorf("RotateKey with an expired key row: err = %v, want ErrPresentedKeyInvalid", err)
	}

	// The administrator regenerates: new inline key, every row revoked.
	ok, err := repo.RegenerateKey(ctx, sid, "inline-admin", "rda_adm_", "regenerated")
	if err != nil || !ok {
		t.Fatalf("RegenerateKey: ok=%v err=%v", ok, err)
	}
	if n := activeRows(); n != 0 {
		t.Fatalf("%d active key rows after regeneration, want 0", n)
	}
	var hash string
	var exp sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT api_key_hash, key_expires_at FROM sensors WHERE id = $1`, sid.String()).Scan(&hash, &exp); err != nil {
		t.Fatal(err)
	}
	if hash != "inline-admin" || exp.Valid {
		t.Fatalf("inline key after regeneration: hash=%q expires=%v, want inline-admin, never", hash, exp)
	}

	// Renewals that authenticated with a replaced key are refused and write
	// nothing, through either write.
	for name, p := range map[string]sensordom.PresentedKey{"replaced inline key": inlineOld, "revoked key row": viaRow} {
		if err := repo.RotateKey(ctx, newKey("after-"+name[:4]), p, nil, at); !errors.Is(err, sensordom.ErrPresentedKeyInvalid) {
			t.Errorf("RotateKey with the %s: err = %v, want ErrPresentedKeyInvalid", name, err)
		}
		if ok, err := repo.ReplaceInlineKey(ctx, sid, p, "inline-attacker", "rda_att_", nil, at); ok || !errors.Is(err, sensordom.ErrPresentedKeyInvalid) {
			t.Errorf("ReplaceInlineKey with the %s: ok=%v err=%v, want ErrPresentedKeyInvalid", name, ok, err)
		}
	}
	if n := activeRows(); n != 0 {
		t.Errorf("a refused renewal minted %d key rows", n)
	}
	if err := db.QueryRowContext(ctx, `SELECT api_key_hash FROM sensors WHERE id = $1`, sid.String()).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if hash != "inline-admin" {
		t.Errorf("a refused renewal replaced the administrator's key: %q", hash)
	}

	// A disabled or revoked sensor cannot rotate even with a valid key.
	adminKey := sensordom.PresentedKey{InlineKeyHashes: []string{"inline-admin"}, At: now()}
	for status, want := range map[string]error{"disabled": sensordom.ErrSensorDisabled, "revoked": sensordom.ErrSensorRevoked} {
		if _, err := db.ExecContext(ctx, `UPDATE sensors SET status = $2 WHERE id = $1`, sid.String(), status); err != nil {
			t.Fatal(err)
		}
		if err := repo.RotateKey(ctx, newKey("st-"+status), adminKey, nil, at); !errors.Is(err, want) {
			t.Errorf("RotateKey on a %s sensor: err = %v, want %v", status, err, want)
		}
	}
	if n := activeRows(); n != 0 {
		t.Errorf("a rotation on an inactive sensor minted %d key rows", n)
	}

	// Regenerating a missing sensor writes nothing.
	if ok, err := repo.RegenerateKey(ctx, shared.NewID(), "h", "p", "regenerated"); err != nil || ok {
		t.Errorf("RegenerateKey on a missing sensor: ok=%v err=%v, want a no-op", ok, err)
	}
}
