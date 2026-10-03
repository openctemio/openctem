package sensor_test

// RFC-032 Phase 0 against a migrated database: the dedicated key-hash pepper
// (old hashes keep verifying), the client address recorded on every key use,
// and cloned-identity detection from real heartbeats.

import (
	"context"
	"database/sql"
	"net"
	"strings"
	"testing"
	"time"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/crypto"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const testEncryptionKey = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"

// newPepperedService is a sensor service configured the way cmd/server
// configures it, with the multi-key store and the activity timeline wired.
func newPepperedService(h *activityHarness, explicit string) *sensorapp.SensorService {
	h.t.Helper()
	db := &postgres.DB{DB: h.db}
	svc := sensorapp.NewSensorService(postgres.NewSensorRepository(db), nil, logger.NewNop())
	pepper, legacy := sensorapp.SensorKeyPeppers(explicit, testEncryptionKey)
	svc.SetPepper(pepper)
	svc.SetLegacyPeppers(legacy...)
	svc.SetAPIKeyRepository(postgres.NewSensorAPIKeyRepository(db))
	events := postgres.NewSensorEventRepository(db)
	svc.SetEventRepository(events, sensordom.DefaultEventLimits())
	svc.SetActivityReader(events)
	return svc
}

// sensorWithKey inserts an active sensor whose inline key hash is hash.
func (h *activityHarness) sensorWithKey(tenantID shared.ID, hash string) shared.ID {
	h.t.Helper()
	id := shared.NewID()
	h.exec(`INSERT INTO sensors (id, tenant_id, name, type, status, health, execution_mode, api_key_hash, api_key_prefix, max_concurrent_jobs)
	        VALUES ($1, $2, $3, 'worker', 'active', 'unknown', 'daemon', $4, 'rda_test', 5)`,
		id.String(), tenantID.String(), "identity-"+id.String()[:8], hash)
	return id
}

// waitFor polls cond (the key-use write is asynchronous) for up to 3 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestSensorKeyPepper_OldHashesKeepVerifying_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	ctx := context.Background()

	// Keys stored before this release: under APP_ENCRYPTION_KEY as the
	// pepper, and (older still) as plain SHA-256.
	oldKey := "rda_" + strings.Repeat("ab", 32)
	plainKey := "rda_" + strings.Repeat("cd", 32)
	oldID := h.sensorWithKey(tid, crypto.HashTokenPeppered(oldKey, testEncryptionKey))
	plainID := h.sensorWithKey(tid, crypto.HashToken(plainKey))

	svc := newPepperedService(h, "")
	for key, want := range map[string]shared.ID{oldKey: oldID, plainKey: plainID} {
		id, err := svc.AuthenticateIdentity(ctx, key)
		if err != nil || id.Sensor == nil || id.Sensor.ID != want {
			t.Fatalf("a key stored before the pepper change must authenticate: %v", err)
		}
	}
	if _, err := svc.AuthenticateIdentity(ctx, "rda_"+strings.Repeat("ef", 32)); err == nil {
		t.Fatal("an unknown key must be refused")
	}

	// A key the admin regenerates now is stored under the derived pepper,
	// not under the encryption key.
	newKey, err := svc.RegenerateAPIKey(ctx, tid.String(), oldID.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := h.db.QueryRowContext(ctx, `SELECT api_key_hash FROM sensors WHERE id = $1`, oldID.String()).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == crypto.HashTokenPeppered(newKey, testEncryptionKey) || stored == crypto.HashToken(newKey) {
		t.Fatal("a new key must not be hashed with the encryption key or unpeppered")
	}
	if stored != crypto.HashTokenPeppered(newKey, sensorapp.DeriveSensorKeyPepper(testEncryptionKey)) {
		t.Fatal("a new key must be hashed with the derived pepper")
	}
	if _, err := svc.AuthenticateIdentity(ctx, newKey); err != nil {
		t.Fatalf("the regenerated key must authenticate: %v", err)
	}
	if _, err := svc.AuthenticateIdentity(ctx, oldKey); err == nil {
		t.Fatal("the replaced key must not authenticate")
	}

	// Moving to an explicit SENSOR_KEY_PEPPER keeps the derived-pepper key.
	explicit := newPepperedService(h, strings.Repeat("p", 40))
	if _, err := explicit.AuthenticateIdentity(ctx, newKey); err != nil {
		t.Fatalf("a key under the derived pepper must survive SENSOR_KEY_PEPPER being set: %v", err)
	}
}

func TestSensorKeyPepper_RenewedOverlapKey_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	ctx := context.Background()

	oldKey := "rda_" + strings.Repeat("12", 32)
	id := h.sensorWithKey(tid, crypto.HashTokenPeppered(oldKey, testEncryptionKey))
	svc := newPepperedService(h, "")
	svc.SetKeyTTL(90 * 24 * time.Hour)

	ident, err := svc.AuthenticateIdentity(ctx, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	renewed, exp, err := svc.RenewAPIKey(ctx, ident.Sensor)
	if err != nil || exp == nil {
		t.Fatalf("renew: %v %v", err, exp)
	}
	got, err := svc.AuthenticateIdentity(ctx, renewed)
	if err != nil || got.Sensor.ID != id {
		t.Fatalf("the renewed key (a sensor_api_keys row under the new pepper) must authenticate: %v", err)
	}
	// The key it replaced stays valid for the overlap grace.
	if _, err := svc.AuthenticateIdentity(ctx, oldKey); err != nil {
		t.Fatalf("the replaced key keeps its overlap grace: %v", err)
	}
}

func TestSensorKeyUse_RecordsClientAddress_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	ctx := context.Background()
	svc := newPepperedService(h, "")
	pepper, _ := sensorapp.SensorKeyPeppers("", testEncryptionKey)

	key := "rda_" + strings.Repeat("34", 32)
	id := h.sensorWithKey(tid, crypto.HashTokenPeppered(key, pepper))

	lastIP := func() string {
		var ip sql.NullString
		var at sql.NullTime
		if err := h.db.QueryRowContext(ctx, `SELECT host(api_key_last_used_ip), api_key_last_used_at FROM sensors WHERE id = $1`,
			id.String()).Scan(&ip, &at); err != nil {
			t.Fatal(err)
		}
		if ip.Valid && !at.Valid {
			t.Fatal("an address is recorded with its time")
		}
		return ip.String
	}

	if _, err := svc.AuthenticateIdentityFrom(ctx, key, "203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the first address", func() bool { return lastIP() == "203.0.113.7" })

	// Same address: no timeline entry. A new address: one.
	if _, err := svc.AuthenticateIdentityFrom(ctx, key, "203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AuthenticateIdentityFrom(ctx, key, "198.51.100.9"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the new address", func() bool { return lastIP() == "198.51.100.9" })
	waitFor(t, "the key_ip_changed event", func() bool {
		var n int
		_ = h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensor_events WHERE sensor_id = $1 AND type = 'key_ip_changed'`, id.String()).Scan(&n)
		return n == 1
	})

	// The response carries it.
	a, err := svc.GetSensor(ctx, tid.String(), id.String())
	if err != nil {
		t.Fatal(err)
	}
	if a.KeyLastUsedIP.String() != "198.51.100.9" || a.KeyLastUsedAt == nil {
		t.Fatalf("entity: ip=%v at=%v", a.KeyLastUsedIP, a.KeyLastUsedAt)
	}

	// No address (an unparseable one): the time moves, the address stays.
	if _, err := svc.AuthenticateIdentityFrom(ctx, key, "not-an-ip"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if lastIP() != "198.51.100.9" {
		t.Fatal("an unknown address must not erase the recorded one")
	}
}

func TestSensorKeyUse_MultiKeyRowGetsAddress_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	ctx := context.Background()
	svc := newPepperedService(h, "")
	svc.SetKeyTTL(90 * 24 * time.Hour)
	pepper, _ := sensorapp.SensorKeyPeppers("", testEncryptionKey)

	key := "rda_" + strings.Repeat("56", 32)
	id := h.sensorWithKey(tid, crypto.HashTokenPeppered(key, pepper))
	ident, err := svc.AuthenticateIdentity(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	renewed, _, err := svc.RenewAPIKey(ctx, ident.Sensor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AuthenticateIdentityFrom(ctx, renewed, "192.0.2.44"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the key row's address", func() bool {
		var ip sql.NullString
		_ = h.db.QueryRowContext(ctx, `SELECT host(last_used_ip) FROM sensor_api_keys WHERE sensor_id = $1 AND last_used_ip IS NOT NULL`,
			id.String()).Scan(&ip)
		return ip.String == "192.0.2.44"
	})
}

func TestSensorCloneDetection_Heartbeats_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	ctx := context.Background()
	svc := newPepperedService(h, "")

	clonedAt := func(id shared.ID) *time.Time {
		a, err := svc.GetSensor(ctx, tid.String(), id.String())
		if err != nil {
			t.Fatal(err)
		}
		return a.IdentityClonedAt
	}
	beat := func(id shared.ID, instance, host string) {
		if err := svc.UpdateHeartbeat(ctx, id, sensorapp.SensorHeartbeatData{
			Version: "0.6.0", Hostname: host, InstanceID: instance, Protocol: 2,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// A restart: one instance replaced by another, never back.
	restarted := h.sensorWithKey(tid, "hash-restart-"+shared.NewID().String())
	for _, inst := range []string{"inst-a", "inst-a", "inst-b", "inst-b", "inst-b"} {
		beat(restarted, inst, "host-1")
	}
	if clonedAt(restarted) != nil {
		t.Fatal("a restart must not flag the identity")
	}

	// Two live copies of one key, alternating.
	cloned := h.sensorWithKey(tid, "hash-clone-"+shared.NewID().String())
	for _, inst := range []string{"inst-a", "inst-b", "inst-a", "inst-b", "inst-a", "inst-b"} {
		beat(cloned, inst, "host-x")
	}
	if clonedAt(cloned) == nil {
		t.Fatal("two alternating instances must flag the identity")
	}
	var events int
	if err := h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensor_events WHERE sensor_id = $1 AND type = 'identity_cloned'`,
		cloned.String()).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("identity_cloned events = %d, want exactly one (flagged once)", events)
	}
	a, _ := svc.GetSensor(ctx, tid.String(), cloned.String())
	health := a.AssessHealth(time.Now(), sensordom.HealthPolicy{OnlineWindow: time.Minute, OfflineAfter: 5 * time.Minute})
	found := false
	for _, r := range health.Reasons {
		found = found || r.Code == sensordom.ReasonIdentityCloned
	}
	if !found {
		t.Fatalf("the fleet health must report identity_cloned: %+v", health.Reasons)
	}

	// Older SDKs (no instance id): two hosts alternating are flagged too.
	byHost := h.sensorWithKey(tid, "hash-host-"+shared.NewID().String())
	for _, host := range []string{"vm-1", "vm-2", "vm-1", "vm-2", "vm-1", "vm-2"} {
		beat(byHost, "", host)
	}
	if clonedAt(byHost) == nil {
		t.Fatal("two hosts alternating without instance ids must flag the identity")
	}

	// Regenerating the key resolves the flag.
	if _, err := svc.RegenerateAPIKey(ctx, tid.String(), cloned.String(), nil); err != nil {
		t.Fatal(err)
	}
	if clonedAt(cloned) != nil {
		t.Fatal("regenerating the key must clear the flag")
	}

	// A disabled sensor's heartbeat is not observed (the guarded write).
	h.exec(`UPDATE sensors SET status = 'disabled' WHERE id = $1`, restarted.String())
	beat(restarted, "inst-z", "host-1")
	var inst sql.NullString
	_ = h.db.QueryRowContext(ctx, `SELECT instance_id FROM sensors WHERE id = $1`, restarted.String()).Scan(&inst)
	if inst.String == "inst-z" {
		t.Fatal("a disabled sensor's heartbeat must not change its instance")
	}
}

// Key uses are recorded off the request path, so they can reach the database
// out of order. An older observation must not overwrite a newer address, and
// must not report an address change.
func TestSensorKeyUse_OutOfOrderKeepsNewerAddress_DB(t *testing.T) {
	h := newActivityHarness(t)
	tid := h.tenant()
	ctx := context.Background()
	id := h.sensorWithKey(tid, crypto.HashTokenPeppered("rda_"+strings.Repeat("78", 32), testEncryptionKey))
	repo := postgres.NewSensorRepository(&postgres.DB{DB: h.db})

	newer := time.Now().UTC().Truncate(time.Microsecond)
	older := newer.Add(-time.Second)

	if _, err := repo.RecordKeyUse(ctx, id, net.ParseIP("198.51.100.9"), newer); err != nil {
		t.Fatal(err)
	}
	prev, err := repo.RecordKeyUse(ctx, id, net.ParseIP("203.0.113.7"), older)
	if err != nil {
		t.Fatal(err)
	}
	if prev != nil {
		t.Fatalf("a stale key use reported a previous address %v; it would raise a false key_ip_changed", prev)
	}

	var ip string
	var at time.Time
	if err := h.db.QueryRowContext(ctx, `SELECT host(api_key_last_used_ip), api_key_last_used_at FROM sensors WHERE id = $1`,
		id.String()).Scan(&ip, &at); err != nil {
		t.Fatal(err)
	}
	if ip != "198.51.100.9" {
		t.Fatalf("the older key use overwrote the newer address: got %s", ip)
	}
	if !at.Equal(newer) {
		t.Fatalf("the key-use time moved backwards: got %v want %v", at, newer)
	}

	// A newer use still moves both forward and reports the change.
	prev, err = repo.RecordKeyUse(ctx, id, net.ParseIP("192.0.2.4"), newer.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if prev == nil || prev.String() != "198.51.100.9" {
		t.Fatalf("previous address: got %v want 198.51.100.9", prev)
	}
}
