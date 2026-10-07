package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// Dispatch to zone sensors filtered on key_expires_at, the inline key's
// expiry. After a renewal that is the retired bootstrap key, so every renewed
// sensor would have been excluded from zone dispatch once the 15-minute grace
// ended. sensorKeyUsableSQL accepts any credential that still authenticates.
func TestSensorKeyUsableSQL(t *testing.T) {
	db := openGroupsDB(t)
	ctx := context.Background()
	tenant := seedTestTenant(ctx, t, db)
	repo := NewSensorRepository(&DB{DB: db})

	mk := func(name string) string {
		t.Helper()
		s, err := sensor.NewSensor(tenant, name, sensor.SensorTypeWorker, "", nil, sensor.ExecutionModeDaemon)
		if err != nil {
			t.Fatal(err)
		}
		s.SetAPIKey(strings.Repeat(name[:1], 64), "rda_"+name[:4])
		if err := repo.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		return s.ID.String()
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	usable := func(id string) bool {
		t.Helper()
		var ok bool
		if err := db.QueryRowContext(ctx, `SELECT `+sensorKeyUsableSQL("s")+` FROM sensors s WHERE s.id = $1`, id).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	addKey := func(id, prefix, expires string, active bool) {
		t.Helper()
		exec(`INSERT INTO sensor_api_keys (sensor_id, key_hash, key_prefix, expires_at, is_active)
			VALUES ($1, md5(random()::text) || md5(random()::text), $2, NOW() + $3::interval, $4)`, id, prefix, expires, active)
	}

	inline := mk("aaaa-inline-only")
	if !usable(inline) {
		t.Error("never-expiring inline key must be usable")
	}

	renewed := mk("bbbb-renewed")
	exec(`UPDATE sensors SET key_expires_at = NOW() - INTERVAL '7 hours' WHERE id = $1`, renewed)
	addKey(renewed, "rda_newkey01", "90 days", true)
	if !usable(renewed) {
		t.Error("renewed sensor (inline retired, rotating key valid) must be usable: this is the live bug")
	}

	expired := mk("cccc-expired")
	exec(`UPDATE sensors SET key_expires_at = NOW() - INTERVAL '30 days' WHERE id = $1`, expired)
	addKey(expired, "rda_oldkey01", "-1 hour", true)
	if usable(expired) {
		t.Error("a sensor whose every key has expired must not be usable")
	}

	revoked := mk("dddd-revoked")
	exec(`UPDATE sensors SET key_expires_at = NOW() - INTERVAL '30 days' WHERE id = $1`, revoked)
	addKey(revoked, "rda_revkey01", "90 days", false)
	if usable(revoked) {
		t.Error("an inactive (revoked) rotating key must not make a sensor usable")
	}

	// The repository read path carries the same choice into the domain.
	got, err := repo.GetByID(ctx, mustID(t, renewed))
	if err != nil {
		t.Fatal(err)
	}
	if ks := got.KeyState(); ks.Prefix != "rda_newkey01" || !ks.Rotating {
		t.Fatalf("GetByID KeyState = %+v, want the rotating key", ks)
	}
}

// A sensor is on a legacy key when its effective key (rotating key first,
// else inline) is rda_. The count behind openctem_sensor_legacy_keys uses the
// same predicate across tenants; here it is checked within one tenant so
// other tests' sensors do not matter.
func TestSensorLegacyKeySQL(t *testing.T) {
	db := openGroupsDB(t)
	ctx := context.Background()
	tenant := seedTestTenant(ctx, t, db)
	repo := NewSensorRepository(&DB{DB: db})

	mk := func(name, prefix string) string {
		t.Helper()
		s, err := sensor.NewSensor(tenant, name, sensor.SensorTypeWorker, "", nil, sensor.ExecutionModeDaemon)
		if err != nil {
			t.Fatal(err)
		}
		s.SetAPIKey(strings.Repeat(name[:1], 64), prefix)
		if err := repo.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		return s.ID.String()
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	legacy := func(id string) bool {
		t.Helper()
		var ok bool
		if err := db.QueryRowContext(ctx, `SELECT `+sensorLegacyKeySQL("s")+` FROM sensors s WHERE s.id = $1`, id).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}

	inlineRDA := mk("a-inline-rda", "rda_1a2b3c4d")
	inlineOCTS := mk("b-inline-octs", "octs_Ab3dE")
	renewed := mk("c-renewed", "rda_5e6f7a8b")
	exec(`INSERT INTO sensor_api_keys (sensor_id, key_hash, key_prefix, expires_at, is_active)
		VALUES ($1, md5(random()::text) || md5(random()::text), 'octs_Zz9Yy', NOW() + INTERVAL '90 days', true)`, renewed)
	underscore := mk("d-lookalike", "rdaX1234")

	for id, want := range map[string]bool{inlineRDA: true, inlineOCTS: false, renewed: false, underscore: false} {
		if got := legacy(id); got != want {
			t.Errorf("sensor %s: legacy = %v, want %v", id, got, want)
		}
	}
	got, err := repo.GetByID(ctx, mustID(t, renewed))
	if err != nil {
		t.Fatal(err)
	}
	if got.IsLegacyKey() {
		t.Error("domain IsLegacyKey disagrees with the SQL for a renewed sensor")
	}

	var mine int64
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensors s WHERE s.tenant_id = $1 AND s.status <> 'revoked' AND `+sensorLegacyKeySQL("s"), tenant.String()).Scan(&mine); err != nil {
		t.Fatal(err)
	}
	if mine != 1 {
		t.Errorf("legacy sensors in the tenant = %d, want 1", mine)
	}
	total, err := repo.CountLegacyKeySensors(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if total < mine {
		t.Errorf("CountLegacyKeySensors = %d, below this tenant's %d", total, mine)
	}

	// A revoked sensor no longer counts.
	exec(`UPDATE sensors SET status = 'revoked' WHERE id = $1`, inlineRDA)
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensors s WHERE s.tenant_id = $1 AND s.status <> 'revoked' AND `+sensorLegacyKeySQL("s"), tenant.String()).Scan(&mine); err != nil {
		t.Fatal(err)
	}
	if mine != 0 {
		t.Errorf("after revoking, legacy sensors in the tenant = %d, want 0", mine)
	}
}
