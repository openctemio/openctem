package postgres

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The config report store is tenant-scoped on every read and write: a
// report is saved only for an active sensor of the given tenant, and read
// back only by that tenant (research/26 T8).
func TestSensorConfigReportStore_TenantScoped(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewSensorRepository(&DB{DB: db})
	tenantA, tenantB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	sensorID := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status)
		VALUES ($1, $2, $3, $4, 'p', 'active')`, sensorID.String(), tenantA.String(), "cfg-"+sensorID.String(), "h-"+sensorID.String()); err != nil {
		t.Fatal(err)
	}

	rep, _, err := sensor.SanitizeConfigReport([]byte(`{"schema":1,"observed_at":"2026-10-05T10:00:00Z",
		"checks":[{"id":"policy.local","status":"warn","code":"absent"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := rep.Digest()
	now := time.Now().UTC().Truncate(time.Microsecond)

	// Another tenant cannot write it ...
	if saved, _, err := repo.SaveConfigReport(ctx, tenantB, sensorID, rep, digest, sensor.ConfigHealthAttention, now); err != nil || saved {
		t.Fatalf("cross-tenant save: saved=%v err=%v", saved, err)
	}
	if _, err := repo.GetConfigReport(ctx, tenantA, sensorID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a cross-tenant save stored something: %v", err)
	}

	saved, changed, err := repo.SaveConfigReport(ctx, tenantA, sensorID, rep, digest, sensor.ConfigHealthAttention, now)
	if err != nil || !saved || !changed {
		t.Fatalf("save: saved=%v changed=%v err=%v", saved, changed, err)
	}
	got, err := repo.GetConfigReport(ctx, tenantA, sensorID)
	if err != nil || got.Digest != digest || got.Health != sensor.ConfigHealthAttention || len(got.Report.Checks) != 1 ||
		got.Report.ObservedAt != "2026-10-05T10:00:00Z" {
		t.Fatalf("read %+v %v", got, err)
	}
	// ... nor read it.
	if _, err := repo.GetConfigReport(ctx, tenantB, sensorID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant read: %v", err)
	}

	// The same digest only moves received_at.
	later := now.Add(time.Minute)
	if saved, changed, err := repo.SaveConfigReport(ctx, tenantA, sensorID, rep, digest, sensor.ConfigHealthAttention, later); err != nil || !saved || changed {
		t.Fatalf("dedup: saved=%v changed=%v err=%v", saved, changed, err)
	}
	if got, _ := repo.GetConfigReport(ctx, tenantA, sensorID); !got.ReceivedAt.Equal(later) {
		t.Fatalf("received_at %v, want %v", got.ReceivedAt, later)
	}
	s, err := repo.GetByTenantAndID(ctx, tenantA, sensorID)
	if err != nil || s.ConfigReportDigest != digest || s.ConfigHealth != sensor.ConfigHealthAttention || s.ConfigHeartbeatDigest != digest {
		t.Fatalf("pointers %+v %v", s, err)
	}

	// A disabled sensor stores nothing.
	if _, err := db.ExecContext(ctx, `UPDATE sensors SET status = 'disabled' WHERE id = $1`, sensorID.String()); err != nil {
		t.Fatal(err)
	}
	if saved, _, err := repo.SaveConfigReport(ctx, tenantA, sensorID, rep, digest, sensor.ConfigHealthOK, later); err != nil || saved {
		t.Fatalf("disabled sensor: saved=%v err=%v", saved, err)
	}
}

// Migration 001061 is additive and reversible on populated tables:
// replayed up -> down -> up in a rolled-back transaction with a sensor and
// its report in place.
func TestSensorConfigReportsMigration_UpDownUp(t *testing.T) {
	ctx := context.Background()
	up, err := os.ReadFile("../../../migrations/001061_sensor_config_reports.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/001061_sensor_config_reports.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := testdb.OpenMigrator(t).BeginTx(ctx, nil) // DDL: schema owner
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	// The new table references both; its foreign keys lock them too.
	testdb.LockForDDL(t, ctx, tx, "tenants", "sensors")
	must := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%.80s: %v", q, err)
		}
	}
	tenant, sensorID := shared.NewID(), shared.NewID()
	must(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'mig1050', $2)`, tenant.String(), "mig1050-"+tenant.String())
	must(`INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status) VALUES ($1, $2, 'mig1050', $3, 'p', 'active')`,
		sensorID.String(), tenant.String(), "h-"+sensorID.String())
	digest := "sha256:" + strings.Repeat("a", 64)
	must(`UPDATE sensors SET config_report_digest = $2, config_health = 'ok' WHERE id = $1`, sensorID.String(), digest)
	must(`INSERT INTO sensor_config_reports (sensor_id, tenant_id, digest, health, report) VALUES ($1, $2, $3, 'ok', '{}')`,
		sensorID.String(), tenant.String(), digest)

	// The constraints hold.
	for _, bad := range []string{
		`INSERT INTO sensor_config_reports (sensor_id, tenant_id, digest, health, report) VALUES ('` + shared.NewID().String() + `', '` + tenant.String() + `', 'md5:x', 'ok', '{}')`,
		`UPDATE sensor_config_reports SET health = 'great' WHERE sensor_id = '` + sensorID.String() + `'`,
		`UPDATE sensor_config_reports SET report = '[]' WHERE sensor_id = '` + sensorID.String() + `'`,
		`UPDATE sensors SET config_health = 'great' WHERE id = '` + sensorID.String() + `'`,
	} {
		must(`SAVEPOINT bad`)
		if _, err := tx.ExecContext(ctx, bad); err == nil {
			t.Errorf("accepted: %.100s", bad)
		}
		must(`ROLLBACK TO SAVEPOINT bad`)
	}

	must(string(down))
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'sensors' AND column_name LIKE 'config\_%'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("columns after down: %d %v", n, err)
	}
	must(string(up))
	must(string(up)) // idempotent
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sensors WHERE id = $1 AND config_report_digest IS NULL`, sensorID.String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("sensor after up: %d %v", n, err)
	}
}
