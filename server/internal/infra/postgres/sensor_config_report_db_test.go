package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

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
