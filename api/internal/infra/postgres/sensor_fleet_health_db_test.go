package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The heartbeat's uptime_seconds used to be parsed and dropped. It is now kept
// as the process start time (heartbeat time minus uptime), which survives
// heartbeats that do not report it and ignores implausible values.
func TestUpdateHeartbeat_StoresProcessStartFromUptime(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewSensorRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	now := time.Now()
	id := seedSensor(ctx, t, db, tenantID, "online", &now, "nuclei", 0)

	get := func() *sensor.Sensor {
		t.Helper()
		s, err := repo.GetByTenantAndID(ctx, tenantID, id)
		if err != nil {
			t.Fatalf("get sensor: %v", err)
		}
		return s
	}
	beat := func(uptime int64) {
		t.Helper()
		ok, err := repo.UpdateHeartbeat(ctx, id, sensor.HeartbeatUpdate{TenantID: &tenantID, UptimeSeconds: uptime})
		if err != nil || !ok {
			t.Fatalf("heartbeat: ok=%v err=%v", ok, err)
		}
	}

	if s := get(); s.StartedAt != nil {
		t.Fatalf("start time before any report: %v", s.StartedAt)
	}

	const uptime = 3600 * 5
	beat(uptime)
	s := get()
	if s.StartedAt == nil || s.LastSeenAt == nil {
		t.Fatalf("start time not stored: started=%v seen=%v", s.StartedAt, s.LastSeenAt)
	}
	if got := s.LastSeenAt.Sub(*s.StartedAt); got < uptime*time.Second-2*time.Second || got > uptime*time.Second+2*time.Second {
		t.Errorf("last_seen - started = %s, want ~%ds", got, uptime)
	}
	started := *s.StartedAt

	// A heartbeat without an uptime keeps the stored start time.
	beat(0)
	if s := get(); s.StartedAt == nil || !s.StartedAt.Equal(started) {
		t.Errorf("start time changed by a heartbeat without uptime: %v -> %v", started, s.StartedAt)
	}

	// An implausible uptime (over ten years) is ignored, not stored.
	beat(sensor.MaxReportedUptime + 1)
	if s := get(); s.StartedAt == nil || !s.StartedAt.Equal(started) {
		t.Errorf("implausible uptime was stored: %v", s.StartedAt)
	}
}

// The stats endpoint and the list must count the same sensors: the tenant's
// own, without shared platform sensors (they have their own page). The list
// used to include rows flagged is_platform_sensor that the stats left out, so
// the page header and the table disagreed.
func TestTenantSensorStats_CountsWhatTheListShows(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewSensorRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	now := time.Now()

	own := seedSensor(ctx, t, db, tenantID, "online", &now, "nuclei", 0)
	platform := seedSensor(ctx, t, db, tenantID, "online", &now, "trivy", 0)
	if _, err := db.ExecContext(ctx, `UPDATE sensors SET is_platform_sensor = TRUE WHERE id = $1`, platform.String()); err != nil {
		t.Fatalf("flag platform sensor: %v", err)
	}

	listed, err := repo.List(ctx, sensor.Filter{TenantID: &tenantID}, pagination.New(1, 100))
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	stats, err := repo.GetTenantSensorStats(ctx, tenantID)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if int64(stats.Total) != listed.Total || stats.Total != 1 {
		t.Errorf("stats total = %d, list total = %d, want both 1", stats.Total, listed.Total)
	}
	if len(listed.Data) != 1 || listed.Data[0].ID != own {
		t.Errorf("the list holds the platform sensor: %+v", listed.Data)
	}
	if stats.OnlineActive != 1 {
		t.Errorf("online_active = %d, want 1", stats.OnlineActive)
	}

	// Nor can a tenant read it by id, though its row carries the tenant.
	if got, err := repo.GetByTenantAndID(ctx, tenantID, platform); err == nil || got != nil {
		t.Errorf("platform sensor read by its row's tenant: %v, %v", got, err)
	}
}
