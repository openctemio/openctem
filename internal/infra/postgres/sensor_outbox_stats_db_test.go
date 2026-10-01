package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/pagination"
)

// TestUpdateHeartbeat_OutboxStats: a heartbeat with an outbox snapshot stores
// it with the server time, every read path returns it, and a heartbeat without
// one leaves both the snapshot and its timestamp untouched.
func TestUpdateHeartbeat_OutboxStats(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := &SensorRepository{db: &DB{DB: db}}

	tenantID := seedTestTenant(ctx, t, db)
	id := seedSensor(ctx, t, db, tenantID, "offline", nil, "nuclei", 0)

	// Before any report: no snapshot.
	a, err := repo.GetByTenantAndID(ctx, tenantID, id)
	if err != nil {
		t.Fatalf("GetByTenantAndID: %v", err)
	}
	if a.Outbox != nil {
		t.Fatalf("new sensor has outbox %+v, want nil", *a.Outbox)
	}

	want := sensor.OutboxStats{PendingCount: 3, PendingBytes: 123456, OldestAgeSeconds: 600, DeadLetterCount: 1, EvictedCount: 7}
	before := time.Now().Add(-time.Minute)
	ok, err := repo.UpdateHeartbeat(ctx, id, sensor.HeartbeatUpdate{TenantID: &tenantID, Outbox: &want})
	if err != nil || !ok {
		t.Fatalf("UpdateHeartbeat with outbox: ok=%v err=%v", ok, err)
	}

	a, err = repo.GetByTenantAndID(ctx, tenantID, id)
	if err != nil {
		t.Fatalf("GetByTenantAndID: %v", err)
	}
	if a.Outbox == nil {
		t.Fatal("outbox not stored")
	}
	reportedAt := a.Outbox.ReportedAt
	if reportedAt.Before(before) {
		t.Errorf("reported_at = %v, want a server time after %v", reportedAt, before)
	}
	got := *a.Outbox
	got.ReportedAt = time.Time{}
	if got != want {
		t.Errorf("stored outbox = %+v, want %+v", got, want)
	}

	// The list and by-id read paths (scanSensorFromRows / scanSensor) agree.
	byID, err := repo.GetByID(ctx, id)
	if err != nil || byID.Outbox == nil || byID.Outbox.PendingCount != 3 {
		t.Errorf("GetByID outbox = %+v, err %v", byID.Outbox, err)
	}
	page, err := repo.List(ctx, sensor.Filter{TenantID: &tenantID}, pagination.New(1, 50))
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, s := range page.Data {
		if s.ID == id {
			found = true
			if s.Outbox == nil || s.Outbox.EvictedCount != 7 || !s.Outbox.ReportedAt.Equal(reportedAt) {
				t.Errorf("List outbox = %+v, want evicted_count=7 reported_at=%v", s.Outbox, reportedAt)
			}
		}
	}
	if !found {
		t.Fatal("seeded sensor missing from List")
	}

	// A heartbeat without the field (an SDK without an outbox) keeps the
	// snapshot and its timestamp.
	ok, err = repo.UpdateHeartbeat(ctx, id, sensor.HeartbeatUpdate{TenantID: &tenantID, CPUPercent: 5})
	if err != nil || !ok {
		t.Fatalf("UpdateHeartbeat without outbox: ok=%v err=%v", ok, err)
	}
	a, err = repo.GetByTenantAndID(ctx, tenantID, id)
	if err != nil {
		t.Fatalf("GetByTenantAndID: %v", err)
	}
	if a.Outbox == nil {
		t.Fatal("a heartbeat without outbox cleared the snapshot")
	}
	if !a.Outbox.ReportedAt.Equal(reportedAt) {
		t.Errorf("reported_at moved to %v on a heartbeat without outbox, want %v", a.Outbox.ReportedAt, reportedAt)
	}
	got = *a.Outbox
	got.ReportedAt = time.Time{}
	if got != want {
		t.Errorf("outbox changed to %+v on a heartbeat without outbox, want %+v", got, want)
	}

	// A new snapshot replaces the old one, including a now-empty outbox.
	ok, err = repo.UpdateHeartbeat(ctx, id, sensor.HeartbeatUpdate{TenantID: &tenantID, Outbox: &sensor.OutboxStats{}})
	if err != nil || !ok {
		t.Fatalf("UpdateHeartbeat with empty outbox: ok=%v err=%v", ok, err)
	}
	a, err = repo.GetByTenantAndID(ctx, tenantID, id)
	if err != nil {
		t.Fatalf("GetByTenantAndID: %v", err)
	}
	if a.Outbox == nil || a.Outbox.PendingCount != 0 || a.Outbox.DeadLetterCount != 0 || a.Outbox.ReportedAt.Before(reportedAt) {
		t.Errorf("empty snapshot not stored: %+v", a.Outbox)
	}
}

// A disabled sensor's heartbeat writes nothing, outbox included.
func TestUpdateHeartbeat_OutboxStatsIgnoredForDisabledSensor(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := &SensorRepository{db: &DB{DB: db}}

	tenantID := seedTestTenant(ctx, t, db)
	id := seedSensor(ctx, t, db, tenantID, "offline", nil, "nuclei", 0)
	if _, err := db.ExecContext(ctx, `UPDATE sensors SET status = 'disabled' WHERE id = $1`, id.String()); err != nil {
		t.Fatalf("disable: %v", err)
	}

	ok, err := repo.UpdateHeartbeat(ctx, id, sensor.HeartbeatUpdate{TenantID: &tenantID, Outbox: &sensor.OutboxStats{PendingCount: 1}})
	if err != nil {
		t.Fatalf("UpdateHeartbeat: %v", err)
	}
	if ok {
		t.Fatal("heartbeat updated a disabled sensor")
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensors WHERE id = $1 AND outbox_stats IS NULL AND outbox_reported_at IS NULL`, id.String()).Scan(&n); err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 1 {
		t.Error("outbox columns written for a disabled sensor")
	}
}
