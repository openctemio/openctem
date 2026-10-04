package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Shared platform sensors are shared fairly across tenants (RFC-046 §11,
// RFC-030 §5.7): within a priority class, the tenant with the fewest platform
// jobs in flight goes first, whatever queue_priority says; a higher class
// still goes first. Requires DATABASE_URL (CI applies every migration first).
func TestGetNextPlatformJob_TenantFairShare(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, db)()
	repo := NewCommandRepository(&DB{DB: db})
	busy := seedTestTenant(ctx, t, db)
	quiet := seedTestTenant(ctx, t, db)
	sensorID := seedJobSensor(ctx, t, db, busy)

	seed := func(tenant shared.ID, priority, status string, queuePriority int) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `
			INSERT INTO commands (id, tenant_id, type, priority, payload, status, is_platform_job, queue_priority, queued_at,
			                      platform_sensor_id, acknowledged_at)
			VALUES ($1, $2, 'scan', $3, '{"kind":"fair-share-test"}'::jsonb, $4::text, TRUE, $5, NOW(),
			        CASE WHEN $4::text = 'pending' THEN NULL ELSE $6::uuid END,
			        CASE WHEN $4::text = 'pending' THEN NULL ELSE NOW() END)`,
			id.String(), tenant.String(), priority, status, queuePriority, sensorID.String()); err != nil {
			t.Fatalf("seed platform job: %v", err)
		}
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM commands WHERE id = $1`, id.String())
		})
		return id
	}
	claim := func() shared.ID {
		t.Helper()
		cmd, err := repo.GetNextPlatformJob(ctx, sensorID, nil, nil)
		if err != nil || cmd == nil {
			t.Fatalf("GetNextPlatformJob = %v, %v", cmd, err)
		}
		return cmd.ID
	}

	// busy already runs three platform jobs and has the higher queue_priority.
	for i := 0; i < 3; i++ {
		seed(busy, "normal", "running", 0)
	}
	busyNext := seed(busy, "normal", "pending", 950000002)
	quietNext := seed(quiet, "normal", "pending", 950000001)
	// A higher class from the busy tenant still goes first.
	busyHigh := seed(busy, "high", "pending", 1)

	if got := claim(); got != busyHigh {
		t.Fatalf("claimed %s, want the busy tenant's high-priority job %s first", got, busyHigh)
	}
	if got := claim(); got != quietNext {
		t.Fatalf("claimed %s, want the quiet tenant's job %s before the busy tenant's %s", got, quietNext, busyNext)
	}
	if got := claim(); got != busyNext {
		t.Fatalf("claimed %s, want the busy tenant's job %s last", got, busyNext)
	}
}
