package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Shared platform sensors are shared fairly across tenants (RFC-046 §11,
// RFC-030 §5.7): within a priority class, the tenant with the fewest platform
// jobs in flight goes first, whatever queue_priority says; a higher class
// still goes first. Requires DATABASE_URL (CI applies every migration first).
// Runs on a queue isolated from other tests (withIsolatedPlatformQueue).
func TestGetNextPlatformJob_TenantFairShare(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	busy := seedTestTenant(ctx, t, db)
	quiet := seedTestTenant(ctx, t, db)
	sensorID := seedJobSensor(ctx, t, db, busy)

	withIsolatedPlatformQueue(ctx, t, db, []shared.ID{busy, quiet}, func(tx *sql.Tx) error {
		seed := func(tenant shared.ID, priority, status string, queuePriority int) (shared.ID, error) {
			id := shared.NewID()
			_, err := tx.ExecContext(ctx, `
				INSERT INTO commands (id, tenant_id, type, priority, payload, status, is_platform_job, queue_priority, queued_at,
				                      platform_sensor_id, acknowledged_at)
				VALUES ($1, $2, 'scan', $3, '{"kind":"fair-share-test"}'::jsonb, $4::text, TRUE, $5, NOW(),
				        CASE WHEN $4::text = 'pending' THEN NULL ELSE $6::uuid END,
				        CASE WHEN $4::text = 'pending' THEN NULL ELSE NOW() END)`,
				id.String(), tenant.String(), priority, status, queuePriority, sensorID.String())
			return id, err
		}
		// busy already runs three platform jobs and has the higher queue_priority.
		for i := 0; i < 3; i++ {
			if _, err := seed(busy, "normal", "running", 0); err != nil {
				return err
			}
		}
		busyNext, err := seed(busy, "normal", "pending", 950000002)
		if err != nil {
			return err
		}
		quietNext, err := seed(quiet, "normal", "pending", 950000001)
		if err != nil {
			return err
		}
		// A higher class from the busy tenant still goes first.
		busyHigh, err := seed(busy, "high", "pending", 1)
		if err != nil {
			return err
		}

		for _, want := range []struct {
			id  shared.ID
			why string
		}{
			{busyHigh, "the busy tenant's high-priority job first"},
			{quietNext, "the quiet tenant's job before the busy tenant's normal one"},
			{busyNext, "the busy tenant's normal job last"},
		} {
			got, err := claimPlatformJobTx(ctx, tx, sensorID, nil, nil)
			if err != nil {
				return err
			}
			if got.IsZero() {
				return errors.New("no platform job claimed")
			}
			if got != want.id {
				t.Fatalf("claimed %s, want %s (%s)", got, want.id, want.why)
			}
		}
		return nil
	})
}
