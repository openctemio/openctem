package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RFC-088: a platform-sensor job falls under the per-host politeness keys,
// like a tenant sensor's claim. A pending platform job is not handed out
// while a running command of its tenant holds a conflicting host key (the
// same address, or an address and a range of one /24 bucket); another
// tenant's command never holds it back. Requires DATABASE_URL.
func TestGetNextPlatformJob_HonoursHostKeys(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)
	sensorID := seedJobSensor(ctx, t, db, tenantA)

	withIsolatedPlatformQueue(ctx, t, db, []shared.ID{tenantA, tenantB}, func(tx *sql.Tx) error {
		insert := func(tenant shared.ID, status string, platform bool, keys ...string) shared.ID {
			t.Helper()
			id := shared.NewID()
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO commands (id, tenant_id, type, priority, payload, status, is_platform_job, queue_priority, queued_at, host_keys)
				VALUES ($1, $2, 'scan', 'normal', '{"scanner":"naabu"}'::jsonb, $3, $4, 1, NOW(), $5)`,
				id.String(), tenant.String(), status, platform, pq.Array(keys)); err != nil {
				t.Fatalf("seed command: %v", err)
			}
			return id
		}
		claim := func() shared.ID {
			t.Helper()
			id, err := claimPlatformJobTx(ctx, tx, sensorID, nil, []string{"naabu"})
			if err != nil {
				t.Fatalf("get_next_platform_job: %v", err)
			}
			return id
		}
		setStatus := func(id shared.ID, status string) {
			t.Helper()
			if _, err := tx.ExecContext(ctx, `UPDATE commands SET status = $2 WHERE id = $1`, id.String(), status); err != nil {
				t.Fatal(err)
			}
		}

		// A tenant sensor is port-scanning 198.51.100.0/24 as a range.
		running := insert(tenantA, "running", false, "net:198.51.100.0/24")
		// Another tenant scans the very address the platform job wants.
		insert(tenantB, "running", false, "198.51.100.7", "in:198.51.100.0/24")

		// A platform job for an address inside that range waits.
		job := insert(tenantA, "pending", true, "198.51.100.7", "in:198.51.100.0/24")
		if got := claim(); !got.IsZero() {
			t.Fatalf("claimed %s while a range scan of its bucket runs", got)
		}
		// An address of another bucket is free (tenant B's command does not
		// hold tenant A's job back).
		free := insert(tenantA, "pending", true, "198.51.101.9", "in:198.51.101.0/24")
		if got := claim(); got != free {
			t.Fatalf("claimed %s, want the job of a free bucket %s", got, free)
		}
		// The range scan finishes: the waiting job is handed out.
		setStatus(running, "completed")
		if got := claim(); got != job {
			t.Fatalf("claimed %s after the range scan finished, want %s", got, job)
		}
		// A job without host keys (a passive stage) never waits.
		passive := insert(tenantA, "pending", true)
		if got := claim(); got != passive {
			t.Fatalf("claimed %s, want the job without host keys %s", got, passive)
		}
		return nil
	})
}
