package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Shared platform sensors are shared fairly across tenants (RFC-046 §11,
// RFC-030 §5.7): within a priority class, the tenant with the fewest platform
// jobs in flight goes first, whatever queue_priority says; a higher class
// still goes first. Requires DATABASE_URL (CI applies every migration first).
//
// The platform queue is global, and other tests on the same database leave
// claimable platform jobs (a pending job with no scanner matches every
// claim). So the test runs in one REPEATABLE READ transaction that is rolled
// back: it seeds its jobs, hides the other claimable platform jobs inside the
// transaction (never committed, so no other test sees the change), and claims
// through get_next_platform_job in the same transaction. Rows other tests
// commit meanwhile are not in its snapshot.
func TestGetNextPlatformJob_TenantFairShare(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	busy := seedTestTenant(ctx, t, db)
	quiet := seedTestTenant(ctx, t, db)
	sensorID := seedJobSensor(ctx, t, db, busy)

	// A concurrent writer can touch a row this test hides after its snapshot
	// (serialization failure): the attempt is rolled back and run again.
	for attempt := 1; ; attempt++ {
		err := fairShareAttempt(ctx, t, db, busy, quiet, sensorID)
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "40001" && attempt < 5 {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		return
	}
}

func fairShareAttempt(ctx context.Context, t *testing.T, db *sql.DB, busy, quiet, sensorID shared.ID) error {
	t.Helper()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

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

	// Hide every other claimable platform job, in this transaction only.
	if _, err := tx.ExecContext(ctx, `
		UPDATE commands SET is_platform_job = FALSE
		WHERE is_platform_job = TRUE AND status = 'pending' AND platform_sensor_id IS NULL
		  AND tenant_id <> ALL($1::uuid[])`,
		pq.Array([]string{busy.String(), quiet.String()})); err != nil {
		return err
	}

	claim := func() (shared.ID, error) {
		var id sql.NullString
		if err := tx.QueryRowContext(ctx,
			`SELECT command_id FROM get_next_platform_job($1, NULL, NULL)`, sensorID.String()).Scan(&id); err != nil {
			return shared.ID{}, err
		}
		if !id.Valid {
			return shared.ID{}, errors.New("no platform job claimed")
		}
		return shared.IDFromString(id.String)
	}
	for _, want := range []struct {
		id  shared.ID
		why string
	}{
		{busyHigh, "the busy tenant's high-priority job first"},
		{quietNext, "the quiet tenant's job before the busy tenant's normal one"},
		{busyNext, "the busy tenant's normal job last"},
	} {
		got, err := claim()
		if err != nil {
			return err
		}
		if got != want.id {
			t.Fatalf("claimed %s, want %s (%s)", got, want.id, want.why)
		}
	}
	return nil
}
