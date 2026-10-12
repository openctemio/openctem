package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// withIsolatedPlatformQueue runs fn in one REPEATABLE READ transaction that is
// always rolled back, with the platform queue reduced to the given tenants.
//
// The platform queue is global: get_next_platform_job takes the best pending
// platform job of any tenant, and a job with no scanner, tool or required
// capability matches every claim, so no claim argument can exclude it. Other
// tests on the same database leave such jobs pending while they run, so a
// claim test that runs on the shared queue picks them up depending on test
// order and parallelism. Inside the transaction every other claimable platform
// job is hidden (is_platform_job = FALSE, never committed, so no other test
// sees the change), and rows other tests commit later are outside the
// snapshot. fn seeds its jobs and claims through get_next_platform_job on tx.
//
// A concurrent writer can touch a hidden row after the snapshot was taken
// (serialization failure); the attempt is rolled back and run again.
func withIsolatedPlatformQueue(ctx context.Context, t *testing.T, db *sql.DB, tenants []shared.ID, fn func(tx *sql.Tx) error) {
	t.Helper()
	ids := make([]string, len(tenants))
	for i, id := range tenants {
		ids[i] = id.String()
	}
	for attempt := 1; ; attempt++ {
		err := isolatedPlatformQueueAttempt(ctx, db, ids, fn)
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

func isolatedPlatformQueueAttempt(ctx context.Context, db *sql.DB, tenants []string, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		UPDATE commands SET is_platform_job = FALSE
		WHERE is_platform_job = TRUE AND status = 'pending' AND platform_sensor_id IS NULL
		  AND tenant_id <> ALL($1::uuid[])`,
		pq.Array(tenants)); err != nil {
		return err
	}
	return fn(tx)
}

// claimPlatformJobTx claims through get_next_platform_job on tx and returns
// the claimed command id, or the zero ID when nothing matched.
func claimPlatformJobTx(ctx context.Context, tx *sql.Tx, sensorID shared.ID, caps, tools []string) (shared.ID, error) {
	var id sql.NullString
	if err := tx.QueryRowContext(ctx,
		`SELECT command_id FROM get_next_platform_job($1, $2, $3)`,
		sensorID.String(), pq.Array(caps), pq.Array(tools)).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return shared.ID{}, nil
		}
		return shared.ID{}, err
	}
	if !id.Valid {
		return shared.ID{}, nil
	}
	return shared.IDFromString(id.String)
}
