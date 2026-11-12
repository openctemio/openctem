package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A deadlock is retried once; any other error, and a second deadlock, are
// returned.
func TestRetryOnDeadlock(t *testing.T) {
	ctx := context.Background()
	calls := 0
	dead := &pq.Error{Code: deadlockDetected}
	if err := retryOnDeadlock(ctx, func() error {
		calls++
		if calls == 1 {
			return dead
		}
		return nil
	}); err != nil || calls != 2 {
		t.Fatalf("retried deadlock: err %v after %d calls", err, calls)
	}
	calls = 0
	if err := retryOnDeadlock(ctx, func() error { calls++; return dead }); !errors.As(err, new(*pq.Error)) || calls != 2 {
		t.Fatalf("second deadlock: err %v after %d calls", err, calls)
	}
	calls = 0
	other := errors.New("boom")
	if err := retryOnDeadlock(ctx, func() error { calls++; return other }); !errors.Is(err, other) || calls != 1 {
		t.Fatalf("other error retried: %d calls", calls)
	}
}

// lockAssetsInOrder is the asset business-context update's lock pattern.
func lockAssetsInOrder(ctx context.Context, tx *sql.Tx, tenant shared.ID, ids []string) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, criticality FROM assets
		WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL ORDER BY id FOR UPDATE`,
		tenant.String(), pq.Array(ids))
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
	}
	return rows.Err()
}

// The ledger reconcile and a writer that locks the same assets FOR UPDATE in
// id order (the asset business-context update) run concurrently without a
// deadlock: the reconcile takes the foreign key's key-share locks in id
// order, in short batches. Before, both deadlocked on live.
func TestAssetCoverageReconcile_NoDeadlockWithOrderedAssetLocks(t *testing.T) {
	db := openHopDB(t)
	repo := NewAssetCoverageRepository(&DB{DB: db})
	ctx := context.Background()
	h := newHopTenant(t, db, 0)
	const n = 1200 // more than two reconcile batches
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id := shared.NewID()
		hopExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type, properties) VALUES ($1, $2, $3, 'subdomain',
			'{"dns_records": [{"type": "A", "value": "203.0.113.9"}]}')`, id, h.tenant, fmt.Sprintf("n%04d.dl.test", i))
		ids = append(ids, id.String())
	}
	rules := coverage.Rules()

	deadline := time.Now().Add(4 * time.Second)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() { // A: the business-context update's lock pattern
		defer wg.Done()
		for time.Now().Before(deadline) {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				errs <- err
				return
			}
			err = lockAssetsInOrder(ctx, tx, h.tenant, ids)
			if err == nil {
				_, err = tx.ExecContext(ctx, `UPDATE assets SET criticality = 'high' WHERE tenant_id = $1 AND id = ANY($2)`,
					h.tenant.String(), pq.Array(ids))
			}
			if err != nil {
				_ = tx.Rollback()
				errs <- fmt.Errorf("writer: %w", err)
				return
			}
			if err := tx.Commit(); err != nil {
				errs <- err
				return
			}
		}
	}()
	go func() { // B: reconcile from scratch, again and again
		defer wg.Done()
		for time.Now().Before(deadline) {
			if _, err := db.ExecContext(ctx, `DELETE FROM asset_coverage WHERE tenant_id = $1`, h.tenant.String()); err != nil {
				errs <- err
				return
			}
			if _, _, err := repo.Reconcile(ctx, h.tenant, rules); err != nil {
				errs <- fmt.Errorf("reconcile: %w", err)
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var rows int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM asset_coverage WHERE tenant_id = $1 AND capability = 'probe.http'`, h.tenant.String()).Scan(&rows)
	if rows != n {
		t.Fatalf("probe.http rows = %d, want %d (every batch reconciled)", rows, n)
	}
}
