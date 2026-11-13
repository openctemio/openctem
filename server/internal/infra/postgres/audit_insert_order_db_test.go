package postgres

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Every audit insert takes the tenant's chain lock until its transaction
// ends. The hourly expiry sweeps insert audit rows for many tenants in one
// statement, so they must take those locks in the order every other writer
// does (tenant ascending), or a sweep and a writer holding two tenants'
// locks in opposite orders deadlock.
//
// The test lays the approvals out so the sweep's natural scan order is
// descending by tenant, holds the lower tenant's chain lock in a writer
// transaction, waits until the sweep is blocked on a chain lock, and then
// lets the writer take the higher tenant's lock. Unordered, the sweep holds
// the higher tenant and waits for the lower one: deadlock. Ordered, it waits
// on the lower tenant first and both finish.
func TestAuditInsertOrder_SweepDoesNotDeadlockWithWriter_DB(t *testing.T) {
	db := testdb.PrivateDatabase(t, "audit_order", "../../../migrations")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tenants := []string{shared.NewID().String(), shared.NewID().String()}
	sort.Strings(tenants)
	lo, hi := tenants[0], tenants[1]
	for _, id := range []string{hi, lo} { // heap order: hi first
		mustExec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$2)`, id, "ord-"+id[24:])
		aid, fid := shared.NewID().String(), shared.NewID().String()
		mustExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1,$2,'a.example.com','domain')`, aid, id)
		mustExec(t, db, `INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
			VALUES ($1::uuid, $2, $3, 'sast', 't', 'm', 'high', $1::text, 'new')`, fid, id, aid)
		mustExec(t, db, `INSERT INTO finding_status_approvals (id, tenant_id, finding_id, requested_status, justification, status, decide_by)
			VALUES ($1,$2,$3,'false_positive','r','pending', NOW() - INTERVAL '1 hour')`, shared.NewID().String(), id, fid)
	}
	wtx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wtx.Rollback() }()
	insert := func(tenant string) error {
		_, err := wtx.ExecContext(ctx, `INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, result, severity, message, logged_at)
			VALUES (gen_random_uuid(), $1, 'test.writer', 'finding', 'x', 'success', 'low', 'm', NOW())`, tenant)
		return err
	}
	if err := insert(lo); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var sweepErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, sweepErr = NewFindingApprovalRepository(&DB{DB: db}).ExpireOverdueRequests(ctx)
	}()

	// Wait until the sweep waits on a chain lock held by the writer.
	deadline := time.Now().Add(20 * time.Second)
	for {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the sweep never waited on a chain lock")
		}
		time.Sleep(20 * time.Millisecond)
	}

	writerErr := insert(hi)
	if writerErr == nil {
		writerErr = wtx.Commit()
	}
	wg.Wait()
	if writerErr != nil {
		t.Errorf("writer: %v", writerErr)
	}
	if sweepErr != nil {
		t.Errorf("sweep: %v", sweepErr)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_logs WHERE action = 'finding_approval.expired'`).Scan(&n); err != nil || n != 2 {
		t.Errorf("expired audit rows = %d (err %v), want 2", n, err)
	}
}
