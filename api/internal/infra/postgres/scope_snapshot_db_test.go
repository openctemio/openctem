package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Scope snapshots (migration 001495): one body per (tenant, hash), one link
// per run, read back only by the run's tenant; a run of another tenant
// cannot be linked. Requires DATABASE_URL.
func TestScopeSnapshotRepository(t *testing.T) {
	db, pdb := openBatchDedupDB(t)
	ctx := context.Background()
	tenant := seedBatchTenant(t, db)
	other := seedBatchTenant(t, db)
	repo := NewScopeSnapshotRepository(pdb)

	run := func(tid shared.ID) shared.ID {
		tpl, id := shared.NewID(), shared.NewID()
		hopExec(t, db, `INSERT INTO scan_workflows (id, tenant_id, name) VALUES ($1, $2, $3)`, tpl, tid, "snap "+tpl.String())
		hopExec(t, db, `INSERT INTO scan_runs (id, scan_workflow_id, tenant_id, trigger_type, status) VALUES ($1, $2, $3, 'manual', 'running')`, id, tpl, tid)
		t.Cleanup(func() {
			_, _ = db.ExecContext(context.Background(), `DELETE FROM scan_runs WHERE id = $1`, id.String())
			_, _ = db.ExecContext(context.Background(), `DELETE FROM scan_workflows WHERE id = $1`, tpl.String())
		})
		return id
	}
	r1, r2, foreign := run(tenant), run(tenant), run(other)
	sum := strings.Repeat("a", 64)
	body := []byte(`{"version":1}`)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := repo.Record(ctx, tenant, r1, sum, body, now); err != nil {
		t.Fatal(err)
	}
	if err := repo.Record(ctx, tenant, r2, sum, body, now); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM scope_snapshots WHERE tenant_id = $1`, tenant.String()).Scan(&n)
	if n != 1 {
		t.Fatalf("one body per hash: %d", n)
	}
	got, err := repo.GetForRun(ctx, tenant, r2)
	if err != nil || got.SHA256 != sum || len(got.Body) == 0 {
		t.Fatalf("get: %+v %v", got, err)
	}
	if _, err := repo.GetForRun(ctx, other, r1); !errors.Is(err, ErrScopeSnapshotNotFound) {
		t.Fatalf("another tenant must not read the snapshot: %v", err)
	}
	// Linking another tenant's run fails on the composite key.
	if err := repo.Record(ctx, tenant, foreign, sum, body, now); err == nil {
		t.Fatal("a run of another tenant must not be linked")
	}
}
