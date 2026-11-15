package integration

// Migrations ai_run_injection_flag and ai_runs_worker_live_index
// (docs/architecture/ai-analysis.md, "Runs on an AI worker"): the run's
// stored injection flag (false for every existing run) and the index of the
// deadline sweep. Up, down, up again.

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/server/internal/testdb"
)

func TestMigrationAIRunInjectionFlag(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "migaiinject", dir)
	vFlag := testdb.MigrationVersion(t, dir, "ai_run_injection_flag")
	vIndex := testdb.MigrationVersion(t, dir, "ai_runs_worker_live_index")
	ctx := context.Background()

	tenant := uuid.NewString()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tenant, "inject-"+tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO ai_runs (tenant_id, use_case, kind, subject_type, subject_id, executor, status)
		VALUES ($1, 'triage', 'triage.legacy', 'finding', $2, 'tenant_worker', 'queued')`, tenant, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	var flag bool
	if err := db.QueryRowContext(ctx, `SELECT injection_suspected FROM ai_runs WHERE tenant_id = $1`, tenant).Scan(&flag); err != nil || flag {
		t.Fatalf("a run without the flag reads %v (%v), want false", flag, err)
	}
	indexed := func() bool {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_indexes WHERE indexname = 'idx_ai_runs_worker_live'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	if !indexed() {
		t.Fatal("the worker run index is missing")
	}

	testdb.Migrate(t, db, dir, vIndex, vIndex, true)
	if indexed() {
		t.Fatal("after down: the worker run index is still there")
	}
	testdb.Migrate(t, db, dir, vFlag, vFlag, true)
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_name = 'ai_runs' AND column_name = 'injection_suspected'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("after down: injection_suspected still there (%d, %v)", n, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM ai_runs WHERE tenant_id = $1`, tenant).Scan(&n); err != nil || n != 1 {
		t.Fatalf("after down: %d runs (%v), want the run kept", n, err)
	}

	testdb.Migrate(t, db, dir, vFlag, vFlag, false)
	testdb.Migrate(t, db, dir, vIndex, vIndex, false)
	if !indexed() {
		t.Fatal("after up again: the worker run index is missing")
	}
}
