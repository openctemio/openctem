package integration

// Migration analyze_command_type (docs/rfcs/RFC-131-ai-analysis.md §5): the
// 'analyze' command type, the run ledger rule for runs on an AI worker (a
// worker run gets its sensor when a worker claims the job) and
// ai_runs.result_digest. Up, down, up again.

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/server/internal/testdb"
)

func TestMigrationAnalyzeCommandType(t *testing.T) {
	const dir = "../../migrations"
	db := testdb.PrivateDatabase(t, "miganalyze", dir)
	v := testdb.MigrationVersion(t, dir, "analyze_command_type")
	ctx := context.Background()

	tenant := uuid.NewString()
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tenant, "analyze-"+tenant); err != nil {
		t.Fatal(err)
	}
	// run inserts one run; the kind is legacy so no AI agent row is needed.
	run := func(executor, status string, sensor bool, digest string) error {
		var sensorID, resultDigest any
		if sensor {
			sensorID = uuid.NewString()
		}
		if digest != "" {
			resultDigest = digest
		}
		cols, vals := "", ""
		args := []any{tenant, uuid.NewString(), executor, status, sensorID}
		if digest != "" {
			cols, vals = ", result_digest", ", $6"
			args = append(args, resultDigest)
		}
		_, err := db.ExecContext(ctx, `INSERT INTO ai_runs (tenant_id, use_case, kind, subject_type, subject_id, executor, status, sensor_id`+cols+`)
			VALUES ($1, 'triage', 'triage.legacy', 'finding', $2, $3, $4, $5`+vals+`)`, args...)
		return err
	}
	wantCheck := func(err error, constraint, what string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), constraint) {
			t.Fatalf("%s: got %v, want a %s violation", what, err, constraint)
		}
	}
	okDigest := "sha256:" + strings.Repeat("ab", 32)

	// A queued worker run has no sensor yet; one that ended before a worker
	// claimed it neither.
	for _, st := range []string{"queued", "canceled", "refused", "failed"} {
		if err := run("tenant_worker", st, false, ""); err != nil {
			t.Fatalf("%s tenant_worker run without a sensor refused: %v", st, err)
		}
	}
	if err := run("platform_worker", "queued", false, ""); err != nil {
		t.Fatalf("queued platform_worker run without a sensor refused: %v", err)
	}
	// Running, waiting or completed on a worker needs the worker.
	for _, st := range []string{"running", "waiting_tool", "waiting_approval", "completed"} {
		wantCheck(run("tenant_worker", st, false, ""), "chk_ai_runs_worker", st+" worker run without a sensor")
	}
	if err := run("tenant_worker", "completed", true, okDigest); err != nil {
		t.Fatalf("completed worker run with a sensor and a result digest refused: %v", err)
	}
	// Built-in and external runs never name a sensor.
	for _, ex := range []string{"builtin", "external"} {
		wantCheck(run(ex, "queued", true, ""), "chk_ai_runs_worker", ex+" run with a sensor")
		if err := run(ex, "completed", false, ""); err != nil {
			t.Fatalf("%s run without a sensor refused: %v", ex, err)
		}
	}
	for _, bad := range []string{"sha256:ABC", "md5:" + strings.Repeat("a", 64), strings.Repeat("a", 64)} {
		wantCheck(run("tenant_worker", "completed", true, bad), "chk_ai_runs_result_digest", "result digest "+bad)
	}
	// The command type.
	if _, err := db.ExecContext(ctx, `INSERT INTO commands (tenant_id, type, status, payload) VALUES ($1, 'analyze', 'pending', '{}')`, tenant); err != nil {
		t.Fatalf("analyze command refused: %v", err)
	}
	wantCheck(func() error {
		_, err := db.ExecContext(ctx, `INSERT INTO commands (tenant_id, type, status, payload) VALUES ($1, 'analyse', 'pending', '{}')`, tenant)
		return err
	}(), "chk_command_type", "unknown command type")

	// Down: the rows the old checks cannot hold go, the old checks are back
	// and validated.
	testdb.Migrate(t, db, dir, v, v, true)
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM commands WHERE type = 'analyze'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("after down: %d analyze commands (%v)", n, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM ai_runs WHERE executor IN ('platform_worker', 'tenant_worker') AND sensor_id IS NULL`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("after down: %d worker runs without a sensor (%v)", n, err)
	}
	wantCheck(run("tenant_worker", "queued", false, ""), "chk_ai_runs_worker", "after down: queued worker run without a sensor")
	var validated bool
	if err := db.QueryRowContext(ctx, `SELECT bool_and(convalidated) FROM pg_constraint
		WHERE conname IN ('chk_ai_runs_worker', 'chk_command_type')`).Scan(&validated); err != nil || !validated {
		t.Fatalf("after down: checks not validated (%v)", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_name = 'ai_runs' AND column_name = 'result_digest'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("after down: result_digest still there (%d, %v)", n, err)
	}

	testdb.Migrate(t, db, dir, v, v, false)
	if err := run("tenant_worker", "queued", false, ""); err != nil {
		t.Fatalf("after up again: queued worker run without a sensor refused: %v", err)
	}
}
