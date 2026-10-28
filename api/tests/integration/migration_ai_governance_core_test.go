package integration

// The AI governance migration copies ai_triage_results into ai_runs and
// ai_suggestions: a run keeps the triage result's id, only the newest
// in-flight row per finding stays in flight (the dedup index allows one), the
// newest completed run's suggestions are open and older ones superseded, and
// a false-positive verdict is stored as lowering risk. Found by name, so the
// merge queue may renumber it. Runs down, legacy rows and up inside one
// transaction that is rolled back, so the shared test database is untouched.

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestMigrationAIGovernanceCore(t *testing.T) {
	url := testdb.URL()
	if url == "" {
		testdb.Skipf(t, "DATABASE_URL not set")
	}
	read := func(suffix string) string {
		t.Helper()
		files, err := filepath.Glob("../../migrations/*_ai_governance_core." + suffix + ".sql")
		if err != nil || len(files) != 1 {
			t.Fatalf("migration file: %v %v", files, err)
		}
		b, err := os.ReadFile(files[0])
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	up, down := read("up"), read("down")

	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := tx.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
		return n
	}

	exec(down)

	tenant, asset, finding := shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tenant, "aigov-"+tenant[24:])
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, $3, 'domain', 'active')`,
		asset, tenant, "aigov-"+tenant[24:]+".example.com")
	exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'sast', 't', 'm', 'medium', $1::text, 'new')`, finding, tenant, asset)

	oldDone, newDone, pend1, pend2 := shared.NewID().String(), shared.NewID().String(), shared.NewID().String(), shared.NewID().String()
	exec(`INSERT INTO ai_triage_results (id, tenant_id, finding_id, triage_type, status, completed_at, created_at,
			llm_provider, llm_model, prompt_tokens, completion_tokens, analysis_summary, remediation_steps,
			false_positive_likelihood, false_positive_reason, severity_assessment, severity_justification)
		VALUES ($1, $2, $3, 'manual', 'completed', now() - interval '2 days', now() - interval '2 days',
			'claude', 'm1', 10, 5, 'old summary', '[{"step":1,"description":"patch","effort":"low"}]', 0.1, '', 'medium', ''),
		       ($4, $2, $3, 'auto', 'completed', now() - interval '1 day', now() - interval '1 day',
			'claude', 'm1', 10, 5, 'new summary', '[{"step":1,"description":"patch","effort":"low"}]', 0.95, 'test fixture',
			'high', 'exposed')`, oldDone, tenant, finding, newDone)
	exec(`INSERT INTO ai_triage_results (id, tenant_id, finding_id, triage_type, status, created_at)
		VALUES ($1, $3, $4, 'manual', 'pending', now() - interval '1 hour'), ($2, $3, $4, 'manual', 'pending', now())`,
		pend1, pend2, tenant, finding)

	exec(up)

	if n := count(`SELECT count(*) FROM ai_runs WHERE tenant_id = $1`, tenant); n != 4 {
		t.Fatalf("runs = %d, want 4 (one per triage result)", n)
	}
	if n := count(`SELECT count(*) FROM ai_runs WHERE id = $1 AND status = 'pending'`, pend2); n != 1 {
		t.Fatal("the newest pending row must stay pending")
	}
	if n := count(`SELECT count(*) FROM ai_runs WHERE id = $1 AND status = 'failed' AND error_code = 'superseded'`, pend1); n != 1 {
		t.Fatal("an older pending row must be recorded failed/superseded")
	}
	if n := count(`SELECT count(*) FROM ai_runs WHERE id = $1 AND provider = 'claude' AND tokens_in = 10 AND trigger = 'on_ingest'`, newDone); n != 1 {
		t.Fatal("provenance and trigger must be copied")
	}
	if n := count(`SELECT count(*) FROM ai_suggestions WHERE run_id = $1 AND state = 'superseded'`, oldDone); n != 2 {
		t.Fatalf("older run: %d superseded suggestions, want 2 (steps, summary)", n)
	}
	if n := count(`SELECT count(*) FROM ai_suggestions WHERE run_id = $1 AND state = 'open'`, newDone); n != 4 {
		t.Fatalf("newest run: %d open suggestions, want 4 (steps, summary, verdict, severity)", n)
	}
	if n := count(`SELECT count(*) FROM ai_suggestions WHERE run_id = $1 AND kind = 'verdict' AND direction = 'lowers_risk'`, newDone); n != 1 {
		t.Fatal("a false-positive verdict lowers risk")
	}
	if n := count(`SELECT count(*) FROM ai_suggestions WHERE run_id = $1 AND kind = 'severity' AND direction = 'raises_risk'`, newDone); n != 1 {
		t.Fatal("medium to high raises risk")
	}
	// The finding itself is untouched.
	if n := count(`SELECT count(*) FROM findings WHERE id = $1 AND severity = 'medium' AND status = 'new'`, finding); n != 1 {
		t.Fatal("the migration must not change the finding")
	}
	// One in-flight run per subject.
	if _, err := tx.ExecContext(ctx, `SAVEPOINT dup`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO ai_runs (tenant_id, use_case, kind, subject_type, subject_id, status)
		VALUES ($1, 'triage', 'triage.v1', 'finding', $2, 'running')`, tenant, finding); err == nil {
		t.Fatal("a second in-flight run for the same subject must be refused")
	}
	if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT dup`); err != nil {
		t.Fatal(err)
	}

	exec(down)
	if n := count(`SELECT count(*) FROM ai_triage_results WHERE tenant_id = $1`, tenant); n != 4 {
		t.Fatal("down must keep ai_triage_results")
	}
}
