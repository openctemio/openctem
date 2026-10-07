package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/workflow"
)

// The loop-guard and cleanup queries of automation runs (research/61 P0-4),
// against real Postgres: the subject cooldown, the latest outcomes that pause
// a failing automation, and the reaper of runs a restart left open.

func TestWorkflowRunGuards_DB(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	tenant := seedScanTriggerTenant(ctx, t, db)
	other := seedScanTriggerTenant(ctx, t, db)
	repo := NewWorkflowRunRepository(&DB{DB: db})
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	mkWF := func(tn shared.ID) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO workflows (id, tenant_id, name) VALUES ($1, $2, $3)`, id.String(), tn.String(), "guard-"+id.String())
		return id
	}
	mkRun := func(tn, wf shared.ID, status, trigger string, subject *shared.ID, age time.Duration, msg string) shared.ID {
		id := shared.NewID()
		var subj any
		if subject != nil {
			subj = subject.String()
		}
		exec(`INSERT INTO workflow_runs (id, workflow_id, tenant_id, trigger_type, status, subject_id, error_message, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, NOW() - $8::interval)`,
			id.String(), wf.String(), tn.String(), trigger, status, subj, msg, age.String())
		return id
	}

	t.Run("subject cooldown", func(t *testing.T) {
		wf, subject := mkWF(tenant), shared.NewID()
		mkRun(tenant, wf, "completed", "finding_status_changed", &subject, 5*time.Minute, "")
		since := time.Now().Add(-10 * time.Minute)
		check := func(tn, w, s shared.ID, tt workflow.TriggerType) bool {
			found, err := repo.HasRecentSubjectRun(ctx, tn, w, s, tt, since)
			if err != nil {
				t.Fatal(err)
			}
			return found
		}
		if !check(tenant, wf, subject, workflow.TriggerTypeFindingStatusChanged) {
			t.Error("a run 5 minutes ago is inside a 10 minute cooldown")
		}
		if check(tenant, wf, shared.NewID(), workflow.TriggerTypeFindingStatusChanged) ||
			check(tenant, wf, subject, workflow.TriggerTypeAITriageCompleted) ||
			check(other, wf, subject, workflow.TriggerTypeFindingStatusChanged) {
			t.Error("cooldown matched another subject, trigger or tenant")
		}
		if found, _ := repo.HasRecentSubjectRun(ctx, tenant, wf, subject, workflow.TriggerTypeFindingStatusChanged, time.Now().Add(-time.Minute)); found {
			t.Error("a run 5 minutes ago is outside a 1 minute cooldown")
		}
	})

	t.Run("latest outcomes leave out throttled records", func(t *testing.T) {
		wf := mkWF(tenant)
		mkRun(tenant, wf, "completed", "manual", nil, 3*time.Hour, "")
		mkRun(tenant, wf, "failed", "manual", nil, 2*time.Hour, "boom")
		mkRun(tenant, wf, "failed", "manual", nil, time.Hour, workflow.ThrottledRunPrefix+"over quota")
		mkRun(tenant, wf, "running", "manual", nil, time.Minute, "")
		got, err := repo.LatestOutcomes(ctx, tenant, wf, 20)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0] != workflow.RunStatusFailed || got[1] != workflow.RunStatusCompleted {
			t.Fatalf("outcomes = %v, want [failed completed]", got)
		}
		if other, _ := repo.LatestOutcomes(ctx, other, wf, 20); len(other) != 0 {
			t.Fatalf("another tenant read %v", other)
		}
	})

	t.Run("reaper ends only stale open runs, with their steps", func(t *testing.T) {
		wf := mkWF(tenant)
		stale := mkRun(tenant, wf, "running", "manual", nil, 2*time.Hour, "")
		waiting := mkRun(tenant, wf, "pending", "manual", nil, 3*time.Hour, "")
		fresh := mkRun(tenant, wf, "running", "manual", nil, 5*time.Minute, "")
		done := mkRun(tenant, wf, "completed", "manual", nil, 5*time.Hour, "")
		node, step, doneStep := shared.NewID(), shared.NewID(), shared.NewID()
		exec(`INSERT INTO workflow_nodes (id, workflow_id, node_key, node_type, name) VALUES ($1, $2, 'a', 'action', 'a')`, node.String(), wf.String())
		exec(`INSERT INTO workflow_node_runs (id, workflow_run_id, node_id, node_key, node_type, status) VALUES ($1, $2, $3, 'a', 'action', 'running')`,
			step.String(), stale.String(), node.String())
		exec(`INSERT INTO workflow_node_runs (id, workflow_run_id, node_id, node_key, node_type, status) VALUES ($1, $2, $3, 'a', 'action', 'completed')`,
			doneStep.String(), done.String(), node.String())

		n, err := repo.FailStaleRuns(ctx, time.Now().Add(-time.Hour), "interrupted")
		if err != nil {
			t.Fatal(err)
		}
		if n < 2 {
			t.Fatalf("ended %d runs, want at least the two stale ones", n)
		}
		status := func(table string, id shared.ID) string {
			var s string
			if err := db.QueryRowContext(ctx, `SELECT status FROM `+table+` WHERE id = $1`, id.String()).Scan(&s); err != nil {
				t.Fatal(err)
			}
			return s
		}
		for id, want := range map[shared.ID]string{stale: "failed", waiting: "failed", fresh: "running", done: "completed"} {
			if got := status("workflow_runs", id); got != want {
				t.Errorf("run %s = %s, want %s", id, got, want)
			}
		}
		if got := status("workflow_node_runs", step); got != "failed" {
			t.Errorf("open step of a reaped run = %s, want failed", got)
		}
		if got := status("workflow_node_runs", doneStep); got != "completed" {
			t.Errorf("finished step = %s, must not change", got)
		}
	})
}
