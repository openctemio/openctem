package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/workflow"
)

// Automation run creation (research/61 P0-2): one run per event (the
// idempotency key), bounded per automation and per tenant per hour, with a
// visible record when events were dropped. Against real Postgres.

func newLimitRun(t *testing.T, tenant, wf shared.ID, key string) *workflow.Run {
	t.Helper()
	r, err := workflow.NewRun(wf, tenant, workflow.TriggerTypeFindingCreated, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	subject := shared.NewID()
	r.SetSubject(&subject, key)
	r.Status = workflow.RunStatusCompleted // keep the active caps out of the quota test
	return r
}

func TestWorkflowRunLimits_IdempotencyAndQuota_DB(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	tenant := seedScanTriggerTenant(ctx, t, db)
	other := seedScanTriggerTenant(ctx, t, db)
	repo := NewWorkflowRunRepository(&DB{DB: db})
	mkWF := func(tn shared.ID) shared.ID {
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO workflows (id, tenant_id, name) VALUES ($1, $2, $3)`, id.String(), tn.String(), "limits-"+id.String()); err != nil {
			t.Fatal(err)
		}
		return id
	}
	wf := mkWF(tenant)

	// The same event twice: one run.
	if err := repo.CreateRunIfUnderLimit(ctx, newLimitRun(t, tenant, wf, "finding_created:x"), 1000, 1000); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := repo.CreateRunIfUnderLimit(ctx, newLimitRun(t, tenant, wf, "finding_created:x"), 1000, 1000); !errors.Is(err, workflow.ErrRunDuplicate) {
		t.Fatalf("same key again = %v, want ErrRunDuplicate", err)
	}
	// The key is per automation: another automation of the tenant runs.
	if err := repo.CreateRunIfUnderLimit(ctx, newLimitRun(t, tenant, mkWF(tenant), "finding_created:x"), 1000, 1000); err != nil {
		t.Fatalf("same key, other automation: %v", err)
	}
	// Another tenant's workflow id is refused (the lock reads it by tenant).
	if err := repo.CreateRunIfUnderLimit(ctx, newLimitRun(t, other, wf, "k"), 1000, 1000); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("run of another tenant's workflow = %v, want ErrNotFound", err)
	}

	// Fill the hourly quota (one run exists already).
	for i := 1; i < workflow.MaxRunsPerWorkflowPerHour; i++ {
		if err := repo.CreateRunIfUnderLimit(ctx, newLimitRun(t, tenant, wf, ""), 1000, 1000); err != nil {
			t.Fatalf("run %d under the quota: %v", i, err)
		}
	}
	for range 3 {
		if err := repo.CreateRunIfUnderLimit(ctx, newLimitRun(t, tenant, wf, ""), 1000, 1000); !workflow.IsRunThrottled(err) {
			t.Fatalf("over the hourly quota = %v, want throttled", err)
		}
	}
	var markers, total int
	if err := db.QueryRowContext(ctx, `SELECT
			COUNT(*) FILTER (WHERE status = 'failed' AND error_message LIKE 'THROTTLED: %'),
			COUNT(*)
		FROM workflow_runs WHERE workflow_id = $1`, wf.String()).Scan(&markers, &total); err != nil {
		t.Fatal(err)
	}
	if markers != 1 {
		t.Fatalf("throttled records = %d, want exactly one per window", markers)
	}
	if total != workflow.MaxRunsPerWorkflowPerHour+1 {
		t.Fatalf("runs = %d, want the quota plus the one record", total)
	}

	// Active cap: waiting runs beyond it are refused.
	wf2 := mkWF(tenant)
	pending := func() *workflow.Run {
		r, _ := workflow.NewRun(wf2, tenant, workflow.TriggerTypeManual, nil)
		return r
	}
	for range 2 {
		if err := repo.CreateRunIfUnderLimit(ctx, pending(), 2, 1000); err != nil {
			t.Fatal(err)
		}
	}
	var de *shared.DomainError
	if err := repo.CreateRunIfUnderLimit(ctx, pending(), 2, 1000); !errors.As(err, &de) || de.Code != "MAX_CONCURRENT_RUNS" {
		t.Fatalf("over the active cap = %v, want MAX_CONCURRENT_RUNS", err)
	}
}
