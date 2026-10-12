package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// research/62 P0-10: a run is pinned to the workflow version it started
// with. The same spec reuses the latest version; a change saves the next
// one; another tenant can neither pin nor read the workflow's versions.
func TestScanWorkflowVersions(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanWorkflowRepository(&DB{DB: db})
	tenant, other := seedScanTriggerTenant(ctx, t, db), seedScanTriggerTenant(ctx, t, db)
	wf := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO scan_workflows (id, tenant_id, name) VALUES ($1, $2, 'pin')`,
		wf.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	live := &scanworkflow.Workflow{ID: wf, TenantID: tenant, Settings: scanworkflow.DefaultSettings(),
		Steps: []*scanworkflow.Step{{ID: shared.NewID(), StepKey: "a", StepOrder: 1, Tool: "nuclei",
			Config: map[string]any{"severity": "high"}, Condition: scanworkflow.AlwaysCondition()}}}

	pin := func(w *scanworkflow.Workflow) (int, string) {
		t.Helper()
		v, d, err := repo.PinVersion(ctx, tenant, wf, scanworkflow.SpecOf(w))
		if err != nil {
			t.Fatal(err)
		}
		return v, d
	}
	v1, d1 := pin(live)
	if v1 != 1 || len(d1) != 64 {
		t.Fatalf("first pin = %d %q", v1, d1)
	}
	if v, d := pin(live); v != 1 || d != d1 {
		t.Fatalf("unchanged spec pinned %d %q, want version 1 again", v, d)
	}
	live.Steps[0].UIPosition = scanworkflow.UIPosition{X: 9, Y: 9}
	if v, _ := pin(live); v != 1 {
		t.Fatalf("a layout move made version %d", v)
	}
	live.Steps[0].Tool = "httpx"
	if v, d := pin(live); v != 2 || d == d1 {
		t.Fatalf("an edited step pinned %d %q, want version 2", v, d)
	}

	spec, err := repo.GetVersion(ctx, tenant, wf, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := spec.Workflow(live); got.Steps[0].Tool != "nuclei" || got.Steps[0].Config["severity"] != "high" {
		t.Fatalf("version 1 = %+v", got.Steps[0])
	}

	// Cross-tenant: another tenant cannot pin the workflow or read a version.
	if _, _, err := repo.PinVersion(ctx, other, wf, scanworkflow.SpecOf(live)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("pin under another tenant = %v, want not found", err)
	}
	if _, err := repo.GetVersion(ctx, other, wf, 1); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("read under another tenant = %v, want not found", err)
	}
	if _, err := repo.GetVersion(ctx, tenant, wf, 3); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("missing version = %v, want not found", err)
	}

	// The run stores and returns its pin.
	runs := NewScanRunRepository(&DB{DB: db})
	run, err := scanrun.NewRun(wf, tenant, nil, scanworkflow.TriggerTypeManual, "", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	run.ScanWorkflowVersion, run.SpecDigest = 2, d1
	if err := runs.CreateRunIfUnderLimit(ctx, run, 100, 100); err != nil {
		t.Fatal(err)
	}
	got, err := runs.GetByTenantAndID(ctx, tenant, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ScanWorkflowVersion != 2 || got.SpecDigest != d1 {
		t.Fatalf("run pin = %d %q", got.ScanWorkflowVersion, got.SpecDigest)
	}

	// A starter (system) workflow is run by every tenant: each can pin a
	// version of it and read it back, and the version is shared (the
	// template's), while another tenant's private workflow stays out of reach.
	starter := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO scan_workflows (id, tenant_id, name, is_system_template)
		VALUES ($1, '00000000-0000-0000-0000-000000000000', $2, TRUE)`, starter.String(), "starter "+starter.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM scan_workflows WHERE id = $1`, starter.String())
	})
	starterSpec := scanworkflow.SpecOf(&scanworkflow.Workflow{ID: starter, Settings: scanworkflow.DefaultSettings(),
		Steps: []*scanworkflow.Step{{ID: shared.NewID(), StepKey: "subs", StepOrder: 1, Tool: "subfinder", Condition: scanworkflow.AlwaysCondition()}}})
	va, _, err := repo.PinVersion(ctx, tenant, starter, starterSpec)
	if err != nil || va != 1 {
		t.Fatalf("tenant pins a starter workflow: %d %v", va, err)
	}
	vb, _, err := repo.PinVersion(ctx, other, starter, starterSpec)
	if err != nil || vb != 1 {
		t.Fatalf("another tenant pins the same starter: %d %v, want the shared version 1", vb, err)
	}
	for _, tn := range []shared.ID{tenant, other} {
		if got, err := repo.GetVersion(ctx, tn, starter, 1); err != nil || got.Steps[0].Tool != "subfinder" {
			t.Fatalf("tenant %s reads the starter version: %+v %v", tn, got, err)
		}
	}

	// Removing the workflow removes its versions.
	if _, err := db.ExecContext(ctx, `DELETE FROM scan_runs WHERE id = $1`, run.ID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM scan_workflows WHERE id = $1`, wf.String()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM scan_workflow_versions WHERE scan_workflow_id = $1`, wf.String()).Scan(&n); err != nil || n != 0 {
		t.Fatalf("versions left after the workflow was removed: %d %v", n, err)
	}
}
