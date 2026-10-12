package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Saving a scan workflow keeps the history of its runs, against the real SQL.
//
// Before: a save deleted and re-created every step; scan_run_steps.step_id was
// ON DELETE CASCADE and scan_step_outputs cascades from scan_run_steps, so one
// save erased the step history and chaining inputs of every past and
// running run of the scan workflow.

type stepHistoryFixture struct {
	tenant, template shared.ID
	stepA, stepB     *scanworkflow.Step
	run              *scanrun.Run
	runA, runB       *scanrun.StepRun
	asset            shared.ID
}

func seedStepHistory(ctx context.Context, t *testing.T, db *sql.DB, finish bool) stepHistoryFixture {
	t.Helper()
	f := stepHistoryFixture{tenant: seedScanTriggerTenant(ctx, t, db), template: shared.NewID()}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO scan_workflows (id, tenant_id, name) VALUES ($1, $2, 'history probe')`,
		f.template.String(), f.tenant.String()); err != nil {
		t.Fatalf("seed template: %v", err)
	}
	steps := NewScanWorkflowStepRepository(&DB{DB: db})
	mk := func(key, tool string, order int) *scanworkflow.Step {
		s, err := scanworkflow.NewStep(f.template, key, "Step "+key, order, []string{"scan"})
		if err != nil {
			t.Fatal(err)
		}
		s.SetTool(tool)
		if err := steps.Create(ctx, s); err != nil {
			t.Fatalf("create step %s: %v", key, err)
		}
		return s
	}
	f.stepA = mk("discover", "subfinder", 1)
	f.stepB = mk("probe", "httpx", 2)

	runs := NewScanRunRepository(&DB{DB: db})
	run, err := scanrun.NewRun(f.template, f.tenant, nil, scanworkflow.TriggerTypeManual, "", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	run.SetTotalSteps(2)
	run.Start()
	if err := runs.Create(ctx, run); err != nil {
		t.Fatalf("create run: %v", err)
	}
	f.run = run

	stepRuns := NewStepRunRepository(&DB{DB: db})
	f.runA = scanrun.NewStepRunForStep(run.ID, f.stepA)
	f.runB = scanrun.NewStepRunForStep(run.ID, f.stepB)
	if err := stepRuns.CreateBatch(ctx, []*scanrun.StepRun{f.runA, f.runB}); err != nil {
		t.Fatalf("create step runs: %v", err)
	}
	f.asset = seedTestAsset(ctx, t, db, f.tenant)
	for _, sr := range []*scanrun.StepRun{f.runA, f.runB} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO scan_step_outputs (tenant_id, run_id, scan_run_step_id, asset_id) VALUES ($1, $2, $3, $4)`,
			f.tenant.String(), run.ID.String(), sr.ID.String(), f.asset.String()); err != nil {
			t.Fatalf("seed step output: %v", err)
		}
	}
	if finish {
		if err := runs.UpdateStatus(ctx, run.ID, scanrun.RunStatusCompleted, ""); err != nil {
			t.Fatalf("finish run: %v", err)
		}
	}
	return f
}

func TestMutateSteps_SaveKeepsRunHistory(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	f := seedStepHistory(ctx, t, db, true)
	steps := NewScanWorkflowStepRepository(&DB{DB: db})
	stepRuns := NewStepRunRepository(&DB{DB: db})

	// Edit discover in place (new tool), remove probe, add a new step.
	added, err := scanworkflow.NewStep(f.template, "vuln", "Vuln", 2, []string{"scan"})
	if err != nil {
		t.Fatal(err)
	}
	added.SetTool("nuclei")
	saved, err := steps.MutateSteps(ctx, f.tenant, f.template, func(cur []*scanworkflow.Step) ([]*scanworkflow.Step, error) {
		if len(cur) != 2 {
			t.Fatalf("mutate saw %d steps, want 2", len(cur))
		}
		var keep *scanworkflow.Step
		for _, s := range cur {
			if s.ID == f.stepA.ID {
				keep = s
			}
		}
		keep.SetTool("amass")
		keep.Name = "Discover (renamed)"
		return []*scanworkflow.Step{keep, added}, nil
	})
	if err != nil {
		t.Fatalf("MutateSteps: %v", err)
	}
	if len(saved) != 2 {
		t.Fatalf("saved %d steps", len(saved))
	}

	// The edited step kept its id and is updated.
	got, err := steps.GetByID(ctx, f.stepA.ID)
	if err != nil || got.Tool != "amass" || got.Name != "Discover (renamed)" {
		t.Fatalf("edited step: %+v, %v", got, err)
	}
	if _, err := steps.GetByID(ctx, f.stepB.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("removed step still there: %v", err)
	}

	// Both step runs survive; the removed step's run keeps its snapshot.
	history, err := stepRuns.GetByScanRunID(ctx, f.run.ID)
	if err != nil || len(history) != 2 {
		t.Fatalf("step runs after save: %d, %v", len(history), err)
	}
	for _, sr := range history {
		switch sr.ID {
		case f.runA.ID:
			if sr.StepID != f.stepA.ID || sr.Tool != "subfinder" || sr.StepName != "Step discover" {
				t.Fatalf("kept step's run changed: step=%s tool=%q name=%q", sr.StepID, sr.Tool, sr.StepName)
			}
		case f.runB.ID:
			if !sr.StepID.IsZero() || sr.StepKey != "probe" || sr.Tool != "httpx" || sr.StepName != "Step probe" {
				t.Fatalf("removed step's run lost history: step=%s key=%q tool=%q name=%q", sr.StepID, sr.StepKey, sr.Tool, sr.StepName)
			}
		}
	}
	if n := countRows(ctx, t, db, `SELECT COUNT(*) FROM scan_step_outputs WHERE run_id = $1`, f.run.ID.String()); n != 2 {
		t.Fatalf("chaining inputs after save: %d, want 2", n)
	}

	// Saving the same steps again changes no ids and loses nothing.
	if _, err := steps.MutateSteps(ctx, f.tenant, f.template, func(cur []*scanworkflow.Step) ([]*scanworkflow.Step, error) {
		return cur, nil
	}); err != nil {
		t.Fatalf("second save: %v", err)
	}
	if n := countRows(ctx, t, db, `SELECT COUNT(*) FROM scan_run_steps WHERE scan_run_id = $1 AND step_id = $2`, f.run.ID.String(), f.stepA.ID.String()); n != 1 {
		t.Fatalf("kept step's run detached after second save: %d", n)
	}

	// The schema itself keeps history: no path that deletes a step (the
	// template delete included) cascades its step runs away any more.
	if _, err := db.ExecContext(ctx, `DELETE FROM scan_workflow_steps WHERE scan_workflow_id = $1`, f.template.String()); err != nil {
		t.Fatal(err)
	}
	if n := countRows(ctx, t, db, `SELECT COUNT(*) FROM scan_run_steps WHERE scan_run_id = $1 AND step_id IS NULL`, f.run.ID.String()); n != 2 {
		t.Fatalf("step runs after deleting every step: %d detached, want 2", n)
	}
	if n := countRows(ctx, t, db, `SELECT COUNT(*) FROM scan_step_outputs WHERE run_id = $1`, f.run.ID.String()); n != 2 {
		t.Fatalf("chaining inputs after deleting every step: %d, want 2", n)
	}
}

// A saved step's key is fixed once the workflow has a run (finished ones
// too): the run's step runs and step outputs refer to it. The name and
// everything else may still change.
func TestMutateSteps_KeyIsFixedOnceTheWorkflowHasRuns(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	f := seedStepHistory(ctx, t, db, true) // one finished run
	steps := NewScanWorkflowStepRepository(&DB{DB: db})

	_, err := steps.MutateSteps(ctx, f.tenant, f.template, func(cur []*scanworkflow.Step) ([]*scanworkflow.Step, error) {
		cur[0].StepKey = "discover-renamed"
		return cur, nil
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("key change after a run: err=%v, want ErrValidation", err)
	}
	if a, _ := steps.GetByID(ctx, f.stepA.ID); a.StepKey != "discover" {
		t.Fatalf("refused save changed the key: %q", a.StepKey)
	}

	// Renaming the step (not its key) is still allowed.
	if _, err := steps.MutateSteps(ctx, f.tenant, f.template, func(cur []*scanworkflow.Step) ([]*scanworkflow.Step, error) {
		cur[0].Name = "Find subdomains"
		return cur, nil
	}); err != nil {
		t.Fatalf("rename a step: %v", err)
	}
	if a, _ := steps.GetByID(ctx, f.stepA.ID); a.Name != "Find subdomains" || a.StepKey != "discover" {
		t.Fatalf("after rename: name=%q key=%q", a.Name, a.StepKey)
	}

	// Another tenant's run of a workflow with the same id cannot exist, and
	// another tenant cannot reach this workflow at all.
	if _, err := steps.MutateSteps(ctx, shared.NewID(), f.template, func(cur []*scanworkflow.Step) ([]*scanworkflow.Step, error) {
		return cur, nil
	}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("other tenant: err=%v, want ErrNotFound", err)
	}
}

func TestMutateSteps_KeysCanSwap(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	f := seedStepHistory(ctx, t, db, true)
	steps := NewScanWorkflowStepRepository(&DB{DB: db})
	// Keys move freely only while the workflow has never run.
	if _, err := db.ExecContext(ctx, `DELETE FROM scan_runs WHERE id = $1`, f.run.ID.String()); err != nil {
		t.Fatalf("drop the run: %v", err)
	}

	_, err := steps.MutateSteps(ctx, f.tenant, f.template, func(cur []*scanworkflow.Step) ([]*scanworkflow.Step, error) {
		cur[0].StepKey, cur[1].StepKey = cur[1].StepKey, cur[0].StepKey
		return cur, nil
	})
	if err != nil {
		t.Fatalf("swap keys: %v", err)
	}
	a, _ := steps.GetByID(ctx, f.stepA.ID)
	b, _ := steps.GetByID(ctx, f.stepB.ID)
	if a.StepKey != "probe" || b.StepKey != "discover" {
		t.Fatalf("keys after swap: %q %q", a.StepKey, b.StepKey)
	}

	// Two steps with one key is still refused, and nothing changes.
	_, err = steps.MutateSteps(ctx, f.tenant, f.template, func(cur []*scanworkflow.Step) ([]*scanworkflow.Step, error) {
		cur[1].StepKey = cur[0].StepKey
		return cur, nil
	})
	if !errors.Is(err, shared.ErrAlreadyExists) {
		t.Fatalf("duplicate key: err=%v, want ErrAlreadyExists", err)
	}
	a, _ = steps.GetByID(ctx, f.stepA.ID)
	if a.StepKey != "probe" {
		t.Fatalf("refused save changed a key: %q", a.StepKey)
	}
}

func TestMutateSteps_RefusedWhileARunIsActive(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	f := seedStepHistory(ctx, t, db, false) // the run is still running
	steps := NewScanWorkflowStepRepository(&DB{DB: db})

	called := false
	_, err := steps.MutateSteps(ctx, f.tenant, f.template, func(cur []*scanworkflow.Step) ([]*scanworkflow.Step, error) {
		called = true
		return cur[:1], nil
	})
	if !errors.Is(err, scanworkflow.ErrScanWorkflowRunActive) || !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("save during a run: err=%v, want ErrScanWorkflowRunActive", err)
	}
	if called {
		t.Fatal("mutate ran although a run is active")
	}
	if n := countRows(ctx, t, db, `SELECT COUNT(*) FROM scan_workflow_steps WHERE scan_workflow_id = $1`, f.template.String()); n != 2 {
		t.Fatalf("steps after refused save: %d, want 2", n)
	}
	if n := countRows(ctx, t, db, `SELECT COUNT(*) FROM scan_run_steps WHERE scan_run_id = $1 AND step_id IS NOT NULL`, f.run.ID.String()); n != 2 {
		t.Fatalf("running run's step runs after refused save: %d, want 2", n)
	}
}

func TestMutateSteps_OtherTenantIsNotFound(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	f := seedStepHistory(ctx, t, db, true)
	other := seedScanTriggerTenant(ctx, t, db)
	steps := NewScanWorkflowStepRepository(&DB{DB: db})

	_, err := steps.MutateSteps(ctx, other, f.template, func(cur []*scanworkflow.Step) ([]*scanworkflow.Step, error) {
		t.Fatal("mutate ran for another tenant's pipeline")
		return nil, nil
	})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("other tenant: err=%v, want ErrNotFound", err)
	}
	if n := countRows(ctx, t, db, `SELECT COUNT(*) FROM scan_workflow_steps WHERE scan_workflow_id = $1`, f.template.String()); n != 2 {
		t.Fatalf("other tenant changed the steps: %d", n)
	}
}

// A step id from another scan workflow cannot be written through this one: the
// in-place update is bound to the scan workflow, so the save fails as a whole.
func TestMutateSteps_ForeignStepIDIsNotUpdated(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	mine := seedStepHistory(ctx, t, db, true)
	theirs := seedStepHistory(ctx, t, db, true)
	steps := NewScanWorkflowStepRepository(&DB{DB: db})

	_, err := steps.MutateSteps(ctx, mine.tenant, mine.template, func(cur []*scanworkflow.Step) ([]*scanworkflow.Step, error) {
		foreign := *theirs.stepA
		foreign.Name = "hijacked"
		return append(cur, &foreign), nil
	})
	if err == nil {
		t.Fatal("a save carrying another pipeline's step id succeeded")
	}
	got, _ := steps.GetByID(ctx, theirs.stepA.ID)
	if got.Name == "hijacked" || got.ScanWorkflowID != theirs.template {
		t.Fatalf("foreign step changed: %+v", got)
	}
}

// prefer_tools round-trips, and a queued step run records the capability
// and the tool the planner picked.
func TestStepSelection_PersistsAndStepRunRecordsResolution(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	f := seedStepHistory(ctx, t, db, false)
	steps := NewScanWorkflowStepRepository(&DB{DB: db})
	stepRuns := NewStepRunRepository(&DB{DB: db})

	_, err := steps.MutateSteps(ctx, f.tenant, f.template, func(cur []*scanworkflow.Step) ([]*scanworkflow.Step, error) {
		return cur, nil
	})
	if !errors.Is(err, scanworkflow.ErrScanWorkflowRunActive) {
		t.Fatalf("precondition: %v", err)
	}
	// Finish the run, then store a prefer list.
	if err := NewScanRunRepository(&DB{DB: db}).UpdateStatus(ctx, f.run.ID, scanrun.RunStatusCompleted, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := steps.MutateSteps(ctx, f.tenant, f.template, func(cur []*scanworkflow.Step) ([]*scanworkflow.Step, error) {
		for _, s := range cur {
			if s.ID == f.stepA.ID {
				s.Tool = ""
				s.Capabilities = []string{"discover.subdomains"}
				s.PreferTools = []string{"subfinder"}
			}
		}
		return cur, nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := steps.GetByID(ctx, f.stepA.ID)
	if err != nil || len(got.PreferTools) != 1 || got.PreferTools[0] != "subfinder" || got.Selection() != scanworkflow.ToolSelectionPrefer {
		t.Fatalf("prefer_tools: %+v %v", got, err)
	}
	b, _ := steps.GetByID(ctx, f.stepB.ID)
	if b.PreferTools == nil || len(b.PreferTools) != 0 {
		t.Fatalf("an empty prefer list reads back as %v", b.PreferTools)
	}

	// Queue-time resolution is written with the queued state.
	sr := scanrun.NewStepRunForStep(f.run.ID, got) // no tool yet: not pinned
	if err := stepRuns.Create(ctx, sr); err != nil {
		t.Fatal(err)
	}
	sr.Queue()
	sr.Tool = "subfinder"
	sr.Capability = "discover.subdomains@1"
	if err := stepRuns.Update(ctx, sr); err != nil {
		t.Fatal(err)
	}
	read, err := stepRuns.GetByID(ctx, sr.ID)
	if err != nil || read.Tool != "subfinder" || read.Capability != "discover.subdomains@1" {
		t.Fatalf("step run resolution: %+v %v", read, err)
	}
	// A later update without them keeps them.
	read.Tool, read.Capability = "", ""
	if err := stepRuns.Update(ctx, read); err != nil {
		t.Fatal(err)
	}
	again, _ := stepRuns.GetByID(ctx, sr.ID)
	if again.Tool != "subfinder" || again.Capability != "discover.subdomains@1" {
		t.Fatalf("an update erased the resolution: %+v", again)
	}
}

// A step stored without a description (a seed, an old row) reads back with
// an empty one instead of failing the whole template read.
func TestPipelineStep_NullDescriptionReads(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	f := seedStepHistory(ctx, t, db, true)
	if _, err := db.ExecContext(ctx, `UPDATE scan_workflow_steps SET description = NULL WHERE id = $1`, f.stepA.ID.String()); err != nil {
		t.Fatal(err)
	}
	got, err := NewScanWorkflowStepRepository(&DB{DB: db}).GetByID(ctx, f.stepA.ID)
	if err != nil || got.Description != "" {
		t.Fatalf("read: %+v %v", got, err)
	}
}

// A negative fractional canvas position is stored and read back (rounded):
// the INTEGER columns used to fail the save with 22P02 and a 500.
func TestMutateSteps_FractionalPositionRoundTrips(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	f := seedStepHistory(ctx, t, db, true)
	steps := NewScanWorkflowStepRepository(&DB{DB: db})

	if _, err := steps.MutateSteps(ctx, f.tenant, f.template, func(cur []*scanworkflow.Step) ([]*scanworkflow.Step, error) {
		if err := cur[0].SetUIPosition(-307.4222108759977, 88.6); err != nil {
			return nil, err
		}
		return cur, nil
	}); err != nil {
		t.Fatalf("save a fractional position: %v", err)
	}
	got, err := steps.GetByID(ctx, f.stepA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.UIPosition.X != -307 || got.UIPosition.Y != 89 {
		t.Fatalf("position after round trip: %+v", got.UIPosition)
	}
}
