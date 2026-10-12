package scanrun

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// stallRuns is statusRuns that also reports stalled runs.
type stallRuns struct {
	*statusRuns
	stalled  []scanrun.StalledRun
	released bool
}

func (r *stallRuns) ReleaseOrphanStagePlans(context.Context, time.Time, int) (int64, error) {
	r.released = true
	return 0, nil
}

func (r *stallRuns) StalledRuns(context.Context, time.Time, int) ([]scanrun.StalledRun, error) {
	return r.stalled, nil
}

// research/62 SG-10: b waited for a's report, which then failed; nothing
// called back, so b stayed pending until the run timeout. The repair
// advances the run: b is queued.
func TestRepairStalledRuns_AdvancesARunWaitingOnNothing(t *testing.T) {
	s, run, store, runs, cmds := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusCompleted, "b": scanrun.StepRunStatusPending},
		map[string][]string{"b": {"a"}})
	repo := &stallRuns{statusRuns: runs, stalled: []scanrun.StalledRun{{TenantID: run.TenantID, RunID: run.ID}}}
	s.runRepo = repo
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.ScanWorkflowID)
	tpl.Steps[1].Tool = "nuclei"
	s.sensorRepo = tenantSensors{id: shared.NewID()}
	run.Context = map[string]any{"targets": []string{"example.com"}}

	n, err := s.RepairStalledRuns(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("RepairStalledRuns = %d, %v; want 1 run advanced", n, err)
	}
	if !repo.released {
		t.Error("orphan stage plans were not released first")
	}
	if b := store.rows["b"]; b.Status != scanrun.StepRunStatusQueued || len(cmds.created) != 1 {
		t.Fatalf("b is %s with %d command(s), want queued with 1", b.Status, len(cmds.created))
	}
}

// A stalled entry naming another tenant than the run's is not acted on.
func TestRepairStalledRuns_RunReadInItsOwnTenant(t *testing.T) {
	s, run, store, runs, cmds := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusCompleted, "b": scanrun.StepRunStatusPending},
		map[string][]string{"b": {"a"}})
	s.runRepo = &stallRuns{statusRuns: runs, stalled: []scanrun.StalledRun{{TenantID: shared.NewID(), RunID: run.ID}}}

	if n, err := s.RepairStalledRuns(context.Background()); err != nil || n != 0 {
		t.Fatalf("RepairStalledRuns = %d, %v; want 0", n, err)
	}
	if store.rows["b"].Status != scanrun.StepRunStatusPending || len(cmds.created) != 0 {
		t.Fatal("a run was advanced under another tenant")
	}
}
