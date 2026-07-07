package compliance

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/simulation"
	"github.com/openctemio/api/pkg/logger"
)

func TestMapOutcomeToResult(t *testing.T) {
	cases := []struct {
		outcome string
		want    simulation.RunResult
	}{
		{"not_detected", simulation.RunResultPrevented}, // unreachable → control held
		{"detected", simulation.RunResultBypassed},      // reachable → path open
		{"inconclusive", simulation.RunResultPartial},
		{"error", simulation.RunResultError},
		{"garbage", simulation.RunResultError},
	}
	for _, tc := range cases {
		got, det, prev := mapOutcomeToResult(tc.outcome)
		if got != tc.want {
			t.Errorf("mapOutcomeToResult(%q) = %q, want %q", tc.outcome, got, tc.want)
		}
		if det == "" || prev == "" {
			t.Errorf("mapOutcomeToResult(%q) must return non-empty detection/prevention text", tc.outcome)
		}
	}
}

// --- fakes for FinalizeRun ---

type fakeRunRepo struct {
	simulation.RunRepository
	run     *simulation.SimulationRun
	getErr  error
	updated *simulation.SimulationRun
}

func (r *fakeRunRepo) GetByID(_ context.Context, _, _ shared.ID) (*simulation.SimulationRun, error) {
	return r.run, r.getErr
}
func (r *fakeRunRepo) Update(_ context.Context, run *simulation.SimulationRun) error {
	r.updated = run
	return nil
}

type fakeSimRepo struct {
	simulation.SimulationRepository
	sim     *simulation.Simulation
	updated *simulation.Simulation
}

func (r *fakeSimRepo) GetByID(_ context.Context, _, _ shared.ID) (*simulation.Simulation, error) {
	return r.sim, nil
}
func (r *fakeSimRepo) Update(_ context.Context, sim *simulation.Simulation) error {
	r.updated = sim
	return nil
}

func TestFinalizeRun_CompletesRunningRunAndRecordsStats(t *testing.T) {
	tenantID := shared.NewID()
	sim, err := simulation.NewSimulation(tenantID, "sim", simulation.SimulationTypeAtomic)
	if err != nil {
		t.Fatalf("NewSimulation: %v", err)
	}
	run := simulation.NewSimulationRun(tenantID, sim.ID())
	run.Start() // status = running

	runRepo := &fakeRunRepo{run: run}
	simRepo := &fakeSimRepo{sim: sim}
	svc := &SimulationService{simRepo: simRepo, runRepo: runRepo, logger: logger.NewNop()}

	if err := svc.FinalizeRun(context.Background(), tenantID, run.ID(), "not_detected", "port closed"); err != nil {
		t.Fatalf("FinalizeRun: %v", err)
	}

	if runRepo.updated == nil {
		t.Fatal("run was not persisted")
	}
	if runRepo.updated.Status() != simulation.RunStatusCompleted {
		t.Errorf("run status = %q, want completed", runRepo.updated.Status())
	}
	if runRepo.updated.Result() != simulation.RunResultPrevented {
		t.Errorf("run result = %q, want prevented (not_detected)", runRepo.updated.Result())
	}
	if runRepo.updated.Output()["verified"] != true {
		t.Error("live-finalized run must be flagged verified:true")
	}
	if simRepo.updated == nil {
		t.Error("simulation stats were not rolled forward")
	}
}

func TestFinalizeRun_SkipsAlreadyFinalizedRun(t *testing.T) {
	tenantID := shared.NewID()
	run := simulation.NewSimulationRun(tenantID, shared.NewID())
	run.Start()
	run.Complete(simulation.RunResultDetected, "d", "p", map[string]any{}) // already completed

	runRepo := &fakeRunRepo{run: run}
	svc := &SimulationService{runRepo: runRepo, logger: logger.NewNop()}

	if err := svc.FinalizeRun(context.Background(), tenantID, run.ID(), "detected", ""); err != nil {
		t.Fatalf("FinalizeRun: %v", err)
	}
	if runRepo.updated != nil {
		t.Error("an already-completed run must not be updated again (idempotent)")
	}
}
