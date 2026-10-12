package scanrun

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// memVersions is a version store keyed by tenant, workflow and version.
type memVersions struct {
	specs map[string]scanworkflow.Spec
	gets  []shared.ID // tenant of each read
}

func versionKey(tenantID, workflowID shared.ID, v int) string {
	return tenantID.String() + "/" + workflowID.String() + "/" + string(rune('0'+v))
}

func (m *memVersions) PinVersion(_ context.Context, tenantID, workflowID shared.ID, spec scanworkflow.Spec) (int, string, error) {
	if m.specs == nil {
		m.specs = map[string]scanworkflow.Spec{}
	}
	m.specs[versionKey(tenantID, workflowID, 1)] = spec
	d, err := spec.Digest()
	return 1, d, err
}

func (m *memVersions) GetVersion(_ context.Context, tenantID, workflowID shared.ID, v int) (*scanworkflow.Spec, error) {
	m.gets = append(m.gets, tenantID)
	spec, ok := m.specs[versionKey(tenantID, workflowID, v)]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return &spec, nil
}

// research/62 P0-10: the run was started with b running nuclei; b was then
// edited to run httpx. The run's next step still runs nuclei: an edit made
// while a run is going changes the next run only.
func TestRunExecutesItsPinnedVersion(t *testing.T) {
	s, run, store, _, cmds := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusCompleted, "b": scanrun.StepRunStatusPending},
		map[string][]string{"b": {"a"}})
	s.sensorRepo = tenantSensors{id: shared.NewID()}
	run.Context = map[string]any{"targets": []string{"example.com"}}
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.ScanWorkflowID)
	tpl.ID = run.ScanWorkflowID
	tpl.Steps[1].Tool = "nuclei"

	versions := &memVersions{}
	s.versions = versions
	if err := scanrun.PinWorkflow(context.Background(), versions, run, tpl); err != nil {
		t.Fatal(err)
	}
	if run.ScanWorkflowVersion != 1 || len(run.SpecDigest) != 64 {
		t.Fatalf("run pinned to version %d digest %q", run.ScanWorkflowVersion, run.SpecDigest)
	}

	tpl.Steps[1].Tool = "httpx" // edited while the run is going

	if err := s.AdvanceRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if b := store.rows["b"]; b.Status != scanrun.StepRunStatusQueued || len(cmds.created) != 1 {
		t.Fatalf("b is %s with %d command(s), want queued with 1", b.Status, len(cmds.created))
	}
	if !strings.Contains(cmds.created[0], "nuclei") || strings.Contains(cmds.created[0], "httpx") {
		t.Fatalf("command payload does not run the pinned tool: %s", cmds.created[0])
	}
	if len(versions.gets) == 0 || versions.gets[0] != run.TenantID {
		t.Fatalf("version read under tenant %v, want the run's tenant", versions.gets)
	}
}

// A pinned version that cannot be read (another tenant's, removed) stops the
// run's progress with an error; it never falls back to the live workflow.
func TestRunPinnedVersionMissing_FailsClosed(t *testing.T) {
	s, run, store, _, cmds := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusCompleted, "b": scanrun.StepRunStatusPending},
		map[string][]string{"b": {"a"}})
	s.sensorRepo = tenantSensors{id: shared.NewID()}
	run.Context = map[string]any{"targets": []string{"example.com"}}
	s.versions = &memVersions{}
	run.ScanWorkflowVersion = 3

	err := s.AdvanceRun(context.Background(), run)
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("AdvanceRun = %v, want not found", err)
	}
	if store.rows["b"].Status != scanrun.StepRunStatusPending || len(cmds.created) != 0 {
		t.Fatal("a step was queued from the live workflow")
	}
}

// A run from before versions (version 0) keeps reading the live workflow.
func TestUnpinnedRunReadsLiveWorkflow(t *testing.T) {
	s, run, store, _, cmds := gatingFixture(
		map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusCompleted, "b": scanrun.StepRunStatusPending},
		map[string][]string{"b": {"a"}})
	s.sensorRepo = tenantSensors{id: shared.NewID()}
	run.Context = map[string]any{"targets": []string{"example.com"}}
	versions := &memVersions{}
	s.versions = versions
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.ScanWorkflowID)
	tpl.Steps[1].Tool = "nuclei"

	if err := s.AdvanceRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if store.rows["b"].Status != scanrun.StepRunStatusQueued || len(cmds.created) != 1 || len(versions.gets) != 0 {
		t.Fatalf("b %s, %d command(s), %d version read(s)", store.rows["b"].Status, len(cmds.created), len(versions.gets))
	}
}
