package scanrun

import (
	"context"
	"errors"
	"slices"
	"testing"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// livenessFixture: hosts (discover.hosts) -> ports (scan.ports), the real
// target gate, run targets as given.
func livenessFixture(t *testing.T, mode string, targets ...string) *chainFixture {
	t.Helper()
	f := &chainFixture{hops: newMemHops(), cmds: &countingCommands{}, acts: &allowActs{}, excl: excludeNames{},
		attr: attrTable{byID: map[string]attribution.State{}, byName: map[string]attribution.State{}, ceiling: map[string]scopedom.Tier{}}, sr: map[string]shared.ID{}}
	rc := map[string]any{"targets": targets}
	if mode != "" {
		rc[scanapp.RunContextKeyCIDRMode] = mode
	}
	f.run = &scanrun.Run{ID: shared.NewID(), TenantID: shared.NewID(), ScanWorkflowID: shared.NewID(),
		Status: scanrun.RunStatusRunning, Context: rc}
	f.tpl = &scanworkflow.Workflow{}
	f.store = &memStepRuns{rows: map[string]scanrun.StepRun{}}
	steps := []struct {
		key, cap string
		deps     []string
	}{{"hosts", "discover.hosts", nil}, {"ports", "scan.ports", []string{"hosts"}}}
	for i, st := range steps {
		step := &scanworkflow.Step{ID: shared.NewID(), StepKey: st.key, Capabilities: []string{st.cap}, StepOrder: i + 1,
			DependsOn: st.deps, Condition: scanworkflow.AlwaysCondition()}
		f.tpl.Steps = append(f.tpl.Steps, step)
		sr := scanrun.NewStepRun(f.run.ID, step.ID, st.key, step.StepOrder, 0)
		f.sr[st.key] = sr.ID
		f.store.rows[st.key] = *sr
		cp := *sr
		f.run.StepRuns = append(f.run.StepRuns, &cp)
	}
	f.run.TotalSteps = len(steps)
	gate := scanapp.NewTargetGate(f.excl, f.attr, zoneList{}, nil, logger.NewNop())
	scanapp.WithActScope(f.acts)(gate)
	f.s = &Service{tools: testTools, stepRunRepo: f.store, runRepo: &statusRuns{run: f.run}, templateRepo: fixedTemplate{tpl: f.tpl},
		commandRepo: f.cmds, toolRepo: platformTools{names: map[string]bool{"naabu": true}},
		targetGate: gate, hops: f.hops, sensorRepo: tenantSensors{id: shared.NewID()}, logger: logger.NewNop()}
	return f
}

// Live hosts first: host discovery gets the range; the port scan after it
// gets the live hosts it found and the known addresses, never the range.
func TestLiveness_RangeOnlyToHostDiscovery(t *testing.T) {
	f := livenessFixture(t, "liveness", "198.51.100.0/24", "198.51.100.200")
	f.schedule(t)
	if got := f.commandTargets(t, 0); !slices.Equal(got, []string{"198.51.100.0/24", "198.51.100.200"}) {
		t.Fatalf("host discovery targets = %v", got)
	}
	f.settle("hosts", scanrun.StepRunStatusCompleted)
	f.output("hosts", "198.51.100.7", "ip_address", "", "")
	f.schedule(t)
	got := f.commandTargets(t, 1)
	if slices.Contains(got, "198.51.100.0/24") {
		t.Fatalf("the port scan got the range: %v", got)
	}
	if !slices.Contains(got, "198.51.100.7") || !slices.Contains(got, "198.51.100.200") {
		t.Fatalf("port scan targets = %v, want the live host and the known address", got)
	}
}

// Without liveness (a scan that sweeps), the port scan keeps the range and
// does not scan a live host inside it a second time.
func TestLiveness_SweepKeepsTheRangeOnce(t *testing.T) {
	f := livenessFixture(t, "", "198.51.100.0/24")
	f.schedule(t)
	f.settle("hosts", scanrun.StepRunStatusCompleted)
	f.output("hosts", "198.51.100.7", "ip_address", "", "")
	f.output("hosts", "203.0.113.9", "ip_address", "", "")
	f.schedule(t)
	got := f.commandTargets(t, 1)
	if !slices.Contains(got, "198.51.100.0/24") || slices.Contains(got, "198.51.100.7") {
		t.Fatalf("port scan targets = %v, want the range once, not the address inside it", got)
	}
}

// A run of names: host discovery has nothing to probe and is settled
// without a command; the port scan after it runs on its own targets.
func TestLiveness_NamesOnlySettlesHostDiscovery(t *testing.T) {
	f := livenessFixture(t, "liveness", "app.example.com")
	err := f.s.QueueRunStep(context.Background(), f.run, f.tpl.Steps[0])
	if !errors.Is(err, scanapp.ErrStepSettled) {
		t.Fatalf("err = %v, want the step settled", err)
	}
	if r := f.store.rows["hosts"]; r.Status != scanrun.StepRunStatusCompleted || len(f.cmds.created) != 0 {
		t.Fatalf("host discovery = %s with %d command(s)", r.Status, len(f.cmds.created))
	}
	f.run.GetStepRun("hosts").Status = scanrun.StepRunStatusCompleted
	f.schedule(t)
	if got := f.commandTargets(t, 0); !slices.Equal(got, []string{"app.example.com"}) {
		t.Fatalf("port scan targets = %v", got)
	}
}

// A port scan that runs first, in a liveness run with only a range, has no
// host to scan: refused with the fix, never handed the range.
func TestLiveness_DeepStepWithoutHostDiscoveryRefused(t *testing.T) {
	f := livenessFixture(t, "liveness", "198.51.100.0/24")
	f.tpl.Steps = f.tpl.Steps[1:]
	f.tpl.Steps[0].DependsOn = nil
	err := f.s.QueueRunStep(context.Background(), f.run, f.tpl.Steps[0])
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != scanapp.CodeLivenessNeedsHostDiscovery || len(f.cmds.created) != 0 {
		t.Fatalf("err = %v, commands %d", err, len(f.cmds.created))
	}
}
