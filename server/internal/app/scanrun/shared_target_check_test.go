package scanrun

import (
	"context"
	"errors"
	"testing"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// sharedTargetGate is a target gate whose shared-sensor check refuses the
// targets in refuse (or fails with err) and allows the rest.
type sharedTargetGate struct {
	TargetGate
	refuse map[string]bool
	err    error
	seen   *[]string
	group  *bool
}

func (g sharedTargetGate) PlatformTargetRefusal(_ context.Context, _ shared.ID, targets []string, assetGroup bool) error {
	if g.seen != nil {
		*g.seen = append(*g.seen, targets...)
	}
	if g.group != nil {
		*g.group = assetGroup
	}
	if g.err != nil {
		return g.err
	}
	if assetGroup {
		return errors.New("asset group")
	}
	for _, t := range targets {
		if g.refuse[t] {
			return errors.New("refused: " + t)
		}
	}
	return nil
}

// A workflow step is queued for shared sensors only when its own targets
// pass the scan trigger's shared-sensor check (internal targets, domain
// proof, bug-bounty program targets). Before, a run started from a workflow
// directly (no trigger decision) reached shared sensors on the workflow's
// preference and the tenant's access alone, with no target check at all,
// and a step of a checked run could carry targets found after the check.
func TestStepDispatch_SharedSensorsNeedTheTargetCheck(t *testing.T) {
	const internalName = "intranet.example.com" // a name that resolves inside
	cases := []struct {
		name     string
		routing  any // the trigger decision in the run context; nil = started from a workflow
		gate     TargetGate
		targets  []string
		group    string
		platform bool
	}{
		{"workflow run, targets pass", nil, sharedTargetGate{}, []string{"example.com"}, "", true},
		{"workflow run, a target refused", nil, sharedTargetGate{refuse: map[string]bool{internalName: true}},
			[]string{"example.com", internalName}, "", false},
		{"workflow run, lookup fails", nil, sharedTargetGate{err: errors.New("db down")}, []string{"example.com"}, "", false},
		{"workflow run, no target check wired", nil, nil, []string{"example.com"}, "", false},
		{"workflow run on an asset group", nil, sharedTargetGate{}, []string{"example.com"}, shared.NewID().String(), false},
		{"trigger said platform, a step target refused", scanrun.SensorRoutingPlatform,
			sharedTargetGate{refuse: map[string]bool{internalName: true}}, []string{internalName}, "", false},
		{"trigger said platform, targets pass", scanrun.SensorRoutingPlatform, sharedTargetGate{}, []string{"example.com"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, run, _, _, _ := gatingFixture(map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusPending}, nil)
			tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.ScanWorkflowID)
			tpl.Steps[0].Tool = "nuclei"
			tpl.Settings.SensorPreference = scanworkflow.SensorPreferencePlatform
			s.sensorRepo = tenantSensors{id: shared.NewID()}
			s.sensorSelector = platformSelector{}
			s.targetGate = tc.gate
			created := &capturingCommands{}
			s.commandRepo = created
			run.Context = map[string]any{"targets": tc.targets}
			if tc.routing != nil {
				run.Context[scanrun.RunContextKeySensorRouting] = tc.routing
			}
			if tc.group != "" {
				run.Context["asset_group_id"] = tc.group
			}
			if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
				t.Fatal(err)
			}
			if len(created.cmds) != 1 {
				t.Fatalf("commands = %d", len(created.cmds))
			}
			if got := created.cmds[0].IsPlatformJob; got != tc.platform {
				t.Fatalf("platform job = %v, want %v", got, tc.platform)
			}
		})
	}
}

// The check sees the step's own targets, and a run with the zero asset
// group id (no group) is not taken for an asset-group run.
func TestStepDispatch_SharedCheckSeesTheStepTargets(t *testing.T) {
	s, run, _, _, _ := gatingFixture(map[string]scanrun.StepRunStatus{"a": scanrun.StepRunStatusPending}, nil)
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.ScanWorkflowID)
	tpl.Steps[0].Tool = "nuclei"
	tpl.Settings.SensorPreference = scanworkflow.SensorPreferencePlatform
	s.sensorRepo = tenantSensors{id: shared.NewID()}
	s.sensorSelector = platformSelector{}
	var seen []string
	group := true
	s.targetGate = sharedTargetGate{seen: &seen, group: &group}
	created := &capturingCommands{}
	s.commandRepo = created
	run.Context = map[string]any{"targets": []string{"a.example.com", "b.example.com"},
		"asset_group_id": shared.ID{}.String()}
	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || group {
		t.Fatalf("check saw targets %v, asset group %v; want both targets and no group", seen, group)
	}
	if len(created.cmds) != 1 || !created.cmds[0].IsPlatformJob {
		t.Fatalf("want one platform job")
	}
}

// The scan service is the production target gate and carries the check.
var _ PlatformTargetChecker = (*scanapp.Service)(nil)
