package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	pipelinedom "github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
)

// platformTools is a tool registry with the given active platform tools.
type platformTools struct {
	tool.Repository
	names map[string]bool
}

func (p platformTools) GetPlatformToolByName(_ context.Context, name string) (*tool.Tool, error) {
	if p.names[name] {
		return &tool.Tool{Name: name, IsActive: true}, nil
	}
	return nil, shared.ErrNotFound
}

func (p platformTools) FindByCapabilities(context.Context, shared.ID, []string) (*tool.Tool, error) {
	return nil, nil
}

func decodePayload(t *testing.T, raw string) map[string]any {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// F1 end to end on the pipeline dispatcher: a step that names only a
// capability is queued with the resolved tool in `scanner`. It used to reach
// the sensor with no scanner and fail with "scanner not found: ".
func TestStepDispatch_CapabilityOnlyStepNamesItsScanner(t *testing.T) {
	s, run, store, _, cmds := gatingFixture(map[string]pipelinedom.StepRunStatus{"a": pipelinedom.StepRunStatusPending}, nil)
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.PipelineID)
	tpl.Steps[0].Capabilities = []string{"recon", "dns"}
	s.toolRepo = platformTools{names: map[string]bool{"dnsx": true}}
	run.Context = map[string]any{"targets": []string{"example.com"}, pipelinedom.RunContextKeyScanZoneID: shared.NewID().String()}

	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	if len(cmds.created) != 1 {
		t.Fatalf("commands = %d (step %s: %s)", len(cmds.created), store.rows["a"].Status, store.rows["a"].ErrorMessage)
	}
	p := decodePayload(t, cmds.created[0])
	if p["scanner"] != "dnsx" || p["preferred_tool"] != "dnsx" {
		t.Fatalf("scanner = %v, preferred_tool = %v", p["scanner"], p["preferred_tool"])
	}
	if tpl.Steps[0].Tool != "" {
		t.Fatal("the template step was changed by dispatch")
	}
}

// A capability no active tool implements fails the step with the planner's
// code; nothing reaches a sensor.
func TestStepDispatch_UnresolvableCapabilityFailsTheStep(t *testing.T) {
	s, run, store, _, cmds := gatingFixture(map[string]pipelinedom.StepRunStatus{"a": pipelinedom.StepRunStatusPending}, nil)
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.PipelineID)
	tpl.Steps[0].Capabilities = []string{"portscan", "dns"}
	s.toolRepo = platformTools{names: map[string]bool{"dnsx": true, "naabu": true}}

	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	if len(cmds.created) != 0 {
		t.Fatalf("a command was created: %v", cmds.created)
	}
	if a := store.rows["a"]; a.Status != pipelinedom.StepRunStatusFailed || a.ErrorCode != "STEP_CAPABILITY_AMBIGUOUS" {
		t.Fatalf("step a = %s/%s", a.Status, a.ErrorCode)
	}
}

// QueueRunStep (the scan trigger's door into this dispatcher) queues one
// step with the template's settings, and fails the step with the reason's
// code when it cannot.
func TestQueueRunStep(t *testing.T) {
	s, run, store, _, cmds := gatingFixture(map[string]pipelinedom.StepRunStatus{"a": pipelinedom.StepRunStatusPending}, nil)
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.PipelineID)
	s.templateRepo = fixedTemplate{tpl: tpl}
	step := tpl.Steps[0]
	step.Tool = "subfinder"
	run.Context = map[string]any{"targets": []string{"example.com"}, pipelinedom.RunContextKeyScanZoneID: shared.NewID().String()}

	if err := s.QueueRunStep(context.Background(), run, step); err != nil {
		t.Fatal(err)
	}
	if len(cmds.created) != 1 || decodePayload(t, cmds.created[0])["scanner"] != "subfinder" {
		t.Fatalf("commands = %v", cmds.created)
	}
	if a := store.rows["a"]; a.Status != pipelinedom.StepRunStatusQueued {
		t.Fatalf("step a = %s", a.Status)
	}

	bad := &pipelinedom.Step{ID: shared.NewID(), StepKey: "a", Capabilities: []string{"portscan"}}
	s.toolRepo = platformTools{names: map[string]bool{}}
	store.rows["a"] = *pipelinedom.NewStepRun(run.ID, bad.ID, "a", 1, 0)
	run.StepRuns = nil
	if err := s.QueueRunStep(context.Background(), run, bad); err == nil {
		t.Fatal("an unresolvable step was queued")
	}
	if a := store.rows["a"]; a.Status != pipelinedom.StepRunStatusFailed || a.ErrorCode != "NO_MATCHING_TOOL" {
		t.Fatalf("step a = %s/%s", a.Status, a.ErrorCode)
	}
}

// fixedTemplate also answers GetByID for QueueRunStep.
func (f fixedTemplate) GetByID(context.Context, shared.ID) (*pipelinedom.Template, error) {
	return f.tpl, nil
}

// tenantSensors finds one tenant sensor for any tool.
type tenantSensors struct {
	sensor.Repository
	id shared.ID
}

func (t tenantSensors) FindAvailableWithTool(context.Context, shared.ID, string) (*sensor.Sensor, error) {
	return &sensor.Sensor{ID: t.id}, nil
}

// platformSelector always picks platform sensors.
type platformSelector struct{}

func (platformSelector) SelectSensor(context.Context, SelectSensorRequest) (*SelectSensorResult, error) {
	return &SelectSensorResult{IsPlatform: true}, nil
}
func (platformSelector) CanUsePlatformSensors(context.Context, shared.ID) (bool, string) {
	return true, ""
}

// A scan that runs on the tenant's own sensors only never has a step sent
// to platform sensors, even when the template prefers them.
func TestStepDispatch_TenantRunnerOnlyNeverGoesToPlatform(t *testing.T) {
	s, run, _, _, cmds := gatingFixture(map[string]pipelinedom.StepRunStatus{"a": pipelinedom.StepRunStatusPending}, nil)
	tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.PipelineID)
	tpl.Steps[0].Tool = "nuclei"
	tpl.Settings.SensorPreference = pipelinedom.SensorPreferencePlatform
	own := shared.NewID()
	s.sensorRepo = tenantSensors{id: own}
	s.sensorSelector = platformSelector{}
	created := &capturingCommands{}
	s.commandRepo = created
	_ = cmds

	run.Context = map[string]any{"targets": []string{"example.com"}, "tenant_runner_only": true}
	if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
		t.Fatal(err)
	}
	if len(created.cmds) != 1 {
		t.Fatalf("commands = %d", len(created.cmds))
	}
	// The tenant's own sensors take it, and none is chosen up front: any
	// of them that has the tool may claim it (research/49 W27).
	c := created.cmds[0]
	if c.IsPlatformJob || c.SensorID != nil {
		t.Fatalf("platform=%v sensor=%v, want an unpinned tenant command", c.IsPlatformJob, c.SensorID)
	}
	_ = own
}

// A step command is never pinned to one sensor, whatever the preference:
// auto with a tenant sensor that has the tool leaves it to every such
// sensor; platform routing makes it a platform job.
func TestStepDispatch_NeverPinsASensor(t *testing.T) {
	for _, tc := range []struct {
		name     string
		pref     pipelinedom.SensorPreference
		selector SensorSelector
		platform bool
	}{
		{"auto, tenant sensor", pipelinedom.SensorPreferenceAuto, nil, false},
		{"tenant", pipelinedom.SensorPreferenceTenant, nil, false},
		{"platform", pipelinedom.SensorPreferencePlatform, platformSelector{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, run, _, _, _ := gatingFixture(map[string]pipelinedom.StepRunStatus{"a": pipelinedom.StepRunStatusPending}, nil)
			tpl, _ := s.templateRepo.GetWithSteps(context.Background(), run.PipelineID)
			tpl.Steps[0].Tool = "nuclei"
			tpl.Settings.SensorPreference = tc.pref
			s.sensorRepo = tenantSensors{id: shared.NewID()}
			s.sensorSelector = tc.selector
			created := &capturingCommands{}
			s.commandRepo = created
			run.Context = map[string]any{"targets": []string{"example.com"}}
			if err := s.scheduleRunnableSteps(context.Background(), run, tpl); err != nil {
				t.Fatal(err)
			}
			if len(created.cmds) != 1 {
				t.Fatalf("commands = %d", len(created.cmds))
			}
			c := created.cmds[0]
			if c.SensorID != nil || c.IsPlatformJob != tc.platform {
				t.Fatalf("platform=%v sensor=%v, want platform=%v and no pinned sensor", c.IsPlatformJob, c.SensorID, tc.platform)
			}
		})
	}
}

type capturingCommands struct {
	command.Repository
	cmds []*command.Command
}

func (c *capturingCommands) Create(_ context.Context, cmd *command.Command) error {
	c.cmds = append(c.cmds, cmd)
	return nil
}
