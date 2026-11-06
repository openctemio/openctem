package unit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scanrun"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A scan runs as far as the organization's tools and sensors support
// (docs/architecture/scan-stages.md, "Steps nothing here runs"): a step no
// tool or sensor runs is skipped with its reason, required or optional,
// the steps that need it are skipped as DEPENDENCY_SKIPPED, and only a
// trigger in which no step can run is refused (NO_RUNNABLE_STEPS). The
// safety gates still refuse, and a scheduled trigger behaves the same.

// supportedWorkflowScan is a workflow scan with the given steps, nuclei and
// subfinder installed.
func supportedWorkflowScan(deps *testScanServiceDeps, tenantID shared.ID, steps ...*scanworkflow.Step) *scan.Scan {
	deps.toolRepo.addTool("subfinder", true)
	deps.toolRepo.addTool("nuclei", true)
	sc := createTestScanInRepo(deps, tenantID, "Supported "+shared.NewID().String(), scan.ScanTypeWorkflow)
	owner := shared.NewID()
	sc.CreatedBy = &owner
	for i, st := range steps {
		st.ID = shared.NewID()
		st.ScanWorkflowID = *sc.ScanWorkflowID
		st.StepOrder = i + 1
		if st.Condition.Type == "" {
			st.Condition = scanworkflow.AlwaysCondition()
		}
	}
	deps.stepRepo.steps[sc.ScanWorkflowID.String()] = steps
	return sc
}

// memStepRunRepo keeps step runs by run and key, shared by the scan service
// and the scan run service, so a test reads what the trigger recorded.
type memStepRunRepo struct {
	mockStepRunRepo
	mu   sync.Mutex
	rows map[shared.ID]map[string]*scanrundom.StepRun
}

func (m *memStepRunRepo) put(sr *scanrundom.StepRun) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows == nil {
		m.rows = map[shared.ID]map[string]*scanrundom.StepRun{}
	}
	if m.rows[sr.ScanRunID] == nil {
		m.rows[sr.ScanRunID] = map[string]*scanrundom.StepRun{}
	}
	cp := *sr
	m.rows[sr.ScanRunID][sr.StepKey] = &cp
}

func (m *memStepRunRepo) Create(_ context.Context, sr *scanrundom.StepRun) error {
	m.put(sr)
	return nil
}

func (m *memStepRunRepo) Update(_ context.Context, sr *scanrundom.StepRun) error {
	m.put(sr)
	return nil
}

func (m *memStepRunRepo) GetByScanRunID(_ context.Context, runID shared.ID) ([]*scanrundom.StepRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*scanrundom.StepRun, 0, len(m.rows[runID]))
	for _, sr := range m.rows[runID] {
		cp := *sr
		out = append(out, &cp)
	}
	return out, nil
}

func (m *memStepRunRepo) GetByStepKey(_ context.Context, runID shared.ID, key string) (*scanrundom.StepRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sr, ok := m.rows[runID][key]; ok {
		cp := *sr
		return &cp, nil
	}
	return nil, shared.ErrNotFound
}

// step returns the stored step run of key in the run (nil when none).
func (m *memStepRunRepo) step(run *scanrundom.Run, key string) *scanrundom.StepRun {
	if run == nil {
		return nil
	}
	sr, _ := m.GetByStepKey(context.Background(), run.ID, key)
	return sr
}

// newSupportedTestService is newTestScanService with one step run store for
// both services.
func newSupportedTestService(opts ...scanservice.ServiceOption) (*scanservice.Service, *testScanServiceDeps, *memStepRunRepo) {
	deps := &testScanServiceDeps{
		scanRepo:       newMockScanRepo(),
		templateRepo:   newMockTemplateRepo(),
		assetGroupRepo: newMockAssetGroupRepo(),
		runRepo:        newMockRunRepo(),
		stepRepo:       newMockStepRepo(),
		commandRepo:    newMockCommandRepo(),
		toolRepo:       newMockToolRepo(),
		sensorSelector: &mockSensorSelector{available: true},
		secValidator:   &mockSecurityValidator{},
		auditSvc:       &mockAuditService{},
	}
	stepRuns := &memStepRunRepo{}
	log := logger.NewNop()
	svc := scanservice.NewService(deps.scanRepo, deps.templateRepo, deps.assetGroupRepo, deps.runRepo, deps.stepRepo,
		stepRuns, deps.commandRepo, &mockScannerTemplateRepo{}, deps.toolRepo, deps.sensorSelector, deps.secValidator, log,
		allowAllTargetChecks(append([]scanservice.ServiceOption{scanservice.WithAuditService(deps.auditSvc)}, opts...)...)...)
	svc.SetStepQueuer(scanrun.NewService(deps.templateRepo, deps.stepRepo, deps.runRepo,
		stepRuns, newMockSensorRepo(), deps.commandRepo, nil, log, scanrun.WithToolRepo(deps.toolRepo)))
	return svc, deps, stepRuns
}

func commandTools(deps *testScanServiceDeps) []string {
	var out []string
	for _, c := range deps.commandRepo.commands {
		var p map[string]any
		_ = json.Unmarshal(c.Payload, &p)
		name, _ := p["scanner"].(string)
		out = append(out, name)
	}
	return out
}

func triggerInputs(tenantID shared.ID, sc *scan.Scan) map[string]scanservice.TriggerScanExecInput {
	return map[string]scanservice.TriggerScanExecInput{
		"manual": {TenantID: tenantID.String(), ScanID: sc.ID.String(), Interactive: true},
		"scheduled": {TenantID: tenantID.String(), ScanID: sc.ID.String(),
			TriggerType: scanworkflow.TriggerTypeSchedule, SkipIfRunning: true},
	}
}

// A required step whose pinned tool is not installed, and one whose
// capability no tool implements, are skipped with their codes; the other
// step runs; the run starts (it ends partial when its steps settle). The
// same for a manual and a scheduled trigger.
func TestSupported_RequiredToolLessStepSkipped(t *testing.T) {
	for _, mode := range []string{"manual", "scheduled"} {
		t.Run(mode, func(t *testing.T) {
			svc, deps, stepRuns := newSupportedTestService()
			tenantID := shared.NewID()
			sc := supportedWorkflowScan(deps, tenantID,
				&scanworkflow.Step{StepKey: "find", Tool: "subfinder"},
				&scanworkflow.Step{StepKey: "iac", Tool: "checkov"},                        // not installed
				&scanworkflow.Step{StepKey: "shots", Capabilities: []string{"scan.ports"}}, // naabu (its implementation) is not installed
			)
			run, err := svc.TriggerScan(context.Background(), triggerInputs(tenantID, sc)[mode])
			if err != nil {
				t.Fatalf("TriggerScan refused a workflow with a runnable step: %v", err)
			}
			if iac := stepRuns.step(run, "iac"); iac == nil || iac.Status != scanrundom.StepRunStatusSkipped ||
				iac.ErrorCode != scanrundom.FailureToolNotInstalled || !strings.Contains(iac.SkipReason, "checkov") {
				t.Fatalf("iac = %+v, want skipped TOOL_NOT_INSTALLED naming checkov", iac)
			}
			if shots := stepRuns.step(run, "shots"); shots == nil || shots.Status != scanrundom.StepRunStatusSkipped ||
				shots.ErrorCode != scanrundom.FailureNoMatchingTool || !strings.Contains(shots.SkipReason, "scan.ports") {
				t.Fatalf("shots = %+v, want skipped NO_MATCHING_TOOL", shots)
			}
			if got := commandTools(deps); len(got) != 1 || got[0] != "subfinder" {
				t.Fatalf("commands for %v, want only subfinder", got)
			}
			if len(blockedRuns(deps, sc.ID)) != 0 {
				t.Fatal("a run with a runnable step was recorded as blocked")
			}
		})
	}
}

// A step that needs the results of a skipped step is skipped as
// DEPENDENCY_SKIPPED; an independent step still runs.
func TestSupported_DependentStepSkipped(t *testing.T) {
	svc, deps, stepRuns := newSupportedTestService()
	tenantID := shared.NewID()
	sc := supportedWorkflowScan(deps, tenantID,
		&scanworkflow.Step{StepKey: "iac", Tool: "checkov"},
		&scanworkflow.Step{StepKey: "after", Tool: "nuclei", DependsOn: []string{"iac"}},
		&scanworkflow.Step{StepKey: "find", Tool: "subfinder"},
	)
	run, err := svc.TriggerScan(context.Background(), triggerInputs(tenantID, sc)["manual"])
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	after := stepRuns.step(run, "after")
	if after == nil || after.Status != scanrundom.StepRunStatusSkipped || after.ErrorCode != scanrundom.FailureDependencySkipped ||
		!strings.Contains(after.SkipReason, `"iac"`) {
		t.Fatalf("after = %+v, want DEPENDENCY_SKIPPED naming iac", after)
	}
	if got := commandTools(deps); len(got) != 1 || got[0] != "subfinder" {
		t.Fatalf("commands for %v, want only subfinder", got)
	}
}

// No step can run: the trigger is refused as a blocked run with
// NO_RUNNABLE_STEPS naming what is missing, and nothing is dispatched. The
// same for a scheduled trigger.
func TestSupported_NoRunnableStepsBlocked(t *testing.T) {
	for _, mode := range []string{"manual", "scheduled"} {
		t.Run(mode, func(t *testing.T) {
			svc, deps, _ := newSupportedTestService()
			tenantID := shared.NewID()
			sc := supportedWorkflowScan(deps, tenantID,
				&scanworkflow.Step{StepKey: "iac", Name: "IaC", Tool: "checkov"},
				&scanworkflow.Step{StepKey: "shots", Name: "Ports", Capabilities: []string{"scan.ports"}},
				&scanworkflow.Step{StepKey: "after", Tool: "nuclei", DependsOn: []string{"iac"}},
			)
			_, err := svc.TriggerScan(context.Background(), triggerInputs(tenantID, sc)[mode])
			if wildcardCode(err) != scanservice.CodeNoRunnableSteps || !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("err = %v, want %s", err, scanservice.CodeNoRunnableSteps)
			}
			for _, want := range []string{"IaC", "checkov", "Ports", "scan.ports"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not name %q", err.Error(), want)
				}
			}
			b := blockedRuns(deps, sc.ID)
			if len(b) != 1 || b[0].RefusalCode != scanservice.CodeNoRunnableSteps {
				t.Fatalf("blocked runs = %+v, want one NO_RUNNABLE_STEPS", b)
			}
			if mode == "scheduled" && b[0].TriggerType != scanworkflow.TriggerTypeSchedule {
				t.Errorf("blocked run trigger = %s, want schedule", b[0].TriggerType)
			}
			if dispatchedRuns(deps) != 0 || len(deps.commandRepo.commands) != 0 {
				t.Fatal("a refused trigger dispatched work")
			}
		})
	}
}

// tenantAvailability answers per tenant: only owner has sensors with the
// tools; any other tenant sees no sensor.
type tenantAvailability struct{ owner shared.ID }

func (a tenantAvailability) ToolAvailabilityFor(_ context.Context, tenantID shared.ID, _ *shared.ID, name string) (*sensordom.ToolAvailability, error) {
	if tenantID == a.owner {
		return &sensordom.ToolAvailability{Name: name, Enabled: true, Status: sensordom.ToolReady, SensorsOnline: 1, SensorsTotal: 1}, nil
	}
	return &sensordom.ToolAvailability{Name: name, Enabled: true, Status: sensordom.ToolNoSensor}, nil
}

// Cross-tenant negative: another organization's sensors never make a step
// runnable. The organization without a sensor for nuclei gets that step
// skipped (NO_SENSOR_FOR_TOOL) and, with nothing else to run, a blocked run;
// the organization with the sensor runs it.
func TestSupported_OtherTenantsSensorNeverCounts(t *testing.T) {
	other := shared.NewID()
	svc, deps, _ := newSupportedTestService(scanservice.WithToolAvailability(tenantAvailability{owner: other}))
	tenantID := shared.NewID()
	sc := supportedWorkflowScan(deps, tenantID, &scanworkflow.Step{StepKey: "vulns", Tool: "nuclei"})
	_, err := svc.TriggerScan(context.Background(), triggerInputs(tenantID, sc)["manual"])
	if wildcardCode(err) != scanservice.CodeNoRunnableSteps || !strings.Contains(err.Error(), "nuclei") {
		t.Fatalf("err = %v, want NO_RUNNABLE_STEPS (no sensor of this organization has nuclei)", err)
	}
	if len(deps.commandRepo.commands) != 0 {
		t.Fatal("dispatched on another organization's sensor")
	}

	own := supportedWorkflowScan(deps, other, &scanworkflow.Step{StepKey: "vulns", Tool: "nuclei"})
	if _, err := svc.TriggerScan(context.Background(), triggerInputs(other, own)["manual"]); err != nil {
		t.Fatalf("the organization with the sensor: %v", err)
	}
}

// A step no sensor here may run is skipped with NO_SENSOR_FOR_TOOL while the
// others run.
type oneToolWithoutSensor struct{ tool string }

func (a oneToolWithoutSensor) ToolAvailabilityFor(_ context.Context, _ shared.ID, _ *shared.ID, name string) (*sensordom.ToolAvailability, error) {
	if name == a.tool {
		return &sensordom.ToolAvailability{Name: name, Enabled: true, Status: sensordom.ToolNoSensor}, nil
	}
	return &sensordom.ToolAvailability{Name: name, Enabled: true, Status: sensordom.ToolReady, SensorsOnline: 1, SensorsTotal: 1}, nil
}

func TestSupported_StepWithoutSensorSkipped(t *testing.T) {
	svc, deps, stepRuns := newSupportedTestService(scanservice.WithToolAvailability(oneToolWithoutSensor{tool: "nuclei"}))
	tenantID := shared.NewID()
	sc := supportedWorkflowScan(deps, tenantID,
		&scanworkflow.Step{StepKey: "find", Tool: "subfinder"},
		&scanworkflow.Step{StepKey: "vulns", Tool: "nuclei"},
	)
	run, err := svc.TriggerScan(context.Background(), triggerInputs(tenantID, sc)["manual"])
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	if v := stepRuns.step(run, "vulns"); v == nil || v.ErrorCode != scanrundom.FailureNoSensorForTool || !strings.Contains(v.SkipReason, "nuclei") {
		t.Fatalf("vulns = %+v, want skipped NO_SENSOR_FOR_TOOL", v)
	}
	if got := commandTools(deps); len(got) != 1 || got[0] != "subfinder" {
		t.Fatalf("commands for %v, want only subfinder", got)
	}
}

// Safety gates: refuse even though some steps would be skipped and others
// could run. A skipped step never opens a way around them.

type notEntitled struct{}

func (notEntitled) Check(context.Context, shared.ID, limits.Key, int) error { return nil }
func (notEntitled) Allowed(context.Context, shared.ID, string) (bool, error) {
	return false, nil
}

type refuseApproval struct{}

func (refuseApproval) CheckRun(context.Context, *scan.Scan, scangov.Definition, scangov.Facts, string) error {
	return shared.NewDomainError("SCAN_APPROVAL_REQUIRED", "this scan needs an approval", shared.ErrForbidden)
}

type excludeAll struct{}

func (excludeAll) ExcludedTargets(_ context.Context, _ string, c []scope.ExclusionCandidate) (map[shared.ID]bool, error) {
	out := map[shared.ID]bool{}
	for _, x := range c {
		out[x.ID] = true
	}
	return out, nil
}

func TestSupported_SafetyGatesStillRefuse(t *testing.T) {
	steps := func() []*scanworkflow.Step {
		return []*scanworkflow.Step{
			{StepKey: "find", Tool: "subfinder"},
			{StepKey: "vulns", Tool: "nuclei"},
			{StepKey: "iac", Tool: "checkov"}, // skipped: not installed
		}
	}
	cases := []struct {
		name  string
		opts  []scanservice.ServiceOption
		setup func(svc *scanservice.Service, sc *scan.Scan)
		code  string
	}{
		{name: "passive-only entitlement", opts: []scanservice.ServiceOption{scanservice.WithSharedScanLimits(notEntitled{})},
			code: scanservice.CodeActiveScanningNotEntitled},
		{name: "approval", setup: func(svc *scanservice.Service, _ *scan.Scan) { svc.SetApprovalGate(refuseApproval{}, nil) },
			code: "SCAN_APPROVAL_REQUIRED"},
		{name: "scope", opts: []scanservice.ServiceOption{scanservice.WithScopeExclusionFilter(excludeAll{})},
			code: "ALL_TARGETS_EXCLUDED"},
	}
	for _, c := range cases {
		for _, mode := range []string{"manual", "scheduled"} {
			t.Run(c.name+"/"+mode, func(t *testing.T) {
				svc, deps, _ := newSupportedTestService(c.opts...)
				tenantID := shared.NewID()
				sc := supportedWorkflowScan(deps, tenantID, steps()...)
				if c.setup != nil {
					c.setup(svc, sc)
				}
				_, err := svc.TriggerScan(context.Background(), triggerInputs(tenantID, sc)[mode])
				if wildcardCode(err) != c.code {
					t.Fatalf("err = %v, want %s", err, c.code)
				}
				if len(deps.commandRepo.commands) != 0 || dispatchedRuns(deps) != 0 {
					t.Fatal("a refused trigger dispatched work")
				}
			})
		}
	}
}

// The intensity gate: a step above the scan's intensity is never
// dispatched, whatever else is skipped.
func TestSupported_IntensityStillGates(t *testing.T) {
	svc, deps, stepRuns := newSupportedTestService()
	tenantID := shared.NewID()
	sc := supportedWorkflowScan(deps, tenantID,
		&scanworkflow.Step{StepKey: "find", Tool: "subfinder"},
		&scanworkflow.Step{StepKey: "vulns", Tool: "nuclei"},
		&scanworkflow.Step{StepKey: "iac", Tool: "checkov"},
	)
	sc.Intensity = scan.IntensityPassive
	run, err := svc.TriggerScan(context.Background(), triggerInputs(tenantID, sc)["manual"])
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	for _, tool := range commandTools(deps) {
		if tool == "nuclei" {
			t.Fatal("a step above the scan's intensity was dispatched")
		}
	}
	if v := stepRuns.step(run, "vulns"); v == nil || v.Status != scanrundom.StepRunStatusSkipped {
		t.Fatalf("vulns = %+v, want skipped by the intensity", v)
	}
}

// Creating a workflow scan whose steps have no tool here is never refused:
// the run decides what runs.
func TestSupported_CreateNeverRefusesForMissingTools(t *testing.T) {
	svc, deps, _ := newSupportedTestService()
	tenantID := shared.NewID()
	sc := supportedWorkflowScan(deps, tenantID,
		&scanworkflow.Step{StepKey: "iac", Tool: "checkov"},
		&scanworkflow.Step{StepKey: "shots", Capabilities: []string{"scan.ports"}},
	)
	created, err := svc.CreateScan(context.Background(), scanservice.CreateScanInput{
		TenantID: tenantID.String(), Name: "no tools yet", ScanType: string(scan.ScanTypeWorkflow),
		ScanWorkflowID: sc.ScanWorkflowID.String(), Targets: []string{"example.com"},
	})
	if err != nil || created == nil {
		t.Fatalf("CreateScan refused a workflow without tools: %v", err)
	}
}
