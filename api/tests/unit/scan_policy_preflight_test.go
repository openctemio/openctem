package unit

import (
	"context"
	"errors"
	"strings"
	"testing"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The scan-trigger preflight against the sensors' reported local policies
// (research/25 §3.6, T-P0a/T-P0b): batches are pinned only to sensors that
// accept them, and a trigger no sensor would accept is refused with the
// layer and rule, leaving no command behind.

type fakeSensorLister struct {
	sensors []*sensor.Sensor
	err     error
}

func (f fakeSensorLister) FindAvailableWithCapacity(context.Context, shared.ID, []string, string) ([]*sensor.Sensor, error) {
	return f.sensors, f.err
}

type fixedPrivatePolicy bool

func (p fixedPrivatePolicy) RequiresLocalPolicyForPrivateTargets(context.Context, shared.ID) (bool, error) {
	return bool(p), nil
}

func newPolicyScanService(dir *fakeZoneDir, lister scanservice.AvailableSensorLister, private scanservice.PrivateTargetPolicy) (*scanservice.Service, *testScanServiceDeps) {
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
	opts := []scanservice.ServiceOption{scanservice.WithAuditService(deps.auditSvc), scanservice.WithDispatchPolicy(lister, private)}
	if dir != nil {
		opts = append(opts, scanservice.WithScanZones(dir, nil))
	}
	svc := scanservice.NewService(deps.scanRepo, deps.templateRepo, deps.assetGroupRepo, deps.runRepo,
		deps.stepRepo, &mockStepRunRepo{}, deps.commandRepo, &mockScannerTemplateRepo{}, &mockTemplateSourceRepo{},
		deps.toolRepo, &mockTemplateSyncer{}, deps.sensorSelector, deps.secValidator, logger.NewNop(), allowAllTargetChecks(opts...)...)
	deps.toolRepo.tools["nuclei"] = &tool.Tool{ID: shared.NewID(), Name: "nuclei", IsActive: true, SupportedTargets: []string{"url", "domain", "ip"}}
	return svc, deps
}

func noInteractsh() *sensor.LocalPolicyReport {
	return &sensor.LocalPolicyReport{State: sensor.LocalPolicyEnforced,
		Summary: &sensor.LocalPolicySummary{TargetsAllow: -1, AllowPrivate: true, Tools: []string{"nuclei"}}}
}

func policyCode(err error) string {
	var de *shared.DomainError
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

// T-P0a: two sensors in a zone, one refuses interactsh: the scan that asks
// for it is pinned to the other.
func TestPolicyPreflight_PinsToTheSensorThatAccepts(t *testing.T) {
	tenant := shared.NewID()
	strict, open := shared.NewID(), shared.NewID()
	dc := zone(t, tenant, "dc", false, []shared.ID{strict, open}, "10.1.0.0/16")
	dir := &fakeZoneDir{zones: []*scanzone.Zone{dc}, routable: map[shared.ID][]scanzone.SensorCandidate{dc.ID: {
		// strict is the least loaded: without the pre-check it would win.
		{ID: strict, ActiveCommands: 0, LocalPolicy: noInteractsh()},
		{ID: open, ActiveCommands: 3, LocalPolicy: &sensor.LocalPolicyReport{State: sensor.LocalPolicyAbsent}},
	}}}
	svc, deps := newPolicyScanService(dir, nil, nil)
	sc := singleScan(t, deps, tenant, "nuclei", 1, map[string]any{"allow_interactsh": true}, "10.1.0.5", "10.1.0.6")
	if _, err := trigger(t, svc, sc); err != nil {
		t.Fatal(err)
	}
	if len(deps.commandRepo.commands) != 2 {
		t.Fatalf("commands = %d, want 2", len(deps.commandRepo.commands))
	}
	for _, c := range deps.commandRepo.commands {
		if c.SensorID == nil || *c.SensorID != open {
			t.Errorf("job pinned to %v, want the sensor that allows interactsh", c.SensorID)
		}
	}

	// Without interactsh the least loaded sensor gets the work, as before.
	svc, deps = newPolicyScanService(dir, nil, nil)
	sc = singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.5")
	if _, err := trigger(t, svc, sc); err != nil {
		t.Fatal(err)
	}
	for _, c := range deps.commandRepo.commands {
		if c.SensorID == nil || *c.SensorID != strict {
			t.Errorf("plain job pinned to %v, want the least loaded sensor", c.SensorID)
		}
	}
}

// T-P0b: every sensor of the zone refuses: the trigger is refused, naming
// the layer and rule, and no command or run is left behind.
func TestPolicyPreflight_AllSensorsRefuse(t *testing.T) {
	tenant := shared.NewID()
	a, b := shared.NewID(), shared.NewID()
	dmz := zone(t, tenant, "DMZ", false, []shared.ID{a, b}, "10.9.0.0/16")
	dir := &fakeZoneDir{zones: []*scanzone.Zone{dmz}, routable: map[shared.ID][]scanzone.SensorCandidate{dmz.ID: {
		{ID: a, LocalPolicy: noInteractsh()}, {ID: b, LocalPolicy: noInteractsh()},
	}}}
	svc, deps := newPolicyScanService(dir, nil, nil)
	sc := singleScan(t, deps, tenant, "nuclei", 1, map[string]any{"allow_interactsh": true}, "10.9.0.1")
	_, err := trigger(t, svc, sc)
	if policyCode(err) != "SENSOR_POLICY_REFUSED" {
		t.Fatalf("err = %v, want SENSOR_POLICY_REFUSED", err)
	}
	for _, want := range []string{"allow_interactsh", "local policy", "2 of 2", `scan zone "DMZ"`, "network owner"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err.Error(), want)
		}
	}
	if len(deps.commandRepo.commands) != 0 || dispatchedRuns(deps) != 0 {
		t.Errorf("left %d command(s) and %d run(s) behind", len(deps.commandRepo.commands), dispatchedRuns(deps))
	}
	if b := blockedRuns(deps, sc.ID); len(b) != 1 || b[0].RefusalCode != "SENSOR_POLICY_REFUSED" {
		t.Errorf("the refusal is not one blocked run: %+v", b)
	}
}

// One zone blocked, another fine: the run goes ahead for what can run and
// the blocked targets are reported in the run warnings.
func TestPolicyPreflight_PartialBlockWarns(t *testing.T) {
	tenant := shared.NewID()
	a, b := shared.NewID(), shared.NewID()
	strictZone := zone(t, tenant, "strict", false, []shared.ID{a}, "10.1.0.0/16")
	openZone := zone(t, tenant, "open", false, []shared.ID{b}, "10.2.0.0/16")
	dir := &fakeZoneDir{zones: []*scanzone.Zone{strictZone, openZone}, routable: map[shared.ID][]scanzone.SensorCandidate{
		strictZone.ID: {{ID: a, LocalPolicy: noInteractsh()}},
		openZone.ID:   {{ID: b}},
	}}
	svc, deps := newPolicyScanService(dir, nil, nil)
	sc := singleScan(t, deps, tenant, "nuclei", 1, map[string]any{"allow_interactsh": true}, "10.1.0.1", "10.2.0.1")
	run, err := trigger(t, svc, sc)
	if err != nil {
		t.Fatal(err)
	}
	byTarget := commandsByTarget(t, deps)
	if byTarget["10.1.0.1"] != nil || byTarget["10.2.0.1"] == nil {
		t.Fatalf("dispatched %v, want only the open zone's target", byTarget)
	}
	if !hasWarning(warningsOf(run), "10.1.0.1 not scanned") || !hasWarning(warningsOf(run), "allow_interactsh") {
		t.Errorf("warnings %v do not explain the blocked target", warningsOf(run))
	}
}

// Outside zones: the tenant's available sensors are judged; none accepting
// refuses the trigger, one accepting lets it through; a failed lookup
// fails closed.
func TestPolicyPreflight_Unzoned(t *testing.T) {
	tenant := shared.NewID()
	httpxOnly := &sensor.Sensor{ID: shared.NewID(), TenantID: &tenant, LocalPolicy: &sensor.LocalPolicyReport{
		State: sensor.LocalPolicyEnforced, Summary: &sensor.LocalPolicySummary{TargetsAllow: -1, Tools: []string{"httpx"}}}}
	legacy := &sensor.Sensor{ID: shared.NewID(), TenantID: &tenant}

	svc, deps := newPolicyScanService(&fakeZoneDir{}, fakeSensorLister{sensors: []*sensor.Sensor{httpxOnly}}, nil)
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "203.0.113.5")
	_, err := trigger(t, svc, sc)
	if policyCode(err) != "SENSOR_POLICY_REFUSED" || !strings.Contains(err.Error(), "tools.allow") {
		t.Fatalf("err = %v, want SENSOR_POLICY_REFUSED naming tools.allow", err)
	}
	if len(deps.commandRepo.commands) != 0 {
		t.Error("a command was created that no sensor accepts")
	}

	svc, deps = newPolicyScanService(&fakeZoneDir{}, fakeSensorLister{sensors: []*sensor.Sensor{httpxOnly, legacy}}, nil)
	sc = singleScan(t, deps, tenant, "nuclei", 1, nil, "203.0.113.5")
	if _, err := trigger(t, svc, sc); err != nil {
		t.Fatalf("a sensor accepts: %v", err)
	}

	svc, deps = newPolicyScanService(&fakeZoneDir{}, fakeSensorLister{err: errors.New("db down")}, nil)
	sc = singleScan(t, deps, tenant, "nuclei", 1, nil, "203.0.113.5")
	if _, err := trigger(t, svc, sc); err == nil || len(deps.commandRepo.commands) != 0 {
		t.Fatalf("lookup failure: err %v, %d command(s)", err, len(deps.commandRepo.commands))
	}

	// No sensor available at all: the preflight does not decide (the job
	// waits, as before).
	svc, deps = newPolicyScanService(&fakeZoneDir{}, fakeSensorLister{}, nil)
	sc = singleScan(t, deps, tenant, "nuclei", 1, nil, "203.0.113.5")
	if _, err := trigger(t, svc, sc); err != nil {
		t.Fatalf("no sensor available: %v", err)
	}
}

// The tenant's private-target switch at trigger: a zone whose sensors run
// without a local policy cannot take private targets; the refusal names
// the platform-side layer.
func TestPolicyPreflight_PrivateTargetsNeedLocalPolicy(t *testing.T) {
	tenant := shared.NewID()
	a := shared.NewID()
	dc := zone(t, tenant, "dc", false, []shared.ID{a}, "10.1.0.0/16")
	dir := &fakeZoneDir{zones: []*scanzone.Zone{dc}, routable: map[shared.ID][]scanzone.SensorCandidate{
		dc.ID: {{ID: a, LocalPolicy: &sensor.LocalPolicyReport{State: sensor.LocalPolicyAbsent}}},
	}}
	svc, deps := newPolicyScanService(dir, nil, fixedPrivatePolicy(true))
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1")
	_, err := trigger(t, svc, sc)
	if policyCode(err) != "SENSOR_POLICY_REFUSED" || !strings.Contains(err.Error(), "managed policy") ||
		!strings.Contains(err.Error(), "private_targets_require_local_policy") {
		t.Fatalf("err = %v", err)
	}
	// The switch off: dispatched as before.
	svc, deps = newPolicyScanService(dir, nil, fixedPrivatePolicy(false))
	sc = singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1")
	if _, err := trigger(t, svc, sc); err != nil {
		t.Fatal(err)
	}
}
