package unit

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scope"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// RFC-023 Phase 1: trigger-time zone routing (D4-D6, D14) through the real
// scan service, with in-memory repositories.

// fakeZoneDir serves a tenant's zones and their routable sensors.
type fakeZoneDir struct {
	zones    []*scanzone.Zone
	routable map[shared.ID][]scanzone.SensorCandidate
	err      error
	tools    []string // tools asked for
}

func (f *fakeZoneDir) List(_ context.Context, _ shared.ID) ([]*scanzone.Zone, error) {
	return f.zones, f.err
}

func (f *fakeZoneDir) RoutableSensors(_ context.Context, _ shared.ID, ids []shared.ID, tool string) (map[shared.ID][]scanzone.SensorCandidate, error) {
	f.tools = append(f.tools, tool)
	out := map[shared.ID][]scanzone.SensorCandidate{}
	for _, id := range ids {
		out[id] = f.routable[id]
	}
	return out, nil
}

type tableResolver map[string][]string

func (r tableResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	addrs, ok := r[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

type valueExclusions map[string]bool

func (v valueExclusions) ExcludedTargets(_ context.Context, _ string, cs []scope.ExclusionCandidate) (map[shared.ID]bool, error) {
	out := map[shared.ID]bool{}
	for _, c := range cs {
		for _, val := range c.Values {
			if v[val] {
				out[c.ID] = true
			}
		}
	}
	return out, nil
}

func zone(t *testing.T, tenant shared.ID, name string, isDefault bool, sensors []shared.ID, ranges ...string) *scanzone.Zone {
	t.Helper()
	z, err := scanzone.NewZone(tenant, name, "", isDefault, ranges, nil)
	if err != nil {
		t.Fatalf("zone %s: %v", name, err)
	}
	z.SensorIDs = sensors
	return z
}

func candidates(ids ...shared.ID) []scanzone.SensorCandidate {
	out := make([]scanzone.SensorCandidate, 0, len(ids))
	for _, id := range ids {
		out = append(out, scanzone.SensorCandidate{ID: id, MaxConcurrentJobs: 5})
	}
	return out
}

func newZonedScanService(dir *fakeZoneDir, res tableResolver, excl valueExclusions, extra ...scanservice.ServiceOption) (*scanservice.Service, *testScanServiceDeps) {
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
	opts := []scanservice.ServiceOption{scanservice.WithAuditService(deps.auditSvc)}
	if dir != nil {
		opts = append(opts, scanservice.WithScanZones(dir, res))
	}
	if excl != nil {
		opts = append(opts, scanservice.WithScopeExclusionFilter(excl))
	}
	svc := scanservice.NewService(deps.scanRepo, deps.templateRepo, deps.assetGroupRepo, deps.runRepo,
		deps.stepRepo, &mockStepRunRepo{}, deps.commandRepo, &mockScannerTemplateRepo{}, &mockTemplateSourceRepo{},
		deps.toolRepo, &mockTemplateSyncer{}, deps.sensorSelector, deps.secValidator, logger.NewNop(), allowAllTargetChecks(append(opts, extra...)...)...)
	deps.toolRepo.tools["nuclei"] = &tool.Tool{ID: shared.NewID(), Name: "nuclei", IsActive: true, SupportedTargets: []string{"url", "domain", "ip"}}
	deps.toolRepo.tools["betterleaks"] = &tool.Tool{ID: shared.NewID(), Name: "betterleaks", IsActive: true, SupportedTargets: []string{"file", "repository"}}
	return svc, deps
}

func singleScan(t *testing.T, deps *testScanServiceDeps, tenant shared.ID, scanner string, perJob int, config map[string]any, targets ...string) *scan.Scan {
	t.Helper()
	s, err := scan.NewScanWithTargets(tenant, "zoned "+scanner, targets, scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	if config == nil {
		config = map[string]any{}
	}
	if err := s.SetSingleScanner(scanner, config, perJob); err != nil {
		t.Fatal(err)
	}
	deps.scanRepo.addScan(s)
	return s
}

func trigger(t *testing.T, svc *scanservice.Service, s *scan.Scan) (*scanrun.Run, error) {
	t.Helper()
	return svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{TenantID: s.TenantID.String(), ScanID: s.ID.String()})
}

// payloadTargets returns the `targets` a command carries to the sensor.
func payloadTargets(t *testing.T, c *commanddom.Command) []string {
	t.Helper()
	var p struct {
		Targets []string       `json:"targets"`
		Config  map[string]any `json:"config"`
		Context map[string]any `json:"context"`
	}
	if err := json.Unmarshal(c.Payload, &p); err != nil {
		t.Fatal(err)
	}
	return p.Targets
}

func commandsByTarget(t *testing.T, deps *testScanServiceDeps) map[string]*commanddom.Command {
	t.Helper()
	out := map[string]*commanddom.Command{}
	for _, c := range deps.commandRepo.commands {
		for _, target := range payloadTargets(t, c) {
			if _, dup := out[target]; dup {
				t.Errorf("target %s dispatched twice", target)
			}
			out[target] = c
		}
	}
	return out
}

func warningsOf(run *scanrun.Run) []string {
	switch w := run.Context["dispatch_warnings"].(type) {
	case []string:
		return w
	default:
		return nil
	}
}

func hasWarning(ws []string, sub string) bool {
	return slices.ContainsFunc(ws, func(w string) bool { return strings.Contains(w, sub) })
}

func TestScanZones_TriggerRoutesBatchesAndPins(t *testing.T) {
	tenant := shared.NewID()
	s1, s1b, s2, s3 := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	dcA := zone(t, tenant, "dc-a", false, []shared.ID{s1, s1b}, "10.1.0.0/16")
	labA := zone(t, tenant, "lab-a", false, []shared.ID{s3}, "10.1.5.0/24") // nested, narrower
	dcB := zone(t, tenant, "dc-b", false, []shared.ID{s2}, "10.2.0.0/16", "fd00:2::/48")
	dir := &fakeZoneDir{
		zones: []*scanzone.Zone{dcA, labA, dcB},
		routable: map[shared.ID][]scanzone.SensorCandidate{
			dcA.ID:  {{ID: s1, ActiveCommands: 1}, {ID: s1b, ActiveCommands: 0}},
			labA.ID: candidates(s3),
			dcB.ID:  candidates(s2),
		},
	}
	res := tableResolver{"db.corp.example": {"10.2.0.9"}}
	svc, deps := newZonedScanService(dir, res, valueExclusions{"10.1.0.2": true})

	sc := singleScan(t, deps, tenant, "nuclei", 1, nil,
		"10.1.0.1", "10.1.0.2", "10.1.0.3", "10.1.5.5", "10.2.0.1", "fd00:2::7",
		"db.corp.example", "192.168.1.1", "nope.corp.example")
	run, err := trigger(t, svc, sc)
	if err != nil {
		t.Fatalf("trigger: %v", err)
	}

	byTarget := commandsByTarget(t, deps)
	want := map[string]struct {
		zone    *scanzone.Zone
		sensors []shared.ID
	}{
		"10.1.0.1":        {dcA, []shared.ID{s1b}},     // least busy first
		"10.1.0.3":        {dcA, []shared.ID{s1, s1b}}, // then the next least busy
		"10.1.5.5":        {labA, []shared.ID{s3}},     // narrowest zone wins
		"10.2.0.1":        {dcB, []shared.ID{s2}},
		"fd00:2::7":       {dcB, []shared.ID{s2}}, // IPv6
		"db.corp.example": {dcB, []shared.ID{s2}}, // hostname, by resolved address
	}
	for target, w := range want {
		c := byTarget[target]
		if c == nil {
			t.Errorf("%s was not dispatched", target)
			continue
		}
		if c.ScanZoneID == nil || *c.ScanZoneID != w.zone.ID {
			t.Errorf("%s: zone = %v, want %s", target, c.ScanZoneID, w.zone.Name)
		}
		if c.SensorID == nil || !slices.Contains(w.sensors, *c.SensorID) {
			t.Errorf("%s: pinned to %v, want one of %v", target, c.SensorID, w.sensors)
		}
		if c.IsPlatformJob {
			t.Errorf("%s: zone job sent to platform sensors", target)
		}
	}
	if byTarget["10.1.0.1"] != nil && byTarget["10.1.0.3"] != nil &&
		*byTarget["10.1.0.1"].SensorID == *byTarget["10.1.0.3"].SensorID {
		t.Error("both dc-a batches went to the same sensor; least-busy balancing did not spread them")
	}
	// Excluded, uncovered and unresolvable targets are never dispatched.
	for _, target := range []string{"10.1.0.2", "192.168.1.1", "nope.corp.example"} {
		if byTarget[target] != nil {
			t.Errorf("%s was dispatched", target)
		}
	}
	if len(deps.commandRepo.commands) != len(want) {
		t.Errorf("commands = %d, want one per target (%d)", len(deps.commandRepo.commands), len(want))
	}
	if run.Context["excluded_target_count"] != 1 {
		t.Errorf("excluded_target_count = %v", run.Context["excluded_target_count"])
	}
	ws := warningsOf(run)
	if !hasWarning(ws, "192.168.1.1 not scanned") || !hasWarning(ws, "nope.corp.example not scanned") {
		t.Errorf("uncovered targets missing from dispatch_warnings: %v", ws)
	}
	if hasWarning(ws, "takes one target per job") {
		t.Errorf("single-target caveat kept although every target got its own job: %v", ws)
	}
	if run.Context["zone_routing"] == nil || run.Context["uncovered_targets"] == nil {
		t.Errorf("routing report missing from run context: %v", run.Context)
	}
	if len(dir.tools) != 1 || dir.tools[0] != "nuclei" {
		t.Errorf("routable sensors asked for tools %v, want the scan's tool", dir.tools)
	}
	// A batch never carries another zone's targets, not even inside its context.
	for _, c := range deps.commandRepo.commands {
		var p map[string]any
		_ = json.Unmarshal(c.Payload, &p)
		ctx, _ := p["context"].(map[string]any)
		for _, k := range []string{"targets", "dispatch_warnings", "zone_routing", "uncovered_targets", "scanner_config"} {
			if _, ok := ctx[k]; ok {
				t.Errorf("batch payload context leaks %q", k)
			}
		}
	}
}

func TestScanZones_BatchesByTargetsPerJobAndRewritesConfigTargets(t *testing.T) {
	tenant := shared.NewID()
	s1 := shared.NewID()
	dc := zone(t, tenant, "dc", false, []shared.ID{s1}, "10.1.0.0/16")
	svc, deps := newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{dc},
		routable: map[shared.ID][]scanzone.SensorCandidate{dc.ID: candidates(s1)}}, nil, nil)

	targets := []string{"10.1.0.1", "10.1.0.2", "10.1.0.3", "10.1.0.4", "10.1.0.5"}
	// A quick scan also stores its targets in the scanner config.
	sc := singleScan(t, deps, tenant, "nuclei", 2, map[string]any{"targets": targets, "severity": "high"}, targets...)
	if _, err := trigger(t, svc, sc); err != nil {
		t.Fatal(err)
	}
	if len(deps.commandRepo.commands) != 3 {
		t.Fatalf("commands = %d, want ceil(5/2) = 3", len(deps.commandRepo.commands))
	}
	for _, c := range deps.commandRepo.commands {
		var p struct {
			Targets []string       `json:"targets"`
			Target  string         `json:"target"`
			Config  map[string]any `json:"config"`
		}
		_ = json.Unmarshal(c.Payload, &p)
		cfgTargets, _ := p.Config["targets"].([]any)
		if len(cfgTargets) != len(p.Targets) {
			t.Errorf("config.targets %v does not match the batch %v", cfgTargets, p.Targets)
		}
		if p.Config["severity"] != "high" {
			t.Error("batch config lost the scanner settings")
		}
		if len(p.Targets) > 1 && p.Target != "" {
			t.Errorf("multi-target batch also sets target=%q (nuclei would scan only it)", p.Target)
		}
	}
}

func TestScanZones_ZoneWithoutHealthySensorQueuesInZone(t *testing.T) {
	tenant := shared.NewID()
	offline := shared.NewID()
	dc := zone(t, tenant, "dc", false, []shared.ID{offline}, "10.1.0.0/16")
	svc, deps := newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{dc}}, nil, nil)
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1")

	run, err := trigger(t, svc, sc)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range deps.commandRepo.commands {
		if c.ScanZoneID == nil || *c.ScanZoneID != dc.ID {
			t.Errorf("queued job not stamped with its zone: %v", c.ScanZoneID)
		}
		if c.SensorID != nil || c.IsPlatformJob {
			t.Errorf("queued zone job pinned to %v / platform=%v; it must wait for a zone sensor", c.SensorID, c.IsPlatformJob)
		}
	}
	if !hasWarning(warningsOf(run), "no assigned sensor") {
		t.Errorf("no warning about the zone without a healthy sensor: %v", warningsOf(run))
	}
}

func TestScanZones_ZoneWithoutSensorsSkipsItsTargets(t *testing.T) {
	tenant := shared.NewID()
	s2 := shared.NewID()
	empty := zone(t, tenant, "empty", false, nil, "10.1.0.0/16")
	dc := zone(t, tenant, "dc", false, []shared.ID{s2}, "10.2.0.0/16")
	svc, deps := newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{empty, dc},
		routable: map[shared.ID][]scanzone.SensorCandidate{dc.ID: candidates(s2)}}, nil, nil)
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1", "10.2.0.1")

	run, err := trigger(t, svc, sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps.commandRepo.commands) != 1 {
		t.Errorf("commands = %d, want only the dc target", len(deps.commandRepo.commands))
	}
	if !hasWarning(warningsOf(run), `"empty" has no sensors`) {
		t.Errorf("warnings = %v", warningsOf(run))
	}
}

func TestScanZones_AllTargetsUncoveredFailsTheTrigger(t *testing.T) {
	tenant := shared.NewID()
	dc := zone(t, tenant, "dc", false, []shared.ID{shared.NewID()}, "10.1.0.0/16")
	svc, deps := newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{dc}}, nil, nil)
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "192.168.1.1", "172.16.0.1")

	_, err := trigger(t, svc, sc)
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != "NO_ZONE_COVERAGE" {
		t.Fatalf("err = %v, want NO_ZONE_COVERAGE", err)
	}
	if len(deps.commandRepo.commands) != 0 {
		t.Error("a command was created for uncovered targets")
	}
}

func TestScanZones_PublicTargets(t *testing.T) {
	tenant := shared.NewID()
	edge, s1 := shared.NewID(), shared.NewID()
	dc := zone(t, tenant, "dc", false, []shared.ID{s1}, "10.1.0.0/16")
	def := zone(t, tenant, "internet", true, []shared.ID{edge})

	// With a default zone, public targets go to its sensors.
	svc, deps := newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{dc, def},
		routable: map[shared.ID][]scanzone.SensorCandidate{def.ID: candidates(edge), dc.ID: candidates(s1)}}, nil, nil)
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "8.8.8.8")
	if _, err := trigger(t, svc, sc); err != nil {
		t.Fatal(err)
	}
	for _, c := range deps.commandRepo.commands {
		if c.ScanZoneID == nil || *c.ScanZoneID != def.ID || c.SensorID == nil || *c.SensorID != edge {
			t.Errorf("public target: zone %v sensor %v, want the default zone's sensor", c.ScanZoneID, c.SensorID)
		}
	}

	// Without a default zone, public targets are dispatched as before zones:
	// unzoned, to any tenant sensor, never silently to platform sensors.
	svc, deps = newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{dc},
		routable: map[shared.ID][]scanzone.SensorCandidate{dc.ID: candidates(s1)}}, nil, nil)
	sc = singleScan(t, deps, tenant, "nuclei", 1, nil, "8.8.8.8")
	if _, err := trigger(t, svc, sc); err != nil {
		t.Fatal(err)
	}
	for _, c := range deps.commandRepo.commands {
		if c.ScanZoneID != nil || c.SensorID != nil || c.IsPlatformJob {
			t.Errorf("unzoned public job: zone %v sensor %v platform %v", c.ScanZoneID, c.SensorID, c.IsPlatformJob)
		}
	}
}

// A tenant without zones keeps the pre-zone dispatch exactly.
func TestScanZones_TenantWithoutZonesUnchanged(t *testing.T) {
	tenant := shared.NewID()
	svc, deps := newZonedScanService(&fakeZoneDir{}, nil, nil)
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "8.8.8.8", "app.example.com")
	run, err := trigger(t, svc, sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps.commandRepo.commands) != 1 {
		t.Fatalf("commands = %d, want the single pre-zone command", len(deps.commandRepo.commands))
	}
	for _, c := range deps.commandRepo.commands {
		if c.ScanZoneID != nil || c.SensorID != nil || c.StepRunID != nil {
			t.Errorf("pre-zone command changed: zone %v sensor %v step_run %v", c.ScanZoneID, c.SensorID, c.StepRunID)
		}
		if got := payloadTargets(t, c); len(got) != 2 {
			t.Errorf("targets = %v", got)
		}
	}
	if run.Context["zone_routing"] != nil {
		t.Error("zone routing report on a tenant without zones")
	}
}

// Code scanners (files, repositories, containers) are not network scans and
// are not zone-routed (RFC-023 D20).
func TestScanZones_NonNetworkToolNotRouted(t *testing.T) {
	tenant := shared.NewID()
	dc := zone(t, tenant, "dc", false, []shared.ID{shared.NewID()}, "10.1.0.0/16")
	svc, deps := newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{dc}}, nil, nil)
	sc := singleScan(t, deps, tenant, "betterleaks", 1, nil, "proofrepo")
	if _, err := trigger(t, svc, sc); err != nil {
		t.Fatalf("betterleaks in a zoned tenant: %v", err)
	}
	for _, c := range deps.commandRepo.commands {
		if c.ScanZoneID != nil {
			t.Error("a code scan was zone-routed")
		}
	}
}

// Zone lookup failure stops the dispatch (fail closed).
func TestScanZones_LookupFailureFailsClosed(t *testing.T) {
	tenant := shared.NewID()
	svc, deps := newZonedScanService(&fakeZoneDir{err: errors.New("db down")}, nil, nil)
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "8.8.8.8")
	if _, err := trigger(t, svc, sc); err == nil {
		t.Fatal("trigger succeeded without being able to read the zones")
	}
	if len(deps.commandRepo.commands) != 0 {
		t.Error("dispatched without zones")
	}
}

func TestScanZones_WorkflowStaysInOneZone(t *testing.T) {
	tenant := shared.NewID()
	a := zone(t, tenant, "a", false, []shared.ID{shared.NewID()}, "10.1.0.0/16")
	b := zone(t, tenant, "b", false, []shared.ID{shared.NewID()}, "10.2.0.0/16")

	mkWorkflow := func(deps *testScanServiceDeps, targets ...string) *scan.Scan {
		s := createTestScanInRepo(deps, tenant, "wf", scan.ScanTypeWorkflow)
		s.SetTargets(targets)
		pid := *s.ScanWorkflowID
		deps.stepRepo.steps[pid.String()] = []*scanworkflow.Step{{ID: shared.NewID(), ScanWorkflowID: pid, StepKey: "s", StepOrder: 1, Tool: "nuclei"}}
		return s
	}

	svc, deps := newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{a, b}}, nil, nil)
	sc := mkWorkflow(deps, "10.1.0.1", "10.2.0.1")
	_, err := trigger(t, svc, sc)
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != "ZONE_SPLIT_REQUIRED" {
		t.Fatalf("workflow across zones: err = %v, want ZONE_SPLIT_REQUIRED", err)
	}

	svc, deps = newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{a, b}}, nil, nil)
	sc = mkWorkflow(deps, "10.1.0.1", "10.1.0.2", "192.168.0.1")
	run, err := trigger(t, svc, sc)
	if err != nil {
		t.Fatal(err)
	}
	if got := scanrun.ScanZoneFromContext(run.Context); got == nil || *got != a.ID {
		t.Errorf("workflow run zone = %v, want a", got)
	}
	if !hasWarning(warningsOf(run), "192.168.0.1 not scanned") {
		t.Errorf("warnings = %v", warningsOf(run))
	}
	for _, c := range deps.commandRepo.commands {
		if c.ScanZoneID == nil || *c.ScanZoneID != a.ID {
			t.Errorf("workflow step command zone = %v, want a", c.ScanZoneID)
		}
	}
}

// A workflow scan has no scanner of its own: its steps plan their targets
// (and cut them into chunks). It is never warned that only its first target
// is scanned.
func TestWorkflowScan_NoSingleTargetCaveat(t *testing.T) {
	tenant := shared.NewID()
	svc, deps := newZonedScanService(&fakeZoneDir{}, nil, nil)
	s := createTestScanInRepo(deps, tenant, "wf", scan.ScanTypeWorkflow)
	s.SetTargets([]string{"8.8.8.8", "1.1.1.1", "app.example.com"})
	pid := *s.ScanWorkflowID
	deps.stepRepo.steps[pid.String()] = []*scanworkflow.Step{{ID: shared.NewID(), ScanWorkflowID: pid, StepKey: "s", StepOrder: 1, Tool: "nuclei"}}
	run, err := trigger(t, svc, s)
	if err != nil {
		t.Fatal(err)
	}
	if hasWarning(warningsOf(run), "takes one target per job") {
		t.Errorf("workflow scan warned that only one target is scanned: %v", warningsOf(run))
	}
}

// RFC-023 D6: private targets are accepted at scan creation only where a zone
// covers them.
func TestScanZones_CreateScanAcceptsPrivateTargetsOnlyInZones(t *testing.T) {
	tenant := shared.NewID()
	dc := zone(t, tenant, "dc", false, []shared.ID{shared.NewID()}, "10.1.0.0/16", "fd00:1::/48")
	create := func(svc *scanservice.Service, targets ...string) (*scan.Scan, error) {
		return svc.CreateScan(context.Background(), scanservice.CreateScanInput{
			TenantID: tenant.String(), Name: "private", ScanType: "single", ScannerName: "nuclei",
			ScheduleType: "manual", Targets: targets,
		})
	}

	svc, _ := newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{dc}}, nil, nil)
	sc, err := create(svc, "10.1.2.3", "10.1.4.0/24", "https://10.1.0.9:8443/", "fd00:1::5", "8.8.8.8")
	if err != nil {
		t.Fatalf("zone-covered private targets rejected: %v", err)
	}
	if len(sc.Targets) != 5 {
		t.Errorf("targets = %v", sc.Targets)
	}
	for _, bad := range []string{"10.9.0.1", "192.168.1.1", "127.0.0.1", "169.254.169.254", "10.0.0.0/8"} {
		if _, err := create(svc, bad); err == nil {
			t.Errorf("%s accepted although no zone covers it", bad)
		}
	}

	// No zones: private targets stay refused (pre-zone behavior).
	svc, _ = newZonedScanService(&fakeZoneDir{}, nil, nil)
	if _, err := create(svc, "10.1.2.3"); err == nil {
		t.Error("private target accepted for a tenant without zones")
	}
}
