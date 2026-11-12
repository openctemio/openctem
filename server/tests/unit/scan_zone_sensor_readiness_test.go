package unit

import (
	"context"
	"errors"
	"testing"

	scanservice "github.com/openctemio/openctem/server/internal/app/scan"
	"github.com/openctemio/openctem/server/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tool"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Plan-time readiness of a zone's sensors (research 466 g, D8): a scan
// whose only zone sensors are New (for a job above T0), or refuse private
// targets on their host, is refused at trigger with zone_sensor_new or
// zone_sensor_no_private and dispatches nothing.

// stateZoneDir adds the zone sensor states to fakeZoneDir, per tenant.
type stateZoneDir struct {
	*fakeZoneDir
	states  map[shared.ID]map[shared.ID][]scanzone.ZoneSensorState // tenant -> zone -> sensors
	tenants []shared.ID
}

func (d *stateZoneDir) ZoneSensorStates(_ context.Context, tenant shared.ID, ids []shared.ID) (map[shared.ID][]scanzone.ZoneSensorState, error) {
	d.tenants = append(d.tenants, tenant)
	out := map[shared.ID][]scanzone.ZoneSensorState{}
	for _, id := range ids {
		out[id] = d.states[tenant][id]
	}
	return out, nil
}

func allowPrivate(b bool) *sensor.LocalPolicyReport {
	return &sensor.LocalPolicyReport{State: sensor.LocalPolicyAbsent, AllowPrivate: &b}
}

func readinessService(t *testing.T, tenant shared.ID, z *scanzone.Zone, online []shared.ID, states ...scanzone.ZoneSensorState) (*scanservice.Service, *testScanServiceDeps, *stateZoneDir) {
	t.Helper()
	dir := &stateZoneDir{
		fakeZoneDir: &fakeZoneDir{zones: []*scanzone.Zone{z}, routable: map[shared.ID][]scanzone.SensorCandidate{z.ID: candidates(online...)}},
		states:      map[shared.ID]map[shared.ID][]scanzone.ZoneSensorState{tenant: {z.ID: states}},
	}
	res := tableResolver{"intranet.example.com": {"10.1.0.7"}}
	svc, deps := newZonedScanService(dir.fakeZoneDir, res, nil, scanservice.WithScanZones(dir, res))
	deps.toolRepo.tools["dnsx"] = &tool.Tool{ID: shared.NewID(), Name: "dnsx", IsActive: true, SupportedTargets: []string{"domain", "ip"}}
	return svc, deps, dir
}

func refusedDetails(t *testing.T, err error) []scopedom.Refusal {
	t.Helper()
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != "NO_ZONE_COVERAGE" {
		t.Fatalf("err = %v, want NO_ZONE_COVERAGE", err)
	}
	details, _ := de.Details.(map[string]any)
	refused, _ := details["refused"].([]scopedom.Refusal)
	return refused
}

func TestZoneReadiness_OnlyNewSensorRefusesActiveScan(t *testing.T) {
	tenant := shared.NewID()
	s := shared.NewID()
	dc := zone(t, tenant, "dc", false, []shared.ID{s}, "10.1.0.0/16")
	svc, deps, dir := readinessService(t, tenant, dc, []shared.ID{s},
		scanzone.ZoneSensorState{ID: s, Name: "edge-1", LocalPolicy: allowPrivate(true)})

	_, err := trigger(t, svc, singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1"))
	refused := refusedDetails(t, err)
	if len(refused) != 1 || refused[0].Code != scopedom.RefusalZoneSensorNew {
		t.Fatalf("refused = %+v", refused)
	}
	if len(refused[0].Fixes) != 1 || refused[0].Fixes[0].Action != scopedom.FixTrustSensor ||
		refused[0].Fixes[0].ID != s.String() || refused[0].Fixes[0].Requires != "sensors:grant:widen" {
		t.Errorf("fixes = %+v", refused[0].Fixes)
	}
	if len(deps.commandRepo.commands) != 0 {
		t.Error("a job was dispatched to a zone whose only sensor is New")
	}
	if len(dir.tenants) == 0 || dir.tenants[0] != tenant {
		t.Errorf("sensor states read for %v, want the scan's tenant", dir.tenants)
	}
}

func TestZoneReadiness_PassiveJobOnNewSensorStillRoutes(t *testing.T) {
	tenant := shared.NewID()
	s := shared.NewID()
	dc := zone(t, tenant, "dc", false, []shared.ID{s}, "10.1.0.0/16")
	svc, deps, _ := readinessService(t, tenant, dc, []shared.ID{s},
		scanzone.ZoneSensorState{ID: s, Name: "edge-1", LocalPolicy: allowPrivate(true)})

	if _, err := trigger(t, svc, singleScan(t, deps, tenant, "dnsx", 1, nil, "intranet.example.com")); err != nil {
		t.Fatalf("a T0 job on a New sensor was refused: %v", err)
	}
	if len(deps.commandRepo.commands) != 1 {
		t.Fatalf("commands = %d, want 1", len(deps.commandRepo.commands))
	}
	for _, c := range deps.commandRepo.commands {
		if c.SensorID == nil || *c.SensorID != s {
			t.Errorf("pinned to %v, want the New sensor", c.SensorID)
		}
	}
}

func TestZoneReadiness_NewOnlineTrustedOfflineWaitsForTrusted(t *testing.T) {
	tenant := shared.NewID()
	newS, trusted := shared.NewID(), shared.NewID()
	dc := zone(t, tenant, "dc", false, []shared.ID{newS, trusted}, "10.1.0.0/16")
	svc, deps, _ := readinessService(t, tenant, dc, []shared.ID{newS},
		scanzone.ZoneSensorState{ID: newS, Name: "edge-new", LocalPolicy: allowPrivate(true)},
		scanzone.ZoneSensorState{ID: trusted, Name: "edge-trusted", Trusted: true, LocalPolicy: allowPrivate(true)})

	run, err := trigger(t, svc, singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range deps.commandRepo.commands {
		if c.SensorID != nil {
			t.Errorf("pinned to %v; the only online sensor is New, so the job waits in the zone", *c.SensorID)
		}
	}
	if !hasWarning(warningsOf(run), "no assigned sensor") {
		t.Errorf("warnings = %v", warningsOf(run))
	}
}

func TestZoneReadiness_HostRefusesPrivateTargets(t *testing.T) {
	tenant := shared.NewID()
	s := shared.NewID()
	dc := zone(t, tenant, "dc", false, []shared.ID{s}, "10.1.0.0/16", "203.0.113.0/24")
	svc, deps, _ := readinessService(t, tenant, dc, []shared.ID{s},
		scanzone.ZoneSensorState{ID: s, Name: "edge-1", Trusted: true, LocalPolicy: allowPrivate(false)})

	_, err := trigger(t, svc, singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1"))
	refused := refusedDetails(t, err)
	if len(refused) != 1 || refused[0].Code != scopedom.RefusalZoneSensorNoPrivate ||
		len(refused[0].Fixes) != 1 || refused[0].Fixes[0].Action != scopedom.FixAllowPrivateTargets || refused[0].Fixes[0].ID != s.String() {
		t.Fatalf("refused = %+v", refused)
	}
	if len(deps.commandRepo.commands) != 0 {
		t.Fatal("a private target was dispatched to a host that refuses private targets")
	}

	// A public target of the same zone still runs there.
	if _, err := trigger(t, svc, singleScan(t, deps, tenant, "nuclei", 1, nil, "203.0.113.5")); err != nil {
		t.Fatalf("public target: %v", err)
	}
	if len(deps.commandRepo.commands) != 1 {
		t.Fatalf("commands = %d, want the public target", len(deps.commandRepo.commands))
	}
}

// Another tenant's sensor states never count: the directory is asked for
// the scan's tenant only, and a sensor the tenant does not have is not
// there (the SQL joins zone and sensor on the tenant).
func TestZoneReadiness_OtherTenantsSensorsDoNotCount(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	s := shared.NewID()
	dc := zone(t, tenant, "dc", false, []shared.ID{s}, "10.1.0.0/16")
	svc, deps, dir := readinessService(t, tenant, dc, []shared.ID{s},
		scanzone.ZoneSensorState{ID: s, Name: "edge-1", LocalPolicy: allowPrivate(true)})
	dir.states[other] = map[shared.ID][]scanzone.ZoneSensorState{dc.ID: {{ID: shared.NewID(), Name: "theirs", Trusted: true, LocalPolicy: allowPrivate(true)}}}

	_, err := trigger(t, svc, singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1"))
	if refused := refusedDetails(t, err); len(refused) != 1 || refused[0].Code != scopedom.RefusalZoneSensorNew {
		t.Fatalf("refused = %+v", refused)
	}
	for _, id := range dir.tenants {
		if id != tenant {
			t.Errorf("states read for tenant %s", id)
		}
	}
}

// The dry run (scope check) answers the same codes; the dispatch paths
// that leave the check off (the claim re-check) are unchanged.
func TestZoneReadiness_DryRunCodes(t *testing.T) {
	tenant := shared.NewID()
	newS, noPriv := shared.NewID(), shared.NewID()
	dcNew := zone(t, tenant, "dc-new", false, []shared.ID{newS}, "10.1.0.0/16")
	dcNoPriv := zone(t, tenant, "dc-np", false, []shared.ID{noPriv}, "10.2.0.0/16")
	dir := &stateZoneDir{
		fakeZoneDir: &fakeZoneDir{zones: []*scanzone.Zone{dcNew, dcNoPriv}},
		states: map[shared.ID]map[shared.ID][]scanzone.ZoneSensorState{tenant: {
			dcNew.ID:    {{ID: newS, Name: "edge-new", LocalPolicy: allowPrivate(true)}},
			dcNoPriv.ID: {{ID: noPriv, Name: "edge-np", Trusted: true, LocalPolicy: allowPrivate(false)}},
		}},
	}
	gate := scanservice.NewTargetGate(noExclusions{}, allOwned{}, dir, nil, logger.NewNop())
	tier1, tier0 := 1, 0
	res, err := gate.ResolveDispatchTargets(context.Background(), scanservice.DispatchTargetsInput{
		TenantID: tenant, Targets: []string{"10.1.0.1", "10.2.0.1"}, AllowNonNetworkTargets: true, DryRun: true, ZoneSensorTier: &tier1})
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]string{}
	for _, r := range res.Refused {
		codes[r.Target] = r.Code
		if r.SensorID == "" {
			t.Errorf("%s: refusal names no sensor", r.Target)
		}
	}
	if codes["10.1.0.1"] != scopedom.RefusalZoneSensorNew || codes["10.2.0.1"] != scopedom.RefusalZoneSensorNoPrivate || len(res.Allowed) != 0 {
		t.Fatalf("refused %+v allowed %v", res.Refused, res.Allowed)
	}

	res, err = gate.ResolveDispatchTargets(context.Background(), scanservice.DispatchTargetsInput{
		TenantID: tenant, Targets: []string{"10.1.0.1"}, AllowNonNetworkTargets: true, DryRun: true, ZoneSensorTier: &tier0})
	if err != nil || len(res.Allowed) != 1 {
		t.Fatalf("a passive check on a New sensor: %+v %v", res, err)
	}

	res, err = gate.ResolveDispatchTargets(context.Background(), scanservice.DispatchTargetsInput{
		TenantID: tenant, Targets: []string{"10.1.0.1", "10.2.0.1"}, AllowNonNetworkTargets: true})
	if err != nil || len(res.Allowed) != 2 {
		t.Fatalf("without the check: %+v %v", res, err)
	}
}
