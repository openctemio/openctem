package unit

import (
	"context"
	"errors"
	"testing"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Overlapping zones end to end (research 466 D9): a target two sites'
// zones hold with different sensors is refused with ambiguous_zone and
// dispatched nowhere; picking the zone routes it there.

func TestScanZones_AmbiguousOverlapRefusedUntilZonePicked(t *testing.T) {
	tenant := shared.NewID()
	officeSensor, cloudSensor := shared.NewID(), shared.NewID()
	office := zone(t, tenant, "office", false, []shared.ID{officeSensor}, "10.0.0.0/16")
	cloud := zone(t, tenant, "cloud", false, []shared.ID{cloudSensor}, "10.0.0.0/16")
	dir := &fakeZoneDir{zones: []*scanzone.Zone{office, cloud}, routable: map[shared.ID][]scanzone.SensorCandidate{
		office.ID: candidates(officeSensor), cloud.ID: candidates(cloudSensor)}}
	svc, deps := newZonedScanService(dir, nil, nil)

	// Saved: the target is inside zones, so create accepts it.
	sc, err := svc.CreateScan(context.Background(), scanservice.CreateScanInput{
		TenantID: tenant.String(), Name: "office scan", ScanType: "single", ScannerName: "nuclei",
		ScheduleType: "manual", Targets: []string{"10.0.4.5"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	_, err = trigger(t, svc, sc)
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != "NO_ZONE_COVERAGE" {
		t.Fatalf("err = %v, want NO_ZONE_COVERAGE", err)
	}
	details, _ := de.Details.(map[string]any)
	refused, _ := details["refused"].([]scopedom.Refusal)
	if len(refused) != 1 || refused[0].Code != scopedom.RefusalAmbiguousZone ||
		len(refused[0].Fixes) != 1 || refused[0].Fixes[0].Action != scopedom.FixPickZone {
		t.Fatalf("refused = %+v", refused)
	}
	if len(deps.commandRepo.commands) != 0 {
		t.Fatal("an ambiguous target was dispatched")
	}

	// Pinned to the office zone: it runs there, on the office sensor.
	sc.ScanZoneID = &office.ID
	if _, err := trigger(t, svc, sc); err != nil {
		t.Fatalf("pinned trigger: %v", err)
	}
	for _, c := range deps.commandRepo.commands {
		if c.ScanZoneID == nil || *c.ScanZoneID != office.ID || c.SensorID == nil || *c.SensorID != officeSensor {
			t.Errorf("pinned job went to zone %v sensor %v", c.ScanZoneID, c.SensorID)
		}
	}
	if len(deps.commandRepo.commands) != 1 {
		t.Errorf("commands = %d, want 1", len(deps.commandRepo.commands))
	}
}

// The scope check answers ambiguous_zone too.
func TestScanZones_AmbiguousOverlapDryRun(t *testing.T) {
	tenant := shared.NewID()
	office := zone(t, tenant, "office", false, []shared.ID{shared.NewID()}, "10.0.0.0/16")
	cloud := zone(t, tenant, "cloud", false, []shared.ID{shared.NewID()}, "10.0.0.0/16")
	gate := scanservice.NewTargetGate(noExclusions{}, allOwned{}, &fakeZoneDir{zones: []*scanzone.Zone{office, cloud}}, nil, logger.NewNop())
	res, err := gate.ResolveDispatchTargets(context.Background(), scanservice.DispatchTargetsInput{
		TenantID: tenant, Targets: []string{"10.0.0.5", "10.1.0.5"}, AllowNonNetworkTargets: true, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	codes := map[string]string{}
	for _, r := range res.Refused {
		codes[r.Target] = r.Code
	}
	if codes["10.0.0.5"] != scopedom.RefusalAmbiguousZone || codes["10.1.0.5"] != scopedom.RefusalZoneNone || len(res.Allowed) != 0 {
		t.Fatalf("refused %+v allowed %v", res.Refused, res.Allowed)
	}
}
