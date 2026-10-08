package unit

import (
	"context"
	"testing"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Every command of a single-scanner run (zoned or not) records what its
// targets were gated with, so the claim re-checks them with the same inputs:
// the scanner's tier and the act scope of the person who triggered the run.
func TestScanTrigger_CommandsRecordTheDispatchGate(t *testing.T) {
	user := shared.NewID()
	want := command.DispatchGate{Tier: int(scanservice.ProbeTier("nuclei")), ActScope: true, Actor: user.String()}

	tenant, _, _, svc, deps := frozenZoneSetup(t, &fakeFreeze{})
	sc := singleScan(t, deps, tenant, "nuclei", 1, nil, "10.1.0.1", "10.2.0.1")
	if _, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenant.String(), ScanID: sc.ID.String(), TriggeredBy: user.String(),
	}); err != nil {
		t.Fatal(err)
	}
	if len(deps.commandRepo.commands) != 2 {
		t.Fatalf("commands = %d, want one per zone", len(deps.commandRepo.commands))
	}
	for _, c := range deps.commandRepo.commands {
		if c.DispatchGate == nil || *c.DispatchGate != want {
			t.Fatalf("zone command gate %+v, want %+v", c.DispatchGate, want)
		}
	}

	// A scheduled run acts for the scan's owner.
	unzoned, udeps := newZonedScanService(&fakeZoneDir{}, nil, nil)
	owner := shared.NewID()
	usc := singleScan(t, udeps, tenant, "nuclei", 1, nil, "app.example.com")
	usc.CreatedBy = &owner
	if _, err := unzoned.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenant.String(), ScanID: usc.ID.String(),
	}); err != nil {
		t.Fatal(err)
	}
	if len(udeps.commandRepo.commands) != 1 {
		t.Fatalf("commands = %d", len(udeps.commandRepo.commands))
	}
	for _, c := range udeps.commandRepo.commands {
		if c.DispatchGate == nil || c.DispatchGate.Actor != owner.String() || !c.DispatchGate.ActScope || c.DispatchGate.Tier != want.Tier {
			t.Fatalf("unzoned command gate %+v", c.DispatchGate)
		}
	}
}
