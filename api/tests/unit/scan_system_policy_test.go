package unit

// Runs a platform policy starts are attributed to the policy, act with its
// system authority and queue below a person's own runs.

import (
	"context"
	"testing"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func commandsOfRun(deps *testScanServiceDeps) []*command.Command {
	var out []*command.Command
	for _, c := range deps.commandRepo.commands {
		out = append(out, c)
	}
	return out
}

func TestTriggerScan_PolicyRunIsAttributedAndQueuedLow(t *testing.T) {
	svc, deps := newTestScanService()
	tenant := shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	sc := createTestScanInRepo(deps, tenant, "Continuous coverage: probe.http", scan.ScanTypeSingle)
	sc.ManagedBy, sc.ManagedKey = scan.ManagedByCoverage, "probe.http"
	sc.AdHoc = true

	run, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenant.String(), ScanID: sc.ID.String(),
		TriggerType: scanworkflow.TriggerTypeSystem, TriggeredBy: "policy:coverage",
		// A hostile context cannot name an actor or another policy.
		Context: map[string]any{scanservice.RunContextKeyActor: shared.NewID().String(), scanservice.RunContextKeySystemPolicy: "enrichment"},
	})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	if run.TriggerType != scanworkflow.TriggerTypeSystem || run.TriggeredBy != "policy:coverage" {
		t.Errorf("run attributed to %s / %q, want system / policy:coverage", run.TriggerType, run.TriggeredBy)
	}
	if got := run.Context[scanservice.RunContextKeySystemPolicy]; got != "coverage" {
		t.Errorf("run policy = %v, want coverage (from the scan, not the caller)", got)
	}
	if _, ok := run.Context[scanservice.RunContextKeyActor]; ok {
		t.Error("a policy run recorded an actor")
	}
	cmds := commandsOfRun(deps)
	if len(cmds) == 0 {
		t.Fatal("no command queued")
	}
	for _, c := range cmds {
		if c.Priority != command.CommandPriorityLow {
			t.Errorf("policy command priority = %s, want low", c.Priority)
		}
		if c.DispatchGate == nil || c.DispatchGate.SystemPolicy != "coverage" || c.DispatchGate.Actor != "" {
			t.Errorf("policy command gate = %+v, want system policy coverage and no actor", c.DispatchGate)
		}
	}
}

func TestTriggerScan_PersonsRunIsHighAndKeepsItsActor(t *testing.T) {
	svc, deps := newTestScanService()
	tenant, user := shared.NewID(), shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	sc := createTestScanInRepo(deps, tenant, "Mine", scan.ScanTypeSingle)

	run, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenant.String(), ScanID: sc.ID.String(), TriggeredBy: user.String(), Interactive: true,
		TriggerType: scanworkflow.TriggerTypeManual,
		// The caller cannot make its own run a policy run.
		Context: map[string]any{scanservice.RunContextKeySystemPolicy: "coverage"},
	})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	if _, ok := run.Context[scanservice.RunContextKeySystemPolicy]; ok {
		t.Error("a caller made its run a policy run")
	}
	if _, ok := run.Context[scanservice.RunContextKeyActor]; ok {
		t.Error("the single-scanner path records no actor in the run context; the dispatch gate derives it")
	}
	for _, c := range commandsOfRun(deps) {
		if c.Priority != command.CommandPriorityHigh {
			t.Errorf("person's command priority = %s, want high", c.Priority)
		}
		if c.DispatchGate == nil || c.DispatchGate.SystemPolicy != "" || c.DispatchGate.Actor != user.String() {
			t.Errorf("person's command gate = %+v", c.DispatchGate)
		}
	}
}

// A schedule or an automation stays normal.
func TestTriggerScan_ScheduleIsNormal(t *testing.T) {
	svc, deps := newTestScanService()
	tenant := shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	sc := createTestScanInRepo(deps, tenant, "Nightly", scan.ScanTypeSingle)
	sc.SetCreatedBy(shared.NewID())
	if _, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenant.String(), ScanID: sc.ID.String(), TriggerType: scanworkflow.TriggerTypeSchedule,
	}); err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	for _, c := range commandsOfRun(deps) {
		if c.Priority != command.CommandPriorityNormal {
			t.Errorf("schedule command priority = %s, want normal", c.Priority)
		}
	}
}
