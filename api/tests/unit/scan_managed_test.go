package unit

// Managed scans (docs/architecture/managed-scans.md) are read-only through
// the scan API: every change a member (or an automation) could make is
// refused with SCAN_MANAGED_BY_POLICY, while a person's scan is unaffected.

import (
	"context"
	"errors"
	"testing"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func managedScan(deps *testScanServiceDeps, tenantID shared.ID) *scan.Scan {
	sc := createTestScanInRepo(deps, tenantID, "Continuous coverage: probe.http", scan.ScanTypeSingle)
	sc.AdHoc = true
	sc.ManagedBy, sc.ManagedKey = scan.ManagedByCoverage, "probe.http"
	sc.SetTags([]string{scanservice.CoverageTag, "keep"})
	return sc
}

func TestManagedScan_MutationsAreRefused(t *testing.T) {
	ctx := context.Background()
	svc, deps := newTestScanService()
	tenant := shared.NewID()
	sc := managedScan(deps, tenant)
	id, tid := sc.ID.String(), tenant.String()
	admin := shared.NewID().String()

	ops := map[string]func() error{
		"update": func() error {
			_, err := svc.UpdateScan(ctx, scanservice.UpdateScanInput{TenantID: tid, ScanID: id, Description: "mine now"})
			return err
		},
		"schedule": func() error {
			_, err := svc.UpdateScan(ctx, scanservice.UpdateScanInput{TenantID: tid, ScanID: id, ScheduleType: "daily"})
			return err
		},
		"delete":   func() error { return svc.DeleteScan(ctx, tid, id) },
		"pause":    func() error { _, err := svc.PauseScan(ctx, tid, id); return err },
		"activate": func() error { _, err := svc.ActivateScan(ctx, tid, id); return err },
		"disable":  func() error { _, err := svc.DisableScan(ctx, tid, id); return err },
		"take ownership": func() error {
			_, err := svc.TakeOwnership(ctx, scanservice.TakeOwnershipInput{TenantID: tid, ScanID: id, ActorID: admin})
			return err
		},
		"save as configuration": func() error { _, err := svc.SaveQuickScan(ctx, tid, id, "My scan"); return err },
		"run now": func() error {
			_, err := svc.TriggerScan(ctx, scanservice.TriggerScanExecInput{TenantID: tid, ScanID: id, TriggeredBy: admin, Interactive: true})
			return err
		},
		"approved or emergency run of a member": func() error {
			_, err := svc.TriggerScan(ctx, scanservice.TriggerScanExecInput{TenantID: tid, ScanID: id, TriggeredBy: admin, TriggerType: scanworkflow.TriggerTypeManual})
			return err
		},
		"automation": func() error {
			_, err := svc.TriggerScan(ctx, scanservice.TriggerScanExecInput{TenantID: tid, ScanID: id, TriggeredBy: "workflow:abc", TriggerType: scanworkflow.TriggerTypeAutomation})
			return err
		},
	}
	for name, op := range ops {
		if err := op(); !errors.Is(err, scanservice.ErrScanManagedByPolicy) {
			t.Errorf("%s: err = %v, want SCAN_MANAGED_BY_POLICY", name, err)
		}
	}
	var de *shared.DomainError
	if err := svc.DeleteScan(ctx, tid, id); !errors.As(err, &de) || de.Code != "SCAN_MANAGED_BY_POLICY" || !errors.Is(err, shared.ErrConflict) {
		t.Errorf("refusal = %v, want the SCAN_MANAGED_BY_POLICY conflict", err)
	}

	// Nothing changed.
	got := deps.scanRepo.scans[id]
	if got == nil || got.Status != scan.StatusActive || got.Description == "mine now" || got.ScheduleType != scan.ScheduleManual || !got.AdHoc {
		t.Errorf("a refused call changed the managed scan: %+v", got)
	}
	if len(deps.auditSvc.events) != 0 {
		t.Errorf("a refused call was audited as a change: %d events", len(deps.auditSvc.events))
	}
	if st := svc.OwnerState(ctx, got); st != scanservice.OwnerStateManaged {
		t.Errorf("owner state = %q, want managed", st)
	}
}

// A person's scan is unaffected by the managed guard.
func TestManagedScan_PersonsScanStillChanges(t *testing.T) {
	ctx := context.Background()
	svc, deps := newTestScanService()
	tenant := shared.NewID()
	mine := createTestScanInRepo(deps, tenant, "Weekly", scan.ScanTypeSingle)
	tid, id := tenant.String(), mine.ID.String()

	if _, err := svc.UpdateScan(ctx, scanservice.UpdateScanInput{TenantID: tid, ScanID: id, Description: "d"}); err != nil {
		t.Errorf("update: %v", err)
	}
	if _, err := svc.PauseScan(ctx, tid, id); err != nil {
		t.Errorf("pause: %v", err)
	}
	if err := svc.DeleteScan(ctx, tid, id); err != nil {
		t.Errorf("delete: %v", err)
	}
}

// A managed scan of another tenant is not found, whatever the call.
func TestManagedScan_OtherTenantIsNotFound(t *testing.T) {
	ctx := context.Background()
	svc, deps := newTestScanService()
	sc := managedScan(deps, shared.NewID())
	other := shared.NewID().String()
	if err := svc.DeleteScan(ctx, other, sc.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("delete across tenants: %v, want not found", err)
	}
	if _, err := svc.PauseScan(ctx, other, sc.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("pause across tenants: %v, want not found", err)
	}
}

// Cloning a managed scan is allowed: the copy is a normal scan owned by the
// caller, without the managed marker or the platform's tag.
func TestManagedScan_CloneIsAnOrdinaryScan(t *testing.T) {
	svc, deps := newTestScanService()
	tenant := shared.NewID()
	sc := managedScan(deps, tenant)
	actor := shared.NewID()
	clone, err := svc.CloneScan(context.Background(), tenant.String(), sc.ID.String(), "My coverage", actor.String())
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if clone.IsManaged() || clone.ManagedKey != "" {
		t.Errorf("clone is managed: %q/%q", clone.ManagedBy, clone.ManagedKey)
	}
	if clone.AdHoc {
		t.Error("clone is ad hoc: it would be hidden from the scan list")
	}
	for _, tag := range clone.Tags {
		if tag == scanservice.CoverageTag {
			t.Error("clone carries the platform's coverage tag")
		}
	}
	if clone.CreatedBy == nil || *clone.CreatedBy != actor {
		t.Errorf("clone owner = %v, want the caller", clone.CreatedBy)
	}
}

// The policy's own run (attributed to the policy, no user) and the platform's
// retry of a failed run are not a member's run: they start.
func TestManagedScan_PolicyAndRetryRunsStart(t *testing.T) {
	ctx := context.Background()
	svc, deps := newTestScanService()
	tenant := shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	sc := managedScan(deps, tenant)
	for name, in := range map[string]scanservice.TriggerScanExecInput{
		"policy": {TenantID: tenant.String(), ScanID: sc.ID.String(), TriggerType: scanworkflow.TriggerTypeSystem, TriggeredBy: "policy:coverage"},
		"retry":  {TenantID: tenant.String(), ScanID: sc.ID.String(), TriggerType: scanworkflow.TriggerTypeSystem},
	} {
		if _, err := svc.TriggerScan(ctx, in); err != nil {
			t.Errorf("%s run of a managed scan: %v", name, err)
		}
	}
}
