package unit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A wildcard pattern (*.x) is not a host. Live, a nuclei scan was dispatched
// against "*.vndirect.com.vn" and refused by the sensor ("cannot resolve").
// Active tools now refuse it at create, edit, quick scan and trigger;
// discovery tools take its root domain.

func wildcardCode(err error) string {
	var de *shared.DomainError
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

func TestWildcardTarget_CreateRefusedForActiveTool(t *testing.T) {
	svc, deps := newTestScanService()
	deps.toolRepo.addTool("nuclei", true)
	_, err := svc.CreateScan(context.Background(), scanservice.CreateScanInput{
		TenantID: shared.NewID().String(), Name: "wild", ScanType: "single",
		ScannerName: "nuclei", Targets: []string{"*.example.com"},
	})
	if wildcardCode(err) != scanservice.CodeWildcardTarget {
		t.Fatalf("err = %v, want %s", err, scanservice.CodeWildcardTarget)
	}
	for _, want := range []string{"*.example.com", "nuclei", "example.com", "discovery"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err.Error(), want)
		}
	}
	if len(deps.scanRepo.scans) != 0 {
		t.Error("the refused scan was stored")
	}
}

func TestWildcardTarget_CreateAllowedForDiscoveryTool(t *testing.T) {
	svc, deps := newTestScanService()
	deps.toolRepo.addTool("subfinder", true)
	sc, err := svc.CreateScan(context.Background(), scanservice.CreateScanInput{
		TenantID: shared.NewID().String(), Name: "recon", ScanType: "single",
		ScannerName: "subfinder", Targets: []string{"*.example.com"},
	})
	if err != nil {
		t.Fatalf("subfinder with a wildcard pattern: %v", err)
	}
	if len(sc.Targets) != 1 || sc.Targets[0] != "*.example.com" {
		t.Errorf("stored targets = %v, want the pattern as written", sc.Targets)
	}
}

func TestWildcardTarget_EditToActiveToolRefused(t *testing.T) {
	svc, deps := newTestScanService()
	deps.toolRepo.addTool("subfinder", true)
	deps.toolRepo.addTool("nuclei", true)
	tenantID := shared.NewID()
	sc, err := svc.CreateScan(context.Background(), scanservice.CreateScanInput{
		TenantID: tenantID.String(), Name: "recon", ScanType: "single",
		ScannerName: "subfinder", Targets: []string{"*.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.UpdateScan(context.Background(), scanservice.UpdateScanInput{
		TenantID: tenantID.String(), ScanID: sc.ID.String(), ScannerName: "nuclei",
	})
	if wildcardCode(err) != scanservice.CodeWildcardTarget {
		t.Fatalf("switching to nuclei: err = %v, want %s", err, scanservice.CodeWildcardTarget)
	}
}

func TestWildcardTarget_QuickScanRefusedBeforeAnyScanIsStored(t *testing.T) {
	svc, deps := newTestScanService()
	deps.toolRepo.addTool("nuclei", true)
	_, err := svc.QuickScan(context.Background(), scanservice.QuickScanInput{
		TenantID: shared.NewID().String(), ScannerName: "nuclei", Targets: []string{"*.example.com"},
	})
	if wildcardCode(err) != scanservice.CodeWildcardTarget {
		t.Fatalf("err = %v, want %s", err, scanservice.CodeWildcardTarget)
	}
	if len(deps.scanRepo.scans) != 0 {
		t.Error("a refused quick scan left an ad-hoc scan behind")
	}
}

// A scan stored before the rule: the trigger refuses it and dispatches
// nothing.
func TestWildcardTarget_TriggerRefusedForActiveTool(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	deps.toolRepo.addTool("nuclei", true)
	sc := createTestScanInRepo(deps, tenantID, "Old wildcard", scan.ScanTypeSingle)
	sc.SetTargets([]string{"*.example.com"})

	_, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: sc.ID.String(),
	})
	if wildcardCode(err) != scanservice.CodeWildcardTarget {
		t.Fatalf("err = %v, want %s", err, scanservice.CodeWildcardTarget)
	}
	if len(deps.commandRepo.commands) != 0 {
		t.Errorf("%d command(s) dispatched for a wildcard pattern", len(deps.commandRepo.commands))
	}
}

// A discovery tool gets the root domain, never the pattern.
func TestWildcardTarget_TriggerHandsDiscoveryToolTheRoot(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	deps.toolRepo.addTool("subfinder", true)
	sc := createTestScanInRepo(deps, tenantID, "Recon", scan.ScanTypeSingle)
	_ = sc.SetSingleScanner("subfinder", map[string]any{"targets": []any{"*.Example.com"}}, 1)
	sc.SetTargets([]string{"*.Example.com", "example.com"})
	sc.AssetGroupID = shared.ID{}
	sc.AssetGroupIDs = nil

	if _, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: sc.ID.String(),
	}); err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	if len(deps.commandRepo.commands) == 0 {
		t.Fatal("nothing dispatched")
	}
	for _, c := range deps.commandRepo.commands {
		if strings.Contains(string(c.Payload), "*.") {
			t.Errorf("payload still carries a wildcard pattern: %s", c.Payload)
		}
		var p map[string]any
		_ = json.Unmarshal(c.Payload, &p)
		ts, _ := p["targets"].([]any)
		if len(ts) != 1 || ts[0] != "example.com" {
			t.Errorf("targets = %v, want [example.com] (root, deduplicated)", p["targets"])
		}
	}
	// The stored scan keeps the pattern: the trigger never rewrites it.
	stored := deps.scanRepo.scans[sc.ID.String()]
	if stored.Targets[0] != "*.Example.com" {
		t.Errorf("stored targets rewritten to %v", stored.Targets)
	}
}

// A workflow takes the pattern when every step that starts the run is a
// discovery step; an active first step refuses it.
func TestWildcardTarget_WorkflowNeedsDiscoveryFirstSteps(t *testing.T) {
	for _, tc := range []struct {
		name, rootTool string
		refused        bool
	}{
		{"discovery first", "subfinder", false},
		{"active first", "nuclei", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, deps := newTestScanService()
			tenantID := shared.NewID()
			deps.toolRepo.addTool("subfinder", true)
			deps.toolRepo.addTool("nuclei", true)
			sc := createTestScanInRepo(deps, tenantID, "Recon chain", scan.ScanTypeWorkflow)
			deps.stepRepo.steps[sc.PipelineID.String()] = []*pipeline.Step{
				{ID: shared.NewID(), PipelineID: *sc.PipelineID, StepKey: "first", StepOrder: 1, Tool: tc.rootTool},
				{ID: shared.NewID(), PipelineID: *sc.PipelineID, StepKey: "then", StepOrder: 2, Tool: "nuclei", DependsOn: []string{"first"}},
			}
			sc.SetTargets([]string{"*.example.com"})
			_, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
				TenantID: tenantID.String(), ScanID: sc.ID.String(),
			})
			refused := wildcardCode(err) == scanservice.CodeWildcardTarget
			if refused != tc.refused {
				t.Fatalf("refused = %v (err %v), want %v", refused, err, tc.refused)
			}
		})
	}
}
