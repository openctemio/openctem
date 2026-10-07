package unit

import (
	"context"
	"errors"
	"strings"
	"testing"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The trigger-time tool availability gate (NO_SENSOR_FOR_TOOL) runs on every
// trigger path and its refusal is recorded as a blocked run with that code
// and the message naming the tool and the sensor counts; the error itself
// reaches the caller unchanged (code and details for the browser).

type noSensorAvailability struct{}

func (noSensorAvailability) ToolAvailabilityFor(_ context.Context, _ shared.ID, _ *shared.ID, name string) (*sensordom.ToolAvailability, error) {
	return &sensordom.ToolAvailability{Name: name, Enabled: true, Status: sensordom.ToolOfflineOnly, SensorsTotal: 2}, nil
}

func assertNoSensorBlocked(t *testing.T, deps *testScanServiceDeps, scanID shared.ID, err error) {
	t.Helper()
	var tu *scanservice.ToolUnavailableError
	if !errors.As(err, &tu) || tu.Tool != "nuclei" || tu.SensorsTotal != 2 {
		t.Fatalf("err = %v, want the ToolUnavailableError for nuclei (details for the browser)", err)
	}
	if wildcardCode(err) != scanservice.CodeNoSensorForTool {
		t.Fatalf("error code = %q, want %s", wildcardCode(err), scanservice.CodeNoSensorForTool)
	}
	b := blockedRuns(deps, scanID)
	if len(b) != 1 {
		t.Fatalf("blocked runs = %d, want 1", len(b))
	}
	if b[0].RefusalCode != scanservice.CodeNoSensorForTool ||
		!strings.Contains(b[0].ErrorMessage, "nuclei") || !strings.Contains(b[0].ErrorMessage, "2 sensor(s)") {
		t.Fatalf("blocked run = %q %q", b[0].RefusalCode, b[0].ErrorMessage)
	}
	if dispatchedRuns(deps) != 0 || len(deps.commandRepo.commands) != 0 {
		t.Fatal("a refused trigger dispatched work")
	}
}

func TestNoSensorForTool_BlockedOnEveryTriggerPath(t *testing.T) {
	t.Run("manual", func(t *testing.T) {
		svc, deps := newTestScanService(scanservice.WithToolAvailability(noSensorAvailability{}))
		tenantID := shared.NewID()
		deps.toolRepo.addTool("nuclei", true)
		sc := createTestScanInRepo(deps, tenantID, "Manual", scan.ScanTypeSingle)
		_, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
			TenantID: tenantID.String(), ScanID: sc.ID.String(), Interactive: true,
		})
		assertNoSensorBlocked(t, deps, sc.ID, err)
	})

	t.Run("scheduled", func(t *testing.T) {
		svc, deps := newTestScanService(scanservice.WithToolAvailability(noSensorAvailability{}))
		tenantID := shared.NewID()
		deps.toolRepo.addTool("nuclei", true)
		sc := createTestScanInRepo(deps, tenantID, "Scheduled", scan.ScanTypeSingle)
		owner := shared.NewID()
		sc.CreatedBy = &owner
		_, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
			TenantID: tenantID.String(), ScanID: sc.ID.String(),
			TriggerType: pipeline.TriggerTypeSchedule, SkipIfRunning: true,
		})
		assertNoSensorBlocked(t, deps, sc.ID, err)
		if b := blockedRuns(deps, sc.ID); b[0].TriggerType != pipeline.TriggerTypeSchedule {
			t.Errorf("blocked run trigger = %s, want schedule", b[0].TriggerType)
		}
	})

	t.Run("quick scan", func(t *testing.T) {
		svc, deps := newTestScanService(scanservice.WithToolAvailability(noSensorAvailability{}))
		tenantID := shared.NewID()
		deps.toolRepo.addTool("nuclei", true)
		_, err := svc.QuickScan(context.Background(), scanservice.QuickScanInput{
			TenantID: tenantID.String(), Targets: []string{"example.com"}, ScannerName: "nuclei",
		})
		if len(deps.scanRepo.scans) != 1 {
			t.Fatalf("quick scan stored %d scan(s), want its one ad-hoc scan", len(deps.scanRepo.scans))
		}
		for _, sc := range deps.scanRepo.scans {
			assertNoSensorBlocked(t, deps, sc.ID, err)
		}
	})
}

// A disabled tool is refused before the availability gate, with its own
// code; that code is what reaches the caller and the blocked run.
func TestToolDisabled_StillReachesTheCaller(t *testing.T) {
	svc, deps := newTestScanService(scanservice.WithToolAvailability(noSensorAvailability{}))
	tenantID := shared.NewID()
	deps.toolRepo.addTool("nuclei", false)
	sc := createTestScanInRepo(deps, tenantID, "Disabled tool", scan.ScanTypeSingle)
	_, err := svc.TriggerScan(context.Background(), scanservice.TriggerScanExecInput{
		TenantID: tenantID.String(), ScanID: sc.ID.String(),
	})
	if wildcardCode(err) != "TOOL_DISABLED" {
		t.Fatalf("err = %v, want TOOL_DISABLED", err)
	}
	if b := blockedRuns(deps, sc.ID); len(b) != 1 || b[0].RefusalCode != "TOOL_DISABLED" {
		t.Fatalf("blocked runs = %+v, want one TOOL_DISABLED", b)
	}
}
