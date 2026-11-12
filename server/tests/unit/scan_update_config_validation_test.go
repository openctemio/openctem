package unit

import (
	"context"
	"errors"
	"testing"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// An edit passes the scanner config checks a new scan passes: a scan saved
// harmless cannot be edited into a config that create refuses. A config sent
// back unchanged (as the edit form does on a rename) is not checked again, so
// an older scan stays editable.

func TestUpdateScan_RefusesAConfigCreateWouldRefuse(t *testing.T) {
	svc, deps := newTestScanService()
	deps.secValidator.refuseConfigKey = "exec"
	tenantID := shared.NewID()
	s := createTestScanInRepo(deps, tenantID, "harmless", scan.ScanTypeSingle)

	_, err := svc.UpdateScan(context.Background(), scanservice.UpdateScanInput{
		TenantID:      tenantID.String(),
		ScanID:        s.ID.String(),
		ScannerName:   "nuclei",
		ScannerConfig: map[string]any{"exec": "x"},
	})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want a validation error", err)
	}
	stored, _ := deps.scanRepo.GetByTenantAndID(context.Background(), tenantID, s.ID)
	if _, ok := stored.ScannerConfig["exec"]; ok {
		t.Fatal("the refused config was stored")
	}
}

func TestUpdateScan_UnchangedConfigIsNotCheckedAgain(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	s := createTestScanInRepo(deps, tenantID, "older", scan.ScanTypeSingle)
	s.ScannerConfig = map[string]any{"severity": "high"}
	deps.secValidator.refuseConfigKey = "severity" // the stored value would fail today's check

	if _, err := svc.UpdateScan(context.Background(), scanservice.UpdateScanInput{
		TenantID:      tenantID.String(),
		ScanID:        s.ID.String(),
		Name:          "renamed",
		ScannerName:   "nuclei",
		ScannerConfig: map[string]any{"severity": "high"},
	}); err != nil {
		t.Fatalf("rename with the config sent back unchanged: %v", err)
	}
	if deps.secValidator.configChecks != 0 {
		t.Fatalf("config checked %d time(s), want 0 for an unchanged config", deps.secValidator.configChecks)
	}
}
