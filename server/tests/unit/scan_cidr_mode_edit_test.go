package unit

import (
	"context"
	"testing"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// rangeWorkflowScan stores a workflow scan of a range whose workflow has a
// Host discovery step, with the stored CIDR mode given ("" for a scan saved
// before live hosts first existed).
func rangeWorkflowScan(t *testing.T, deps *testScanServiceDeps, tenantID shared.ID, mode scan.CIDRMode) *scan.Scan {
	t.Helper()
	s := createTestScanInRepo(deps, tenantID, "range scan "+string(mode), scan.ScanTypeWorkflow)
	s.Targets = []string{"198.51.100.0/24"}
	s.TargetOptions = scan.TargetOptions{CIDRMode: mode}
	hosts, err := scanworkflow.NewStep(*s.ScanWorkflowID, "hosts", "Host discovery", 1, []string{"discover.hosts"})
	if err != nil {
		t.Fatal(err)
	}
	deps.stepRepo.steps[s.ScanWorkflowID.String()] = []*scanworkflow.Step{hosts}
	return s
}

// Decision A1 as refined by the owner: editing a scan never switches it to
// live hosts first; only a person choosing it does.
func TestUpdateScan_KeepsTheCIDRMode(t *testing.T) {
	cases := []struct {
		name   string
		stored scan.CIDRMode
		sent   scan.CIDRMode
		want   scan.CIDRMode
	}{
		{"an old sweeping scan stays sweeping", "", "", ""},
		{"an explicit sweep stays sweep", scan.CIDRModeSweep, "", scan.CIDRModeSweep},
		{"a liveness scan stays liveness", scan.CIDRModeLiveness, "", scan.CIDRModeLiveness},
		{"choosing live hosts first switches", "", scan.CIDRModeLiveness, scan.CIDRModeLiveness},
		{"choosing sweep switches back", scan.CIDRModeLiveness, scan.CIDRModeSweep, scan.CIDRModeSweep},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, deps := newTestScanService()
			tenantID := shared.NewID()
			s := rangeWorkflowScan(t, deps, tenantID, tc.stored)
			got, err := svc.UpdateScan(context.Background(), scanservice.UpdateScanInput{
				TenantID: tenantID.String(), ScanID: s.ID.String(), Description: "edited",
				TargetOptions: &scan.TargetOptions{CIDRMode: tc.sent},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got.TargetOptions.CIDRMode != tc.want {
				t.Fatalf("cidr_mode = %q, want %q", got.TargetOptions.CIDRMode, tc.want)
			}
		})
	}
}

// Live hosts first still needs a Host discovery step on edit.
func TestUpdateScan_LivenessNeedsHostDiscovery(t *testing.T) {
	svc, deps := newTestScanService()
	tenantID := shared.NewID()
	s := rangeWorkflowScan(t, deps, tenantID, "")
	deps.stepRepo.steps[s.ScanWorkflowID.String()] = nil
	_, err := svc.UpdateScan(context.Background(), scanservice.UpdateScanInput{
		TenantID: tenantID.String(), ScanID: s.ID.String(),
		TargetOptions: &scan.TargetOptions{CIDRMode: scan.CIDRModeLiveness},
	})
	if err == nil {
		t.Fatal("explicit liveness on a workflow without Host discovery must be refused")
	}
}
