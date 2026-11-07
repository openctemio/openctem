package unit

import (
	"context"
	"errors"
	"testing"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Large range targets on edit (RFC-151): the organization's limit, the
// confirmation and live hosts first through a scan that finds hosts all
// apply when an edit names a range wider than a /16.

type fixedRangeLimits int

func (f fixedRangeLimits) MaxRangeHostBits(context.Context, shared.ID) (int, error) {
	return int(f), nil
}

func largeRangeService(t *testing.T, tenantID shared.ID, hostBits int) (*scanservice.Service, *testScanServiceDeps) {
	t.Helper()
	zone, err := scanzone.NewZone(tenantID, "datacenter", "", false, []string{"10.0.0.0/8"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return newTestScanService(
		scanservice.WithScanZones(&fakeZoneDir{zones: []*scanzone.Zone{zone}}, nil),
		scanservice.WithRangeLimits(fixedRangeLimits(hostBits)),
	)
}

func editLargeTargets(svc *scanservice.Service, tenantID shared.ID, s *scan.Scan, confirm bool, targets ...string) (*scan.Scan, error) {
	return svc.UpdateScan(context.Background(), scanservice.UpdateScanInput{
		TenantID: tenantID.String(), ScanID: s.ID.String(), Targets: &targets, ConfirmLargeRange: confirm,
	})
}

// A workflow that finds hosts first takes a confirmed /8 on edit and runs it
// live hosts first; without the confirmation it is refused.
func TestUpdateScan_LargeRangeNeedsConfirmation(t *testing.T) {
	tenantID := shared.NewID()
	svc, deps := largeRangeService(t, tenantID, 24)
	s := rangeWorkflowScan(t, deps, tenantID, "")

	if _, err := editLargeTargets(svc, tenantID, s, false, "10.0.0.0/8"); domainCode(err) != scanservice.CodeLargeRangeUnconfirmed {
		t.Fatalf("unconfirmed /8: err = %v", err)
	}
	got, err := editLargeTargets(svc, tenantID, s, true, "10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if got.TargetOptions.CIDRMode != scan.CIDRModeLiveness {
		t.Fatalf("cidr_mode = %q, want liveness", got.TargetOptions.CIDRMode)
	}
}

// An edit that puts a /8 on a single-scanner scan is refused even when
// confirmed: its scanner would probe every address (the CIDR mode is settled
// again on every target edit, not only for a liveness scan).
func TestUpdateScan_SingleScannerRefusesLargeRange(t *testing.T) {
	tenantID := shared.NewID()
	svc, deps := largeRangeService(t, tenantID, 24)
	s := createTestScanInRepo(deps, tenantID, "single", scan.ScanTypeSingle)
	if _, err := editLargeTargets(svc, tenantID, s, true, "10.0.0.0/8"); domainCode(err) != scanservice.CodeLivenessNeedsHostDiscovery {
		t.Fatalf("single scanner /8: err = %v", err)
	}
	// A /16 is unchanged.
	if _, err := editLargeTargets(svc, tenantID, s, false, "10.1.0.0/16"); err != nil {
		t.Fatalf("/16: %v", err)
	}
}

// The organization's default limit is a /16: a /8 is refused at validation,
// confirmed or not, until the organization opts in.
func TestUpdateScan_LargeRangeNeedsTheOrganizationsOptIn(t *testing.T) {
	tenantID := shared.NewID()
	svc, deps := largeRangeService(t, tenantID, 16)
	s := rangeWorkflowScan(t, deps, tenantID, "")
	_, err := editLargeTargets(svc, tenantID, s, true, "10.0.0.0/8")
	if err == nil || !errors.Is(err, shared.ErrValidation) || domainCode(err) == scanservice.CodeLargeRangeUnconfirmed {
		t.Fatalf("a /8 at the /16 default: err = %v", err)
	}
}
