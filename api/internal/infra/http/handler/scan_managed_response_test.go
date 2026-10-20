package handler

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A managed scan is reported as managed (no owner to take over) and names
// the policy that owns it; a person's scan reports neither.
func TestBuildScanResponse_ManagedBy(t *testing.T) {
	managed, err := scan.NewScan(shared.NewID(), "Continuous coverage: probe.http", shared.ID{}, scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	managed.ManagedBy, managed.ManagedKey = scan.ManagedByCoverage, "probe.http"
	got := buildScanResponse(managed, nil, false)
	if got.OwnerState != "managed" || got.ManagedBy != "coverage" {
		t.Errorf("managed scan: owner_state=%q managed_by=%q", got.OwnerState, got.ManagedBy)
	}

	mine, _ := scan.NewScan(shared.NewID(), "Weekly", shared.ID{}, scan.ScanTypeSingle)
	got = buildScanResponse(mine, nil, false)
	if got.OwnerState != "missing" || got.ManagedBy != "" {
		t.Errorf("person's scan: owner_state=%q managed_by=%q", got.OwnerState, got.ManagedBy)
	}
}
