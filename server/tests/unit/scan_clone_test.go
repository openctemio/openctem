package unit

import (
	"context"
	"testing"
	"time"

	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A clone is a new scan: it keeps the probe ceiling it was given, starts
// paused (the console always said so; the API started it active, so a
// scheduled clone ran by itself) and passes the create's probe gates.

func TestCloneScan_KeepsIntensityAndStartsPaused(t *testing.T) {
	for _, in := range []scan.Intensity{scan.IntensityPassive, scan.IntensityIntrusive} {
		t.Run(string(in), func(t *testing.T) {
			svc, deps := newTestScanService()
			tenantID := shared.NewID()
			original := createTestScanInRepo(deps, tenantID, "orig "+string(in), scan.ScanTypeSingle)
			if err := original.SetIntensity(in); err != nil {
				t.Fatal(err)
			}
			at := time.Date(2000, 1, 1, 2, 0, 0, 0, time.UTC)
			if err := original.SetSchedule(scan.ScheduleDaily, "", nil, &at, "UTC"); err != nil || original.NextRunAt == nil {
				t.Fatalf("schedule: %v next %v", err, original.NextRunAt)
			}

			clone, err := svc.CloneScan(context.Background(), tenantID.String(), original.ID.String(), "copy", shared.NewID().String())
			if err != nil {
				t.Fatal(err)
			}
			if clone.Intensity != in {
				// A passive scan used to clone as active: the copy sent
				// probes the original never did.
				t.Fatalf("clone intensity = %q, want %q", clone.Intensity, in)
			}
			if clone.Status != scan.StatusPaused || clone.NextRunAt != nil {
				t.Fatalf("clone status = %s next %v, want paused with no next run", clone.Status, clone.NextRunAt)
			}
		})
	}
}

// tierGate reports every target above the scope tier ceiling.
type tierGate struct{ allOwned }

func (tierGate) TierExceeded(_ context.Context, _ shared.ID, targets []string, _ scopedom.Tier) (map[string]*scopedom.RuleRef, error) {
	out := map[string]*scopedom.RuleRef{}
	for _, t := range targets {
		out[t] = &scopedom.RuleRef{}
	}
	return out, nil
}

func TestCloneScan_RefusesTargetsAboveTheTierCeiling(t *testing.T) {
	svc, deps := newTestScanService(scanservice.WithAttributionGate(tierGate{}))
	tenantID := shared.NewID()
	original := createTestScanInRepo(deps, tenantID, "tier", scan.ScanTypeSingle)
	original.Targets = []string{"app.example.com"}

	if _, err := svc.CloneScan(context.Background(), tenantID.String(), original.ID.String(), "copy", shared.NewID().String()); err == nil {
		t.Fatal("a clone whose targets the scope tier ceiling refuses for its scanner must be refused")
	}
}

func TestCloneScan_AnotherTenantsScanIsNotFound(t *testing.T) {
	svc, deps := newTestScanService()
	original := createTestScanInRepo(deps, shared.NewID(), "theirs", scan.ScanTypeSingle)

	if _, err := svc.CloneScan(context.Background(), shared.NewID().String(), original.ID.String(), "copy", shared.NewID().String()); err == nil {
		t.Fatal("cloning another tenant's scan must be refused")
	}
}
