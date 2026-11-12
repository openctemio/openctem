package scan

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A triggered run re-applies the private-range policy of scan create for a
// tenant without scan zones: internal addresses are left out. Asset group
// members (never validated on create) and direct targets saved while a zone
// (since deleted) covered them are both caught.
func TestResolveScanTargets_InternalAddressesOnlyInsideZones(t *testing.T) {
	members := []*assetgroup.GroupAsset{
		{ID: shared.NewID(), Name: "192.168.50.10"},   // private member, no zone
		{ID: shared.NewID(), Name: "app.example.com"}, // hostname: not resolved here
		{ID: shared.NewID(), Name: "http://127.0.0.1:8080/"},
	}
	zones := &gateZones{}
	svc := allowAllChecks(&Service{assetGroupRepo: &stubGroupAssetsRepo{assets: members}, zones: zones, logger: logger.NewNop()})
	sc := testScan("nuclei", "10.20.0.5", "203.0.113.7", "169.254.169.254")
	sc.AssetGroupID = shared.NewID()

	got, err := svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"203.0.113.7", "app.example.com"}; !reflect.DeepEqual(got.Targets, want) {
		t.Fatalf("no zones: targets = %v, want %v", got.Targets, want)
	}
	if got.InternalOutsideZones != 4 {
		t.Fatalf("InternalOutsideZones = %d, want 4", got.InternalOutsideZones)
	}
	rc := map[string]any{}
	if err := recordResolvedTargets(sc, got, rc); err != nil || rc["internal_outside_zones_target_count"] != 4 {
		t.Fatalf("record: err=%v ctx=%v", err, rc)
	}

	// With zones, zone routing decides (it refuses what no zone covers):
	// nothing is dropped here.
	tenant := sc.TenantID
	zones.zones = append(zones.zones, mustZone(t, tenant, "office", []string{"10.20.0.0/16"}, shared.NewID()))
	got, err = svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if got.InternalOutsideZones != 0 || len(got.Targets) != 6 {
		t.Fatalf("with zones: targets = %v, dropped %d", got.Targets, got.InternalOutsideZones)
	}
	zones.zones = nil

	// Only internal targets outside zones: the run is refused with a reason.
	only := testScan("nuclei", "192.168.1.1")
	only.TenantID = tenant
	svc.assetGroupRepo = nil
	got, err = svc.resolveScanTargets(context.Background(), only)
	if err != nil {
		t.Fatal(err)
	}
	var de *shared.DomainError
	if err := recordResolvedTargets(only, got, map[string]any{}); !errors.As(err, &de) || de.Code != "INTERNAL_TARGET_OUTSIDE_ZONES" {
		t.Fatalf("err = %v, want INTERNAL_TARGET_OUTSIDE_ZONES", err)
	}

	// The zone lookup failing stops the run (fail closed).
	zones.err = errors.New("db down")
	if _, err := svc.resolveScanTargets(context.Background(), only); err == nil {
		t.Fatal("a failed zone lookup must stop the run")
	}
}
