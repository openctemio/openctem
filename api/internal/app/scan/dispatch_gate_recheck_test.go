package scan

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The claim-time re-check (AllowNonNetworkTargets) re-applies the gate to targets a
// dispatch already let through: a repository dispatched by its asset name is
// not refused for its form, but every check that can turn on a change still
// runs (exclusions; internal addresses need a zone).
func TestResolveDispatchTargets_Recheck(t *testing.T) {
	svc := &Service{scopeExclusions: &stubExclusions{values: map[string]bool{"gone.example.com": true}},
		attributionGate: &stubGate{}, logger: logger.NewNop()}
	targets := []string{"github.com/example/app", "app.example.com", "gone.example.com", "10.0.0.5", "169.254.169.254"}

	plain, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{TenantID: shared.NewID(), Targets: targets})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(refusedTargets(plain), ","), "github.com/example/app") {
		t.Fatalf("a dispatch refuses a repository path as a typed target: refused = %v", refusedTargets(plain))
	}

	got, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{TenantID: shared.NewID(), Targets: targets, AllowNonNetworkTargets: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"github.com/example/app", "app.example.com"}; !reflect.DeepEqual(got.Allowed, want) {
		t.Fatalf("allowed = %v, want %v", got.Allowed, want)
	}
	if want := []string{"gone.example.com"}; !reflect.DeepEqual(got.Excluded, want) {
		t.Fatalf("excluded = %v, want %v", got.Excluded, want)
	}
	refused := strings.Join(refusedTargets(got), ",")
	for _, ip := range []string{"10.0.0.5", "169.254.169.254"} {
		if !strings.Contains(refused, ip) {
			t.Fatalf("%s must stay refused on a re-check without a zone; refused = %v", ip, refused)
		}
	}
}

// An internal address admitted by a zone at dispatch is refused at the
// re-check once the zone no longer covers it (shrunk or deleted).
func TestResolveDispatchTargets_RecheckZoneShrunk(t *testing.T) {
	tenant, sensor := shared.NewID(), shared.NewID()
	before := mustGateZone(t, tenant, "dc-a", []shared.ID{sensor}, "10.1.0.0/16")
	after := mustGateZone(t, tenant, "dc-a", []shared.ID{sensor}, "10.1.0.0/24")
	in := DispatchTargetsInput{TenantID: tenant, SensorID: &sensor, Targets: []string{"10.1.0.5", "10.1.7.5"}, AllowNonNetworkTargets: true}
	for name, tc := range map[string]struct {
		zones []*scanzone.Zone
		want  []string
	}{
		"zone as dispatched": {[]*scanzone.Zone{before}, []string{"10.1.0.5", "10.1.7.5"}},
		"zone shrunk":        {[]*scanzone.Zone{after}, []string{"10.1.0.5"}},
		"zone deleted":       {nil, nil},
	} {
		svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: &stubGate{}, zones: listZones{zones: tc.zones}, logger: logger.NewNop()}
		got, err := svc.ResolveDispatchTargets(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Allowed, tc.want) {
			t.Fatalf("%s: allowed = %v, want %v (refused %v)", name, got.Allowed, tc.want, got.Refused)
		}
	}
}
