package scan

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/scanzone"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// A public target no zone covers is unzoned: it goes to the tenant's sensors
// as before zones. The zone sensor readiness check (ZoneSensorTier, set by the
// dry run that scan create runs) judges a zone's sensors and has nothing to
// judge for it. It used to dereference the nil zone and turn POST /scans into
// a 500 for a tenant whose zones cover none of the targets.
func TestResolveDispatchTargets_ZoneSensorTierUnzonedTarget(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	internal := mustZone(t, tenant, "Internal", []string{"10.0.0.0/8"}, shared.NewID())
	svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: &stubGate{},
		zones:        &gateZones{zones: []*scanzone.Zone{internal}},
		zoneResolver: mapResolver{addrs: map[string][]string{"www.example.com": {"192.0.2.10"}}},
		logger:       logger.NewNop()}
	for _, tier := range []int{scanzone.TierUnknown, 0, 2} {
		tier := tier
		got, err := svc.ResolveDispatchTargets(ctx, DispatchTargetsInput{
			TenantID: tenant, Targets: []string{"www.example.com", "198.51.100.7"}, DryRun: true, ZoneSensorTier: &tier,
		})
		if err != nil {
			t.Fatalf("tier %d: %v", tier, err)
		}
		if len(got.Allowed) != 2 || len(got.Refused) != 0 {
			t.Fatalf("tier %d: allowed %v refused %v, want both unzoned targets allowed", tier, got.Allowed, got.Refused)
		}
		for _, target := range got.Allowed {
			if z, ok := got.ZoneOf[target]; !ok || z != nil {
				t.Fatalf("tier %d: %s routed to %v (present %v), want unzoned", tier, target, z, ok)
			}
		}
	}
}
