package scan

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A name with no DNS answer is refused as "unresolved", not as "no scan zone
// covers this private target": it is not a private target, and the fix is
// DNS, not a zone. A name that resolves to a private address no zone holds
// keeps zone_none.
func TestResolveDispatchTargets_UnresolvedNameHasItsOwnCode(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	zones := &gateZones{zones: []*scanzone.Zone{mustZone(t, tenant, "office", []string{"10.0.0.0/24"}, shared.NewID())}}
	svc := &Service{
		scopeExclusions: &stubExclusions{}, attributionGate: &stubGate{}, zones: zones, logger: logger.NewNop(),
		zoneResolver: mapResolver{addrs: map[string][]string{"intra.example.com": {"192.168.7.7"}}},
	}
	got, err := svc.ResolveDispatchTargets(ctx, DispatchTargetsInput{
		TenantID: tenant, Targets: []string{"gone.example.com", "intra.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	codes := refusalCodes(got)
	if codes["gone.example.com"] != scopedom.RefusalUnresolved {
		t.Fatalf("unresolvable name refused %v, want unresolved", got.Refused)
	}
	if codes["intra.example.com"] != scopedom.RefusalZoneNone {
		t.Fatalf("private name refused %v, want zone_none", got.Refused)
	}
	if scopedom.RefusalMessages[scopedom.RefusalUnresolved] == "" {
		t.Fatal("unresolved has no message")
	}
}
