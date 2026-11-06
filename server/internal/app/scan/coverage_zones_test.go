package scan

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func zonedCoverageService(t *testing.T, tenant shared.ID) *Service {
	t.Helper()
	zones := &gateZones{zones: []*scanzone.Zone{mustZone(t, tenant, "office", []string{"10.0.0.0/24"}, shared.NewID())}}
	return &Service{
		scopeExclusions: &stubExclusions{}, attributionGate: &stubGate{}, zones: zones, logger: logger.NewNop(),
		zoneResolver: mapResolver{addrs: map[string][]string{
			"www.example.com":    {"203.0.113.10"},
			"intra.example.com":  {"192.168.7.7"},
			"office.example.com": {"10.0.0.5"},
		}},
	}
}

// A passive batch: public names (resolving publicly or not at all) skip
// zone routing; internal names (a private answer, a non-public suffix) and
// addresses keep it. The batch's first target picks the group that runs.
func TestCoverageZoneGroup(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	svc := zonedCoverageService(t, tenant)
	batch := []string{"gone.example.com", "intra.example.com", "www.example.com", "host.corp", "203.0.113.9", "office.example.com"}

	run, deferred, skip, err := svc.coverageZoneGroup(ctx, tenant, batch, true)
	if err != nil {
		t.Fatal(err)
	}
	if !skip || strings.Join(run, ",") != "gone.example.com,www.example.com" {
		t.Fatalf("public group = %v skip=%v", run, skip)
	}
	if strings.Join(deferred, ",") != "intra.example.com,host.corp,203.0.113.9,office.example.com" {
		t.Fatalf("deferred = %v", deferred)
	}

	// Oldest target internal: the routed group runs now, public names wait.
	run, deferred, skip, err = svc.coverageZoneGroup(ctx, tenant, []string{"intra.example.com", "gone.example.com"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if skip || strings.Join(run, ",") != "intra.example.com" || strings.Join(deferred, ",") != "gone.example.com" {
		t.Fatalf("routed group = %v deferred %v skip=%v", run, deferred, skip)
	}

	// An active capability is always routed, whole.
	run, deferred, skip, _ = svc.coverageZoneGroup(ctx, tenant, batch, false)
	if skip || len(run) != len(batch) || len(deferred) != 0 {
		t.Fatalf("active batch = %v deferred %v skip=%v", run, deferred, skip)
	}

	// No zones: nothing changes.
	plain := &Service{logger: logger.NewNop()}
	run, deferred, skip, _ = plain.coverageZoneGroup(ctx, tenant, batch, true)
	if skip || len(run) != len(batch) || len(deferred) != 0 {
		t.Fatalf("zoneless batch = %v deferred %v skip=%v", run, deferred, skip)
	}
}

// The public group passes the gate without zone routing, so a public name
// that stopped resolving reaches its DNS re-check; the routed group keeps
// zone routing (a private name no zone holds is still refused).
func TestCoverageZoneGroup_GateEffect(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	svc := zonedCoverageService(t, tenant)
	tier := scopedom.TierPassive
	gate := func(targets []string, skip bool) *DispatchTargets {
		t.Helper()
		got, err := svc.ResolveDispatchTargets(ctx, DispatchTargetsInput{TenantID: tenant, Targets: targets,
			PassiveOnly: true, Tier: &tier, SkipZoneRouting: skip})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	run, deferred, skip, _ := svc.coverageZoneGroup(ctx, tenant, []string{"gone.example.com", "intra.example.com"}, true)
	if got := gate(run, skip); len(got.Allowed) != 1 || got.Allowed[0] != "gone.example.com" {
		t.Fatalf("public group allowed %v refused %v", got.Allowed, got.Refused)
	}
	run, _, skip, _ = svc.coverageZoneGroup(ctx, tenant, deferred, true)
	if got := gate(run, skip); refusalCodes(got)["intra.example.com"] != scopedom.RefusalZoneNone {
		t.Fatalf("internal name refused %v, want zone_none", got.Refused)
	}
}

// Only StartCoverage's own context skips the trigger's zone routing.
func TestZoneRoutingSkippedOnlyWithMarker(t *testing.T) {
	if zoneRoutingSkipped(context.Background()) {
		t.Fatal("a plain context skips zone routing")
	}
	// A foreign key of the same name and value must not count.
	type foreignKey string
	if zoneRoutingSkipped(context.WithValue(context.Background(), foreignKey("zoneRoutingKey"), true)) {
		t.Fatal("a string key skips zone routing")
	}
	if !zoneRoutingSkipped(withoutZoneRouting(context.Background())) {
		t.Fatal("the marker does not skip zone routing")
	}
}

// Special-use names are never public, even when they look registrable: they
// keep zone routing. Real public names, including look-alikes whose label
// merely contains a special-use word, stay public.
func TestPublicName_SpecialUseNamesExcluded(t *testing.T) {
	for _, h := range []string{
		"printer.home.arpa", "home.arpa", "4.3.2.1.in-addr.arpa", "1.0.0.0.ip6.arpa",
		"nas.local", "app.localhost", "localhost", "db.internal", "api.corp.internal",
		"x.test", "bad.invalid", "abc.onion", "host.example", "Printer.HOME.ARPA.",
	} {
		if publicName(scanzone.Route{Target: h}) {
			t.Errorf("%s counted as a public name", h)
		}
	}
	for _, h := range []string{"www.example.com", "localnews.com", "internal.example.org", "mytest.io", "test.co.uk"} {
		if !publicName(scanzone.Route{Target: h}) {
			t.Errorf("%s not counted as a public name", h)
		}
	}
}
