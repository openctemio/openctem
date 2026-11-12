package scan

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// stubVantage answers per tenant: another tenant's rows are never returned.
type stubVantage struct {
	byTenant map[shared.ID]scanzone.VantageAnswers
	err      error
	since    time.Time
}

func (v *stubVantage) VantageAnswers(_ context.Context, tenantID shared.ID, names []string, since time.Time) (scanzone.VantageAnswers, error) {
	v.since = since
	if v.err != nil {
		return nil, v.err
	}
	out := scanzone.VantageAnswers{}
	for _, n := range names {
		if a, ok := v.byTenant[tenantID][n]; ok {
			out[n] = a
		}
	}
	return out, nil
}

// splitHorizonGate is the owner's case: one laptop sensor in zone Internal
// (10.0.0.0/8); the platform resolves nothing of the internal names.
func splitHorizonGate(t *testing.T, tenant shared.ID, excl *stubExclusions, gate *stubGate, v *stubVantage) (*Service, *scanzone.Zone, shared.ID) {
	t.Helper()
	laptop := shared.NewID()
	internal := mustZone(t, tenant, "Internal", []string{"10.0.0.0/8"}, laptop)
	v.byTenant = map[shared.ID]scanzone.VantageAnswers{tenant: {
		"intranet.example.com": {{Observer: laptop, Addrs: []netip.Addr{netip.MustParseAddr("10.20.0.5")}, ObservedAt: time.Now()}},
		"hr.example.com":       {{Observer: laptop, Addrs: []netip.Addr{netip.MustParseAddr("10.20.0.9")}, ObservedAt: time.Now()}},
	}}
	svc := &Service{scopeExclusions: excl, attributionGate: gate, zones: &gateZones{zones: []*scanzone.Zone{internal}},
		zoneResolver: mapResolver{addrs: map[string][]string{"www.example.com": {"192.0.2.10"}}}, vantage: v, logger: logger.NewNop()}
	return svc, internal, laptop
}

func TestResolveDispatchTargets_SensorVantageRoutesInternalName(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	v := &stubVantage{}
	svc, internal, _ := splitHorizonGate(t, tenant, &stubExclusions{}, &stubGate{}, v)
	got, err := svc.ResolveDispatchTargets(ctx, DispatchTargetsInput{
		TenantID: tenant, Targets: []string{"intranet.example.com", "www.example.com", "gone.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if z := got.ZoneOf["intranet.example.com"]; z == nil || z.ID != internal.ID {
		t.Fatalf("internal-only name routed to %v, want Internal (refused %v)", z, got.Refused)
	}
	// A public name keeps the platform's routing (unzoned, any eligible
	// sensor including the same laptop).
	if z, ok := got.ZoneOf["www.example.com"]; !ok || z != nil {
		t.Fatalf("public name = %v (present %v), want unzoned", z, ok)
	}
	if c := refusalCodes(got)["gone.example.com"]; c != scopedom.RefusalUnresolved {
		t.Fatalf("name no vantage resolves refused %q, want unresolved", c)
	}
	if time.Since(v.since) < 6*24*time.Hour {
		t.Fatalf("answers read since %v: want the resolve TTL window", v.since)
	}
}

// A sensor's private answer is never a scope grant: an excluded or rejected
// address refuses the name.
func TestResolveDispatchTargets_SensorVantageExcludedOrRejectedAddress(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	excl := &stubExclusions{values: map[string]bool{"10.20.0.5": true}}
	gate := &stubGate{blockedTyped: map[string]attribution.State{"10.20.0.9": attribution.StateRejected}}
	svc, _, _ := splitHorizonGate(t, tenant, excl, gate, &stubVantage{})
	got, err := svc.ResolveDispatchTargets(ctx, DispatchTargetsInput{TenantID: tenant, Targets: []string{"intranet.example.com", "hr.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	codes := refusalCodes(got)
	for _, n := range []string{"intranet.example.com", "hr.example.com"} {
		if codes[n] != scopedom.RefusalVantageOutOfScope {
			t.Errorf("%s refused %q, want %s", n, codes[n], scopedom.RefusalVantageOutOfScope)
		}
		if _, routed := got.ZoneOf[n]; routed {
			t.Errorf("%s routed although its address is not allowed", n)
		}
	}
}

// Another tenant's sensors' answers never route this tenant's names.
func TestResolveDispatchTargets_SensorVantageCrossTenant(t *testing.T) {
	ctx, owner, other := context.Background(), shared.NewID(), shared.NewID()
	svc, _, _ := splitHorizonGate(t, owner, &stubExclusions{}, &stubGate{}, &stubVantage{})
	got, err := svc.ResolveDispatchTargets(ctx, DispatchTargetsInput{TenantID: other, Targets: []string{"intranet.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if c := refusalCodes(got)["intranet.example.com"]; c != scopedom.RefusalUnresolved {
		t.Fatalf("another tenant's answer was used: refused %q", c)
	}
}

// A failed read of the answers routes by the platform only (never wider);
// a failed exclusion check of an answer refuses the dispatch (fail closed).
func TestResolveDispatchTargets_SensorVantageFailures(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	v := &stubVantage{}
	svc, _, _ := splitHorizonGate(t, tenant, &stubExclusions{}, &stubGate{}, v)
	v.err = errors.New("db down")
	got, err := svc.ResolveDispatchTargets(ctx, DispatchTargetsInput{TenantID: tenant, Targets: []string{"intranet.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if c := refusalCodes(got)["intranet.example.com"]; c != scopedom.RefusalUnresolved {
		t.Fatalf("read failure: refused %q, want unresolved", c)
	}

	v2 := &stubVantage{}
	svc2, _, _ := splitHorizonGate(t, tenant, &stubExclusions{}, &stubGate{}, v2)
	svc2.scopeExclusions = failOnAddr{}
	if _, err := svc2.ResolveDispatchTargets(ctx, DispatchTargetsInput{TenantID: tenant, Targets: []string{"intranet.example.com"}}); err == nil {
		t.Fatal("exclusion check of an answer failed but the dispatch went on")
	}
}

// failOnAddr passes the name check and fails the check of an address.
type failOnAddr struct{}

func (failOnAddr) ExcludedTargets(_ context.Context, _ string, cs []scope.ExclusionCandidate) (map[shared.ID]bool, error) {
	for _, c := range cs {
		for _, v := range c.Values {
			if _, err := netip.ParseAddr(v); err == nil {
				return nil, errors.New("exclusions unavailable")
			}
		}
	}
	return map[shared.ID]bool{}, nil
}
