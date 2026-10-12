package scan

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The gate's options for the scan trigger: each one's zero value is the
// strict behavior, and each one changes only what it says.

func refusalCodes(d *DispatchTargets) map[string]string {
	out := map[string]string{}
	for _, r := range d.Refused {
		out[r.Target] = r.Code
	}
	return out
}

func TestResolveDispatchTargets_AllowNonNetworkTargets(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: &stubGate{}, zones: &gateZones{}, logger: logger.NewNop()}
	targets := []string{"github.com/acme/app", "nginx:1.25", "10.0.0.5", "100.64.0.1", "app.example.com"}

	// Off (default): the scan target validator refuses what is not a
	// network target and every internal address outside a zone.
	strict, err := svc.ResolveDispatchTargets(ctx, DispatchTargetsInput{TenantID: tenant, Targets: targets})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(strict.Allowed, []string{"100.64.0.1", "app.example.com"}) {
		t.Fatalf("default: allowed = %v", strict.Allowed)
	}
	for _, r := range []string{"github.com/acme/app", "nginx:1.25", "10.0.0.5"} {
		if refusalCodes(strict)[r] != scopedom.RefusalInvalidTarget {
			t.Fatalf("default: %s refused %v, want invalid_target", r, strict.Refused)
		}
	}

	// On, no zones: non-network names pass; every internal address
	// (carrier-grade NAT too) is refused with zone_none.
	in := DispatchTargetsInput{TenantID: tenant, Targets: targets, AllowNonNetworkTargets: true}
	got, err := svc.ResolveDispatchTargets(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Allowed, []string{"github.com/acme/app", "nginx:1.25", "app.example.com"}) {
		t.Fatalf("allowed = %v", got.Allowed)
	}
	for _, r := range []string{"10.0.0.5", "100.64.0.1"} {
		if refusalCodes(got)[r] != scopedom.RefusalZoneNone {
			t.Fatalf("%s refused %v, want zone_none", r, got.Refused)
		}
	}

	// On, with zones: zone routing refuses what no zone covers.
	svc.zones = &gateZones{zones: []*scanzone.Zone{mustZone(t, tenant, "office", []string{"10.0.0.0/24"}, shared.NewID())}}
	got, err = svc.ResolveDispatchTargets(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if refusalCodes(got)["100.64.0.1"] != scopedom.RefusalZoneNone || refusalCodes(got)["10.0.0.5"] != "" {
		t.Fatalf("with zones: refused = %v", got.Refused)
	}

	// The zone lookup failing refuses (fail closed).
	svc.zones = &gateZones{err: errors.New("db down")}
	if _, err := svc.ResolveDispatchTargets(ctx, in); err == nil {
		t.Fatal("a failed zone lookup must refuse the dispatch")
	}
}

func TestResolveDispatchTargets_SkipZoneRouting(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	zones := &gateZones{zones: []*scanzone.Zone{mustZone(t, tenant, "office", []string{"10.0.0.0/24"})}} // no sensor
	svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: &stubGate{}, zones: zones, logger: logger.NewNop()}
	in := DispatchTargetsInput{TenantID: tenant, Targets: []string{"10.0.0.5", "203.0.113.9"}}

	routed, err := svc.ResolveDispatchTargets(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if refusalCodes(routed)["10.0.0.5"] != scopedom.RefusalZoneNoSensor || !reflect.DeepEqual(routed.Allowed, []string{"203.0.113.9"}) {
		t.Fatalf("default routes: refused = %v", routed.Refused)
	}

	in.SkipZoneRouting = true
	got, err := svc.ResolveDispatchTargets(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Allowed, []string{"10.0.0.5", "203.0.113.9"}) || got.ZoneOf != nil || len(got.Refused) != 0 {
		t.Fatalf("skip routing: %+v", got)
	}
}

func TestResolveDispatchTargets_TakeoverOnly(t *testing.T) {
	ctx := context.Background()
	member := shared.NewID().String()
	gate := &takeoverStub{
		stubGate: stubGate{
			blocked:      map[string]attribution.State{member: attribution.StateDependency},
			blockedTyped: map[string]attribution.State{"saas.example.com": attribution.StateDependency},
		},
		admitted: map[string]bool{member: true, "saas.example.com": true},
	}
	svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: gate, logger: logger.NewNop()}
	in := DispatchTargetsInput{TenantID: shared.NewID(), Targets: []string{"saas.example.com", "dangling.example.com"},
		Assets: map[string]DispatchAsset{"dangling.example.com": {IDs: []string{member}}}}

	strict, err := svc.ResolveDispatchTargets(ctx, in)
	if err != nil || len(strict.Allowed) != 0 || len(strict.Refused) != 2 {
		t.Fatalf("default: %+v %v", strict, err)
	}
	in.TakeoverOnly = true
	got, err := svc.ResolveDispatchTargets(ctx, in)
	if err != nil || !reflect.DeepEqual(got.Allowed, []string{"saas.example.com", "dangling.example.com"}) {
		t.Fatalf("takeover only: %+v %v", got, err)
	}
	gate.err = errors.New("db down")
	if _, err := svc.ResolveDispatchTargets(ctx, in); err == nil {
		t.Fatal("a failed takeover lookup must refuse the dispatch")
	}
}

func TestResolveDispatchTargets_ActScopeAssetsByID(t *testing.T) {
	ctx := context.Background()
	id := shared.NewID()
	stub := &stubActScope{targets: map[string]string{"member.example.com": actscope.ReasonNoScopeTarget}}
	svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: &stubGate{}, actScope: stub, logger: logger.NewNop()}
	in := DispatchTargetsInput{TenantID: shared.NewID(), Targets: []string{"member.example.com", "typed.example.com"}, ActScope: true,
		Assets: map[string]DispatchAsset{"member.example.com": {IDs: []string{id.String()}}}}

	// Default: the member's name is also checked as free text.
	strict, err := svc.ResolveDispatchTargets(ctx, in)
	if err != nil || !reflect.DeepEqual(strict.Allowed, []string{"typed.example.com"}) {
		t.Fatalf("default: %+v %v", strict, err)
	}
	if got := stub.got[0]; !reflect.DeepEqual(got.Targets, in.Targets) || !reflect.DeepEqual(got.AssetIDs, []shared.ID{id}) {
		t.Fatalf("default checker input = %+v", got)
	}

	in.ActScopeAssetsByID = true
	got, err := svc.ResolveDispatchTargets(ctx, in)
	if err != nil || !reflect.DeepEqual(got.Allowed, []string{"member.example.com", "typed.example.com"}) {
		t.Fatalf("by id: %+v %v", got, err)
	}
	if in := stub.got[1]; !reflect.DeepEqual(in.Targets, []string{"typed.example.com"}) || !reflect.DeepEqual(in.AssetIDs, []shared.ID{id}) {
		t.Fatalf("by id checker input = %+v", in)
	}
	// The asset itself is still checked.
	stub.assets = map[shared.ID]bool{id: true}
	got, err = svc.ResolveDispatchTargets(ctx, in)
	if err != nil || refusalCodes(got)["member.example.com"] != scopedom.RefusalOutOfDataScope {
		t.Fatalf("member outside the data scope: %+v %v", got, err)
	}
}

func TestResolveDispatchTargets_MaxTargets(t *testing.T) {
	svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: &stubGate{}, logger: logger.NewNop()}
	many := make([]string, maxResolvedTargets+1)
	for i := range many {
		many[i] = fmt.Sprintf("h%05d.example.com", i)
	}
	in := DispatchTargetsInput{TenantID: shared.NewID(), Targets: many, AllowNonNetworkTargets: true}
	if _, err := svc.ResolveDispatchTargets(context.Background(), in); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("default bound: err = %v", err)
	}
	in.MaxTargets = len(many)
	if got, err := svc.ResolveDispatchTargets(context.Background(), in); err != nil || len(got.Allowed) != len(many) {
		t.Fatalf("raised bound: %v", err)
	}
}

// An entry with only AlsoMatch is a typed target with more names for the
// exclusion match; an entry with neither ids nor names is refused.
func TestResolveDispatchTargets_AliasOnlyAsset(t *testing.T) {
	ctx := context.Background()
	gate := &stubGate{}
	svc := &Service{scopeExclusions: &stubExclusions{values: map[string]bool{"198.51.100.7": true}}, attributionGate: gate, logger: logger.NewNop()}
	in := DispatchTargetsInput{TenantID: shared.NewID(), Targets: []string{"db.example.com", "web.example.com"},
		Assets: map[string]DispatchAsset{
			"db.example.com":  {AlsoMatch: []string{"198.51.100.7"}},
			"web.example.com": {AlsoMatch: []string{"198.51.100.8"}},
		}}
	got, err := svc.ResolveDispatchTargets(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Excluded, []string{"db.example.com"}) || !reflect.DeepEqual(got.Allowed, []string{"web.example.com"}) {
		t.Fatalf("got %+v", got)
	}
	if !reflect.DeepEqual(gate.askedTyped, []string{"web.example.com"}) || len(gate.asked) != 0 {
		t.Fatalf("ownership asked by name %v, by id %v; want web.example.com by name", gate.askedTyped, gate.asked)
	}
	in.Assets["web.example.com"] = DispatchAsset{}
	if _, err := svc.ResolveDispatchTargets(ctx, in); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("an empty asset entry: err = %v, want a validation error", err)
	}
}

// Asset keys match targets case-insensitively; two keys that differ only
// in case are both checked.
func TestResolveDispatchTargets_AssetKeysFoldCase(t *testing.T) {
	a, b := shared.NewID().String(), shared.NewID().String()
	gate := &stubGate{blocked: map[string]attribution.State{b: attribution.StateRejected}}
	svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: gate, logger: logger.NewNop()}
	got, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{TenantID: shared.NewID(),
		Targets: []string{"App.Example.com"},
		Assets:  map[string]DispatchAsset{"app.example.com": {IDs: []string{a}}, "APP.EXAMPLE.COM": {IDs: []string{b}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Allowed) != 0 || refusalCodes(got)["App.Example.com"] != scopedom.RefusalRejected {
		t.Fatalf("got %+v", got)
	}
}

// A target refused by the act scope and above its tier is reported once,
// under the act scope: an actor learns nothing about the scope entries of
// what they may not scan.
func TestResolveDispatchTargets_ActScopeBeforeTier(t *testing.T) {
	stub := &stubActScope{targets: map[string]string{"both.example.com": actscope.ReasonOutOfDataScope}}
	gate := &stubGate{ceiling: map[string]scopedom.Tier{"both.example.com": scopedom.TierPassive, "tier.example.com": scopedom.TierPassive}}
	svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: gate, actScope: stub, logger: logger.NewNop()}
	got, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{TenantID: shared.NewID(),
		Targets: []string{"both.example.com", "tier.example.com", "ok.example.com"}, ActScope: true})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"both.example.com": scopedom.RefusalOutOfDataScope, "tier.example.com": scopedom.RefusalTierExceeds}
	if !reflect.DeepEqual(refusalCodes(got), want) || !reflect.DeepEqual(got.Allowed, []string{"ok.example.com"}) {
		t.Fatalf("got %+v", got)
	}
}

// The scan trigger refuses to run without each of its checks wired: before,
// an unwired exclusion filter, ownership gate or act-scope check was
// silently skipped.
func TestResolveScanTargets_UnwiredChecksFailClosed(t *testing.T) {
	for name, unwire := range map[string]func(*Service){
		"exclusions": func(s *Service) { s.scopeExclusions = nil },
		"ownership":  func(s *Service) { s.attributionGate = nil },
		"act scope":  func(s *Service) { s.actScope = nil },
	} {
		svc := allowAllChecks(&Service{logger: logger.NewNop()})
		unwire(svc)
		if got, err := svc.resolveScanTargets(context.Background(), testScan("nuclei", "app.example.com")); err == nil {
			t.Fatalf("%s not wired: dispatched %v, want the run stopped", name, got.Targets)
		}
	}
	svc := allowAllChecks(&Service{logger: logger.NewNop()})
	svc.scopeExclusions = nil
	if _, err := svc.resolveScanTargets(context.Background(), testScan("nuclei", "app.example.com")); !errors.Is(err, ErrDispatchGateUnavailable) {
		t.Fatalf("err = %v, want ErrDispatchGateUnavailable", err)
	}
}
