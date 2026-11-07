package scan

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// Large range targets (RFC-151): a range wider than a /16 is cut into /16
// chunks at dispatch, to the tenant's in-scope networks minus exclusions
// and the deny list, and only where the dispatch allows it.

// tenantTargetRepo holds active scope entries per tenant; any other method
// panics (embedded nil interface).
type tenantTargetRepo struct {
	scopedom.TargetRepository
	byTenant map[shared.ID][]*scopedom.Target
	err      error
}

func (r *tenantTargetRepo) ListActive(_ context.Context, tenantID shared.ID) ([]*scopedom.Target, error) {
	return r.byTenant[tenantID], r.err
}

func scopeEntry(t *testing.T, tenant shared.ID, typ scopedom.TargetType, pattern string) *scopedom.Target {
	t.Helper()
	e, err := scopedom.NewTarget(tenant, typ, pattern, "test", "tester")
	if err != nil {
		t.Fatalf("NewTarget(%s): %v", pattern, err)
	}
	e.Activate()
	return e
}

// largeGate is a gate whose scope entries and exclusions come from the real
// scope service, with a scan zone over the internal ranges (internal
// addresses are scanned only inside one).
func largeGate(targets map[shared.ID][]*scopedom.Target, excl map[shared.ID][]*scopedom.Exclusion) *Service {
	zone, err := scanzone.NewZone(shared.NewID(), "datacenter", "", false, []string{"10.0.0.0/8", "172.16.0.0/12"}, nil)
	if err != nil {
		panic(err)
	}
	return &Service{
		scopeExclusions: scope.NewService(&tenantTargetRepo{byTenant: targets}, &tenantExclusionRepo{byTenant: excl}, nil, logger.NewNop()),
		attributionGate: &stubGate{},
		zones:           &gateZones{zones: []*scanzone.Zone{zone}},
		logger:          logger.NewNop(),
	}
}

func largeInput(tenant shared.ID, targets ...string) DispatchTargetsInput {
	in := triggerInput(tenant, targets...)
	in.MaxRangeHostBits = validator.MaxCIDRHostBitsLimit
	return in
}

// A /8 the tenant's scope holds whole is 256 /16 chunks: never 16,777,216
// addresses or 65,536 /24 rows, and 256 one-target jobs (under the per-run
// job bound).
func TestLargeRange_SlashEightIs256Chunks(t *testing.T) {
	tenant := shared.NewID()
	svc := largeGate(map[shared.ID][]*scopedom.Target{tenant: {scopeEntry(t, tenant, scopedom.TargetTypeCIDR, "10.0.0.0/8")}}, nil)
	got, err := svc.ResolveDispatchTargets(context.Background(), largeInput(tenant, "10.0.0.0/8"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Refused) != 0 || len(got.Excluded) != 0 {
		t.Fatalf("refused = %+v, excluded = %v", got.Refused, got.Excluded)
	}
	if len(got.Allowed) != 256 {
		t.Fatalf("%d chunks, want 256", len(got.Allowed))
	}
	for i, p := range got.Allowed {
		if want := fmt.Sprintf("10.%d.0.0/16", i); p != want {
			t.Fatalf("chunk %d = %s, want %s", i, p, want)
		}
	}
	if len(got.Split) != 1 || got.Split[0].Removed != 0 || got.Split[0].OutOfScope != 0 {
		t.Fatalf("split = %+v", got.Split)
	}
	if jobs := len(chunkTargets(got.Allowed, 1)); jobs != 256 || jobs > maxZoneJobsPerRun {
		t.Fatalf("%d jobs", jobs)
	}
}

// 172.16.0.0/12 is 16 chunks; IPv6 /104 is 256 /112 chunks.
func TestLargeRange_ChunkCounts(t *testing.T) {
	tenant := shared.NewID()
	svc := largeGate(map[shared.ID][]*scopedom.Target{tenant: {
		scopeEntry(t, tenant, scopedom.TargetTypeCIDR, "172.16.0.0/12"),
		scopeEntry(t, tenant, scopedom.TargetTypeCIDR, "2001:db8::/104"),
	}}, nil)
	for target, want := range map[string]int{"172.16.0.0/12": 16, "2001:db8::/104": 256, "172.16.0.0/16": 256} {
		got, err := svc.ResolveDispatchTargets(context.Background(), largeInput(tenant, target))
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Allowed) != want {
			t.Fatalf("%s: %d chunks, want %d", target, len(got.Allowed), want)
		}
	}
}

// The out-of-scope parts of a large range and its excluded addresses are
// removed; what is left goes in chunks no wider than a /16.
func TestLargeRange_ScopeAndExclusionsSubtracted(t *testing.T) {
	tenant := shared.NewID()
	svc := largeGate(
		map[shared.ID][]*scopedom.Target{tenant: {
			scopeEntry(t, tenant, scopedom.TargetTypeCIDR, "10.1.0.0/16"),
			scopeEntry(t, tenant, scopedom.TargetTypeIPRange, "10.2.0.0-10.2.127.255"),
		}},
		map[shared.ID][]*scopedom.Exclusion{tenant: {approvedExclusion(t, tenant, scopedom.ExclusionTypeCIDR, "10.1.2.0/24")}},
	)
	got, err := svc.ResolveDispatchTargets(context.Background(), largeInput(tenant, "10.0.0.0/8"))
	if err != nil {
		t.Fatal(err)
	}
	set := allowedSet(t, got.Allowed)
	if set.Contains(netip.MustParseAddr("10.1.2.9")) {
		t.Fatal("an excluded address is dispatched")
	}
	if set.Contains(netip.MustParseAddr("10.3.0.1")) || set.Contains(netip.MustParseAddr("10.2.128.0")) {
		t.Fatal("an out-of-scope address is dispatched")
	}
	if n, _ := set.Size(); n != 1<<16+1<<15-256 {
		t.Fatalf("dispatched %d addresses", n)
	}
	for _, p := range got.Allowed {
		if pr, err := netip.ParsePrefix(p); err == nil && pr.Bits() < 16 {
			t.Fatalf("chunk %s is wider than a /16", p)
		}
	}
	if len(got.Split) != 1 || got.Split[0].OutOfScope != 1<<24-1<<16-1<<15 || got.Split[0].Removed != 1<<24-(1<<16+1<<15-256) {
		t.Fatalf("split = %+v", got.Split)
	}
}

// Another tenant's scope entries never let a large range through, and
// another tenant's exclusions never cut it.
func TestLargeRange_CrossTenantScope(t *testing.T) {
	mine, other := shared.NewID(), shared.NewID()
	svc := largeGate(
		map[shared.ID][]*scopedom.Target{other: {scopeEntry(t, other, scopedom.TargetTypeCIDR, "10.0.0.0/8")}},
		map[shared.ID][]*scopedom.Exclusion{other: {approvedExclusion(t, other, scopedom.ExclusionTypeCIDR, "10.9.0.0/16")}},
	)
	got, err := svc.ResolveDispatchTargets(context.Background(), largeInput(mine, "10.0.0.0/8"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Allowed) != 0 || len(got.Refused) != 1 || got.Refused[0].Code != scopedom.RefusalNoEntry {
		t.Fatalf("allowed = %v, refused = %+v: another tenant's entry authorized the range", got.Allowed, got.Refused)
	}
	got, err = svc.ResolveDispatchTargets(context.Background(), largeInput(other, "10.0.0.0/8"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Allowed) != 255 || allowedSet(t, got.Allowed).Contains(netip.MustParseAddr("10.9.0.1")) {
		t.Fatalf("the owner's own exclusion was not applied: %d chunks", len(got.Allowed))
	}
}

// Without the large-range allowance (a sweep scan, a caller's context
// targets) a range wider than a /16 is refused, as is anything wider than a
// /8 everywhere; a lookup error dispatches nothing.
func TestLargeRange_Bounds(t *testing.T) {
	tenant := shared.NewID()
	svc := largeGate(map[shared.ID][]*scopedom.Target{tenant: {scopeEntry(t, tenant, scopedom.TargetTypeCIDR, "10.0.0.0/8")}}, nil)
	ctx := context.Background()

	got, err := svc.ResolveDispatchTargets(ctx, triggerInput(tenant, "10.0.0.0/15", "10.4.0.0/16"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Refused) != 1 || got.Refused[0].Target != "10.0.0.0/15" || got.Refused[0].Reason != ReasonRangeTooLarge {
		t.Fatalf("refused = %+v", got.Refused)
	}
	if len(got.Allowed) != 256 {
		t.Fatalf("a /16 keeps its /24 pieces: %d", len(got.Allowed))
	}

	got, err = svc.ResolveDispatchTargets(ctx, largeInput(tenant, "10.0.0.0/7"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Refused) != 1 || got.Refused[0].Reason != ReasonRangeTooLarge {
		t.Fatalf("a /7 was not refused: %+v", got.Refused)
	}

	// A tenant limit below the platform's (/12) refuses a /11.
	in := largeInput(tenant, "10.0.0.0/11")
	in.MaxRangeHostBits = 20
	if got, err = svc.ResolveDispatchTargets(ctx, in); err != nil || len(got.Refused) != 1 {
		t.Fatalf("a /11 under a /12 limit: %+v, %v", got, err)
	}

	broken := largeGate(nil, nil)
	broken.scopeExclusions = scope.NewService(&tenantTargetRepo{err: errors.New("db down")}, &tenantExclusionRepo{}, nil, logger.NewNop())
	if _, err := broken.ResolveDispatchTargets(ctx, largeInput(tenant, "10.0.0.0/8")); err == nil {
		t.Fatal("a failed scope lookup dispatched a large range")
	}
	// No address filter at all: the range is refused, never sent whole.
	bare := largeGate(nil, nil)
	bare.scopeExclusions = noAddressFilter{}
	got, err = bare.ResolveDispatchTargets(ctx, largeInput(tenant, "10.0.0.0/8"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Allowed) != 0 {
		t.Fatalf("a large range went out whole: %v", got.Allowed)
	}
}

// noAddressFilter is an exclusion filter that answers no address sets.
type noAddressFilter struct{}

func (noAddressFilter) ExcludedTargets(context.Context, string, []scope.ExclusionCandidate) (map[shared.ID]bool, error) {
	return map[shared.ID]bool{}, nil
}

// The dispatch takes a range wider than a /16 only where it cuts it (or
// checks it without dispatching).
func TestRangeHostBits(t *testing.T) {
	for _, c := range []struct {
		in   DispatchTargetsInput
		want int
	}{
		{DispatchTargetsInput{}, 16},
		{DispatchTargetsInput{MaxRangeHostBits: 24}, 16},
		{DispatchTargetsInput{MaxRangeHostBits: 24, SplitRanges: true}, 24},
		{DispatchTargetsInput{MaxRangeHostBits: 24, DryRun: true}, 24},
		{DispatchTargetsInput{MaxRangeHostBits: 40, SplitRanges: true}, 24},
		{DispatchTargetsInput{MaxRangeHostBits: 8}, 8},
	} {
		if got := c.in.rangeHostBits(); got != c.want {
			t.Errorf("%+v: %d, want %d", c.in, got, c.want)
		}
	}
}

// A scan with a range wider than a /16 is scanned live hosts first: sweep
// and inventory are refused, an unnamed mode becomes liveness, and a
// workflow without host discovery is refused.
func TestApplyCIDRMode_LargeRange(t *testing.T) {
	plain, network := shared.NewID(), shared.NewID()
	s := &Service{stepRepo: workflowSteps{by: map[shared.ID][]*scanworkflow.Step{
		plain:   {{StepKey: "ports", Tool: "naabu"}},
		network: {{StepKey: "hosts", Capabilities: []string{"discover.hosts"}}, {StepKey: "ports", Capabilities: []string{"scan.ports"}}},
	}}}
	ctx := context.Background()
	for _, mode := range []scan.CIDRMode{scan.CIDRModeSweep, scan.CIDRModeInventory} {
		sc := workflowScan(t, network, "10.0.0.0/8")
		if err := sc.SetTargetOptions(scan.TargetOptions{CIDRMode: mode}); err != nil {
			t.Fatal(err)
		}
		var de *shared.DomainError
		if err := s.applyCIDRMode(ctx, sc, true); !errors.As(err, &de) || de.Code != CodeLargeRangeNeedsLiveness {
			t.Fatalf("%s: err = %v", mode, err)
		}
	}
	// A workflow that finds hosts first takes a /8, live hosts first.
	sc := workflowScan(t, network, "10.0.0.0/8")
	if err := s.applyCIDRMode(ctx, sc, false); err != nil || sc.TargetOptions.CIDRMode != scan.CIDRModeLiveness {
		t.Fatalf("mode = %q, err = %v", sc.TargetOptions.CIDRMode, err)
	}
	var de *shared.DomainError
	if err := s.applyCIDRMode(ctx, workflowScan(t, plain, "10.0.0.0/8"), false); !errors.As(err, &de) || de.Code != CodeLivenessNeedsHostDiscovery {
		t.Fatalf("a workflow without host discovery took a /8: %v", err)
	}
	// A /16 keeps the old rule: a workflow without host discovery sweeps.
	small := workflowScan(t, plain, "10.0.0.0/16")
	if err := s.applyCIDRMode(ctx, small, false); err != nil || small.TargetOptions.CIDRMode != "" {
		t.Fatalf("/16: mode = %q, err = %v", small.TargetOptions.CIDRMode, err)
	}
}

// A single-scanner scan never takes a range wider than a /16: its scanner
// (a port scanner here) would probe every address of the range, so live
// hosts first cannot hold. Explicit liveness, an unnamed mode and an edit
// are all refused; a /16 is still accepted.
func TestApplyCIDRMode_SingleScannerRefusesLargeRange(t *testing.T) {
	ctx := context.Background()
	s := &Service{}
	for _, explicit := range []bool{false, true} {
		for _, mode := range []scan.CIDRMode{"", scan.CIDRModeLiveness} {
			sc := rangeScan(t, "10.0.0.0/8")
			sc.ScannerName = "naabu"
			sc.TargetOptions.CIDRMode = mode
			var de *shared.DomainError
			if err := s.applyCIDRMode(ctx, sc, explicit); !errors.As(err, &de) || de.Code != CodeLivenessNeedsHostDiscovery {
				t.Fatalf("explicit=%v mode=%q: a single port scanner took a /8: %v", explicit, mode, err)
			}
		}
	}
	small := rangeScan(t, "10.0.0.0/16")
	small.ScannerName = "naabu"
	if err := s.applyCIDRMode(ctx, small, false); err != nil {
		t.Fatalf("/16: %v", err)
	}
}

// Measured: cutting a /8 around 100 scattered single-address exclusions is
// a bounded list of prefixes (no per-address work, no per-address rows).
func BenchmarkLargeRangeSplit(b *testing.B) {
	tenant := shared.NewID()
	excl := make([]*scopedom.Exclusion, 0, 100)
	for i := range 100 {
		e, err := scopedom.NewExclusion(tenant, scopedom.ExclusionTypeIPAddress, fmt.Sprintf("10.%d.0.7", i), "bench", nil, "tester")
		if err != nil {
			b.Fatal(err)
		}
		if err := e.Approve("approver"); err != nil {
			b.Fatal(err)
		}
		excl = append(excl, e)
	}
	entry, err := scopedom.NewTarget(tenant, scopedom.TargetTypeCIDR, "10.0.0.0/8", "bench", "tester")
	if err != nil {
		b.Fatal(err)
	}
	entry.Activate()
	svc := largeGate(map[shared.ID][]*scopedom.Target{tenant: {entry}}, map[shared.ID][]*scopedom.Exclusion{tenant: excl})
	b.ReportAllocs()
	var pieces int
	for b.Loop() {
		got, err := svc.ResolveDispatchTargets(context.Background(), largeInput(tenant, "10.0.0.0/8"))
		if err != nil {
			b.Fatal(err)
		}
		pieces = len(got.Allowed)
	}
	b.ReportMetric(float64(pieces), "chunks")
}

// A group member network asset 10.0.0.0/8 that also matches by its name
// (AlsoMatch) is never dispatched whole: at the default bound it is refused,
// with large ranges allowed it is cut to the tenant's scope in /16 chunks,
// and a name exclusion of the asset still removes every chunk.
func TestLargeRange_GroupMemberWithOtherNames(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	member := func(in DispatchTargetsInput) DispatchTargetsInput {
		in.Assets = map[string]DispatchAsset{"10.0.0.0/8": {IDs: []string{shared.NewID().String()}, AlsoMatch: []string{"core.example.com"}}}
		return in
	}
	scopeOf := map[shared.ID][]*scopedom.Target{tenant: {scopeEntry(t, tenant, scopedom.TargetTypeCIDR, "10.0.0.0/9")}}

	// The default bound: refused, never sent as typed.
	svc := largeGate(scopeOf, nil)
	got, err := svc.ResolveDispatchTargets(ctx, member(triggerInput(tenant, "10.0.0.0/8")))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Allowed) != 0 || len(got.Refused) != 1 || got.Refused[0].Reason != ReasonRangeTooLarge {
		t.Fatalf("default bound: allowed = %v, refused = %+v", got.Allowed, got.Refused)
	}

	// Large ranges allowed: cut to the in-scope /9, 128 /16 chunks.
	got, err = svc.ResolveDispatchTargets(ctx, member(largeInput(tenant, "10.0.0.0/8")))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Allowed) != 128 || len(got.Refused) != 0 {
		t.Fatalf("allowed %d chunks, refused = %+v", len(got.Allowed), got.Refused)
	}
	for _, a := range got.Allowed {
		if p, err := netip.ParsePrefix(a); err != nil || p.Bits() != 16 || !netip.MustParsePrefix("10.0.0.0/9").Contains(p.Addr()) {
			t.Fatalf("chunk %q is not a /16 inside the scope entry", a)
		}
	}

	// A name exclusion of the asset applies to every chunk (inherited).
	excl := map[shared.ID][]*scopedom.Exclusion{tenant: {approvedExclusion(t, tenant, scopedom.ExclusionTypeDomain, "core.example.com")}}
	got, err = largeGate(scopeOf, excl).ResolveDispatchTargets(ctx, member(largeInput(tenant, "10.0.0.0/8")))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Allowed) != 0 || len(got.Excluded) != 128 {
		t.Fatalf("name exclusion: allowed = %d, excluded = %d", len(got.Allowed), len(got.Excluded))
	}
}
