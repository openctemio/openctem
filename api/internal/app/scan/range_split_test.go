package scan

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scope/ipset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// tenantExclusionRepo holds active exclusions per tenant; any other method
// panics (embedded nil interface).
type tenantExclusionRepo struct {
	scopedom.ExclusionRepository
	byTenant map[shared.ID][]*scopedom.Exclusion
	err      error
}

func (r *tenantExclusionRepo) ListActive(_ context.Context, tenantID shared.ID) ([]*scopedom.Exclusion, error) {
	return r.byTenant[tenantID], r.err
}

func approvedExclusion(t *testing.T, tenant shared.ID, typ scopedom.ExclusionType, pattern string) *scopedom.Exclusion {
	t.Helper()
	e, err := scopedom.NewExclusion(tenant, typ, pattern, "test", nil, "tester")
	if err != nil {
		t.Fatalf("NewExclusion(%s): %v", pattern, err)
	}
	if err := e.Approve("approver"); err != nil {
		t.Fatal(err)
	}
	return e
}

// splitGate is a gate whose exclusions come from the real scope service.
func splitGate(repo scopedom.ExclusionRepository, gate *stubGate) *Service {
	if gate == nil {
		gate = &stubGate{}
	}
	return &Service{tools: testTools,
		scopeExclusions: scope.NewService(nil, repo, nil, logger.NewNop()),
		attributionGate: gate,
		logger:          logger.NewNop(),
	}
}

// triggerInput gates like the scan trigger: no validator (saved targets were
// validated at save), zone routing left to the trigger, ranges split.
func triggerInput(tenant shared.ID, targets ...string) DispatchTargetsInput {
	return DispatchTargetsInput{TenantID: tenant, Targets: targets, AllowNonNetworkTargets: true,
		SkipZoneRouting: true, SplitRanges: true}
}

// allowedSet is every address the allowed targets cover.
func allowedSet(t *testing.T, allowed []string) ipset.Set {
	t.Helper()
	rs := make([]ipset.Range, 0, len(allowed))
	for _, a := range allowed {
		r, ok := ipset.Parse(a)
		if !ok {
			t.Fatalf("allowed target %q is not an address set", a)
		}
		rs = append(rs, r)
	}
	return ipset.Of(rs...)
}

// An exclusion inside a range used to drop the whole range (nothing of it
// was scanned). The range is now cut around it: every other address is
// dispatched, the excluded one never is.
func TestSplitRanges_ExclusionInsideRangeSplitsIt(t *testing.T) {
	tenant := shared.NewID()
	svc := splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{
		tenant: {approvedExclusion(t, tenant, scopedom.ExclusionTypeIPAddress, "198.51.100.7")},
	}}, nil)

	got, err := svc.ResolveDispatchTargets(context.Background(), triggerInput(tenant, "198.51.100.0/24", "app.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Excluded) != 0 {
		t.Fatalf("excluded = %v; the range must be split, not dropped", got.Excluded)
	}
	want := []string{"198.51.100.0/30", "198.51.100.4/31", "198.51.100.6", "198.51.100.8/29", "198.51.100.16/28",
		"198.51.100.32/27", "198.51.100.64/26", "198.51.100.128/25", "app.example.com"}
	if !reflect.DeepEqual(got.Allowed, want) {
		t.Fatalf("allowed = %v, want %v", got.Allowed, want)
	}
	set := allowedSet(t, got.Allowed[:8])
	if set.Contains(netip.MustParseAddr("198.51.100.7")) {
		t.Fatal("the excluded address is dispatched")
	}
	if n, _ := set.Size(); n != 255 {
		t.Fatalf("dispatched %d addresses, want 255", n)
	}
	if len(got.Split) != 1 || got.Split[0].Target != "198.51.100.0/24" || got.Split[0].Removed != 1 || len(got.Split[0].Pieces) != 8 {
		t.Fatalf("split = %+v", got.Split)
	}
}

func TestSplitRanges_ExclusionCoveringWholeRangeExcludesIt(t *testing.T) {
	tenant := shared.NewID()
	svc := splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{
		tenant: {
			approvedExclusion(t, tenant, scopedom.ExclusionTypeCIDR, "198.51.100.0/25"),
			approvedExclusion(t, tenant, scopedom.ExclusionTypeIPRange, "198.51.100.128-198.51.100.255"),
		},
	}}, nil)
	got, err := svc.ResolveDispatchTargets(context.Background(), triggerInput(tenant, "198.51.100.0/24", "198.51.100.64/26"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Allowed) != 0 {
		t.Fatalf("allowed = %v, want nothing", got.Allowed)
	}
	if want := []string{"198.51.100.0/24", "198.51.100.64/26"}; !reflect.DeepEqual(got.Excluded, want) {
		t.Fatalf("excluded = %v, want %v", got.Excluded, want)
	}
}

// The built-in deny list is subtracted too: a range that runs into it keeps
// only its allowed part; a range wholly inside it is refused.
func TestSplitRanges_DenyList(t *testing.T) {
	tenant := shared.NewID()
	svc := splitGate(&tenantExclusionRepo{}, nil)
	got, err := svc.ResolveDispatchTargets(context.Background(),
		triggerInput(tenant, "126.255.255.250-127.0.0.5", "127.0.0.0/24", "169.254.169.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"126.255.255.250/31", "126.255.255.252/30"}; !reflect.DeepEqual(got.Allowed, want) {
		t.Fatalf("allowed = %v, want %v", got.Allowed, want)
	}
	for _, r := range got.Refused {
		if r.Code != scopedom.RefusalDenyList {
			t.Fatalf("refused %s with %s, want deny_list", r.Target, r.Code)
		}
	}
	if want := []string{"127.0.0.0/24", "169.254.169.0/24"}; !sameSet(refusedTargets(got), want) {
		t.Fatalf("refused = %v, want %v", refusedTargets(got), want)
	}
}

func TestSplitRanges_IPv6(t *testing.T) {
	tenant := shared.NewID()
	svc := splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{
		tenant: {approvedExclusion(t, tenant, scopedom.ExclusionTypeCIDR, "2001:db8::80/121")},
	}}, nil)
	got, err := svc.ResolveDispatchTargets(context.Background(), triggerInput(tenant, "2001:db8::/120"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"2001:db8::/121"}; !reflect.DeepEqual(got.Allowed, want) {
		t.Fatalf("allowed = %v, want %v", got.Allowed, want)
	}
}

// A path that skips the validator still never takes a range wider than
// 2^16 addresses: it is refused, never expanded or cut into pieces.
func TestSplitRanges_HugeRangesRefused(t *testing.T) {
	tenant := shared.NewID()
	svc := splitGate(&tenantExclusionRepo{}, nil)
	huge := []string{"0.0.0.0/0", "::/0", "198.50.0.0/15", "2001:db8::/64", "198.51.0.0-198.52.0.0"}
	got, err := svc.ResolveDispatchTargets(context.Background(), triggerInput(tenant, append(huge, "198.51.0.0/16")...))
	if err != nil {
		t.Fatal(err)
	}
	// The /16 itself is allowed, as 256 pieces of a /24.
	if len(got.Allowed) != 256 || !allowedSet(t, got.Allowed).Equal(allowedSet(t, []string{"198.51.0.0/16"})) {
		t.Fatalf("allowed %d targets, want the /16 as 256 pieces", len(got.Allowed))
	}
	if !sameSet(refusedTargets(got), huge) {
		t.Fatalf("refused = %v, want %v", refusedTargets(got), huge)
	}
	for _, r := range got.Refused {
		if r.Reason != ReasonRangeTooLarge {
			t.Fatalf("%s refused with %q", r.Target, r.Reason)
		}
	}
}

// Overlapping targets and overlapping exclusions: no allowed piece holds an
// excluded address, and every other address of the targets is dispatched.
func TestSplitRanges_OverlappingEntries(t *testing.T) {
	tenant := shared.NewID()
	svc := splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{
		tenant: {
			approvedExclusion(t, tenant, scopedom.ExclusionTypeIPRange, "203.0.113.100-203.0.113.150"),
			approvedExclusion(t, tenant, scopedom.ExclusionTypeCIDR, "203.0.113.128/26"),
			approvedExclusion(t, tenant, scopedom.ExclusionTypeIPAddress, "203.0.113.200"),
		},
	}}, nil)
	got, err := svc.ResolveDispatchTargets(context.Background(),
		triggerInput(tenant, "203.0.113.0/24", "203.0.113.128/25", "203.0.113.0/26"))
	if err != nil {
		t.Fatal(err)
	}
	set := allowedSet(t, got.Allowed)
	for i := 0; i < 256; i++ {
		a := netip.AddrFrom4([4]byte{203, 0, 113, byte(i)})
		excluded := (i >= 100 && i <= 191) || i == 200
		if set.Contains(a) == excluded {
			t.Fatalf("%s dispatched = %v, excluded = %v", a, set.Contains(a), excluded)
		}
	}
	// The pieces of the three targets overlap each other; the gate keeps
	// each piece string once.
	seen := map[string]bool{}
	for _, a := range got.Allowed {
		if seen[a] {
			t.Fatalf("piece %s dispatched twice", a)
		}
		seen[a] = true
	}
}

// Exclusions are per tenant: another tenant's exclusion never cuts this
// tenant's range, and this tenant's exclusion never reaches the other.
func TestSplitRanges_CrossTenant(t *testing.T) {
	tenantA, tenantB := shared.NewID(), shared.NewID()
	svc := splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{
		tenantB: {approvedExclusion(t, tenantB, scopedom.ExclusionTypeCIDR, "198.51.100.0/25")},
	}}, nil)
	got, err := svc.ResolveDispatchTargets(context.Background(), triggerInput(tenantA, "198.51.100.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"198.51.100.0/24"}; !reflect.DeepEqual(got.Allowed, want) || len(got.Split) != 0 {
		t.Fatalf("tenant A allowed = %v split = %v; tenant B's exclusion must not apply", got.Allowed, got.Split)
	}
	got, err = svc.ResolveDispatchTargets(context.Background(), triggerInput(tenantB, "198.51.100.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"198.51.100.128/25"}; !reflect.DeepEqual(got.Allowed, want) {
		t.Fatalf("tenant B allowed = %v, want %v", got.Allowed, want)
	}
}

// Splitting a range never bypasses ownership: pieces of an inventory range
// are checked by the range asset's id, like the range.
func TestSplitRanges_PiecesKeepTheRangeAssetGate(t *testing.T) {
	tenant := shared.NewID()
	assetID := shared.NewID().String()
	gate := &stubGate{blocked: map[string]attribution.State{assetID: attribution.StateNeedsReview}}
	svc := splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{
		tenant: {approvedExclusion(t, tenant, scopedom.ExclusionTypeIPAddress, "198.51.100.7")},
	}}, gate)
	in := triggerInput(tenant, "198.51.100.0/24")
	in.Assets = map[string]DispatchAsset{"198.51.100.0/24": {IDs: []string{assetID}}}
	got, err := svc.ResolveDispatchTargets(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Allowed) != 0 {
		t.Fatalf("allowed = %v; pieces of an unconfirmed range asset must be refused", got.Allowed)
	}
	if len(got.Refused) != 8 {
		t.Fatalf("refused = %v, want the 8 pieces", refusedTargets(got))
	}
}

// Exclusions so scattered that the rest needs more than MaxRangePieces
// prefixes refuse the dispatch instead of building a huge list.
func TestSplitRanges_TooFragmented(t *testing.T) {
	tenant := shared.NewID()
	ex := make([]*scopedom.Exclusion, 0, MaxRangePieces+1)
	for i := 0; i <= MaxRangePieces; i++ {
		ex = append(ex, approvedExclusion(t, tenant, scopedom.ExclusionTypeIPAddress,
			fmt.Sprintf("198.51.%d.%d", (2*i+1)/256, (2*i+1)%256)))
	}
	svc := splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{tenant: ex}}, nil)
	_, err := svc.ResolveDispatchTargets(context.Background(), triggerInput(tenant, "198.51.0.0/16"))
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != CodeRangeTooFragmented {
		t.Fatalf("err = %v, want %s", err, CodeRangeTooFragmented)
	}
}

func TestSplitRanges_LookupErrorFailsClosed(t *testing.T) {
	svc := splitGate(&tenantExclusionRepo{err: errors.New("db down")}, nil)
	if got, err := svc.ResolveDispatchTargets(context.Background(), triggerInput(shared.NewID(), "198.51.100.0/24")); err == nil {
		t.Fatalf("a failed exclusion lookup must refuse the dispatch, got %+v", got)
	}
}

// Without SplitRanges (callers that map Allowed back onto their own list),
// a range that overlaps an exclusion is still excluded whole.
func TestSplitRanges_OffKeepsWholeTargetRule(t *testing.T) {
	tenant := shared.NewID()
	svc := splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{
		tenant: {approvedExclusion(t, tenant, scopedom.ExclusionTypeIPAddress, "198.51.100.7")},
	}}, nil)
	in := triggerInput(tenant, "198.51.100.0/24")
	in.SplitRanges = false
	got, err := svc.ResolveDispatchTargets(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Allowed) != 0 || !reflect.DeepEqual(got.Excluded, []string{"198.51.100.0/24"}) {
		t.Fatalf("allowed = %v excluded = %v; want the range excluded whole", got.Allowed, got.Excluded)
	}
}

// The scan trigger cuts a range around an exclusion and says so in the run.
func TestResolveScanTargets_SplitsRangeAroundExclusion(t *testing.T) {
	sc := testScan("naabu", "198.51.100.0/24")
	svc := allowAllChecks(splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{
		sc.TenantID: {approvedExclusion(t, sc.TenantID, scopedom.ExclusionTypeCIDR, "198.51.100.0/26")},
	}}, nil))
	got, err := svc.resolveScanTargets(context.Background(), sc)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"198.51.100.64/26", "198.51.100.128/25"}; !reflect.DeepEqual(got.Targets, want) {
		t.Fatalf("targets = %v, want %v", got.Targets, want)
	}
	if got.Excluded != 0 {
		t.Fatalf("excluded = %d, want 0 (split, not excluded)", got.Excluded)
	}
	if w := strings.Join(got.Warnings, "\n"); !strings.Contains(w, "198.51.100.0/24: 64 excluded") {
		t.Fatalf("warnings = %q, want the split named", w)
	}
}

// A range wider than one piece is cut into pieces of at most /24 (IPv6
// /120), even with nothing excluded, so it can be chunked by address count;
// a range that fits one piece is kept as written. No warning: nothing was
// left out.
func TestSplitRanges_PiecesOfAtMostSlash24(t *testing.T) {
	tenant := shared.NewID()
	svc := splitGate(&tenantExclusionRepo{}, nil)
	got, err := svc.ResolveDispatchTargets(context.Background(),
		triggerInput(tenant, "198.51.100.0/22", "203.0.113.0/25", "2001:db8::/118", "192.0.2.10-192.0.2.20"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.0/24", "198.51.101.0/24", "198.51.102.0/24", "198.51.103.0/24", "203.0.113.0/25",
		"2001:db8::/120", "2001:db8::100/120", "2001:db8::200/120", "2001:db8::300/120",
		"192.0.2.10/31", "192.0.2.12/30", "192.0.2.16/30", "192.0.2.20"}
	if !reflect.DeepEqual(got.Allowed, want) {
		t.Fatalf("allowed = %v, want %v", got.Allowed, want)
	}
	if w := splitWarnings(got.Split); len(w) != 0 {
		t.Fatalf("warnings = %v, want none (nothing left out)", w)
	}
}
