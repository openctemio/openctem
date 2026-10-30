package scan

// An exclusion of a dedicated address reaches the names resolving to it on
// every dispatch path, whatever the caller put in DispatchAsset.AlsoMatch:
// coverage batches, workflow hops (names, ids and named ports) and the
// claim-time recheck hand the gate bare names or asset ids, so the gate
// itself reads the resolution relations (resolvingExclusionValues).

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type stubNameAddrs struct {
	byName map[string][]string
	err    error
	calls  int
	asked  []string
}

func (s *stubNameAddrs) AddressesOf(_ context.Context, _ shared.ID, names []string) (map[string][]string, error) {
	s.calls++
	s.asked = append(s.asked, names...)
	if s.err != nil {
		return nil, s.err
	}
	out := map[string][]string{}
	for _, n := range names {
		if a, ok := s.byName[n]; ok {
			out[n] = a
		}
	}
	return out, nil
}

// idResolver is an attribution gate that also names what an asset id probes.
type idResolver struct {
	*stubGate
	values map[shared.ID][]string
	calls  int
}

func (r *idResolver) ConstraintRefused(context.Context, shared.ID, []string, scopedom.Tier, scopedom.JobShape) (map[string]string, error) {
	return nil, nil
}

func (r *idResolver) AssetTargets(_ context.Context, _ shared.ID, ids []shared.ID) (map[shared.ID][]string, error) {
	r.calls++
	out := map[shared.ID][]string{}
	for _, id := range ids {
		if v, ok := r.values[id]; ok {
			out[id] = v
		}
	}
	return out, nil
}

func TestExclusionReachesNamesResolvingToIt(t *testing.T) {
	const (
		dedicated = "203.0.113.10"
		onDed     = "vpn.example.com"
		onEdge    = "shop.example.com"
		free      = "www.example.com"
	)
	tenant := shared.NewID()
	repo := &tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{tenant: {
		approvedExclusion(t, tenant, scopedom.ExclusionTypeIPAddress, dedicated),
		approvedExclusion(t, tenant, scopedom.ExclusionTypeIPAddress, edgeAddr),
	}}}
	assetID := shared.NewID()
	byID := "id-asset.example.com"
	svc := splitGate(repo, nil)
	addrs := &stubNameAddrs{byName: map[string][]string{
		onDed: {dedicated}, onEdge: {edgeAddr}, "named.example.com": {dedicated},
	}}
	svc.nameAddresses = addrs
	svc.actScope = &stubActScope{}
	res := &idResolver{stubGate: &stubGate{}, values: map[shared.ID][]string{assetID: {byID, dedicated}}}
	svc.attributionGate = res

	tier := scopedom.TierActive
	paths := map[string]func(ts []string) DispatchTargetsInput{
		"coverage batch": func(ts []string) DispatchTargetsInput {
			return DispatchTargetsInput{TenantID: tenant, Targets: ts, SystemPolicy: string(scan.ManagedByCoverage),
				Tier: &tier, SkipZoneRouting: true, Path: "auto_coverage"}
		},
		"workflow hop": func(ts []string) DispatchTargetsInput {
			return DispatchTargetsInput{TenantID: tenant, Targets: ts, SplitRanges: true, Path: "scan_run"}
		},
		"claim recheck": func(ts []string) DispatchTargetsInput {
			job := scopedom.JobShape{Tool: "nuclei"}
			return DispatchTargetsInput{TenantID: tenant, Targets: ts, Job: &job, Path: "claim_recheck",
				AllowNonNetworkTargets: true, SkipZoneRouting: true}
		},
	}
	targets := []string{
		onDed, onDed + ":8080", "https://" + onDed + "/x", // names on the dedicated address
		"named.example.com:443", // a named open port
		byID,                    // a hop candidate carrying only an asset id
		onEdge, onEdge + ":443", // behind an excluded shared front end: still dispatched
		free,
	}
	wantExcluded := []string{onDed, onDed + ":8080", "https://" + onDed + "/x", "named.example.com:443", byID}
	wantAllowed := []string{onEdge, onEdge + ":443", free}
	for name, build := range paths {
		in := build(targets)
		in.Assets = map[string]DispatchAsset{byID: {IDs: []string{assetID.String()}}}
		addrs.calls, addrs.asked, res.calls = 0, nil, 0
		got, err := svc.ResolveDispatchTargets(context.Background(), in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, w := range wantExcluded {
			if slices.Contains(got.Allowed, w) || !slices.Contains(got.Excluded, w) {
				t.Errorf("%s: %q must be excluded (allowed %v excluded %v)", name, w, got.Allowed, got.Excluded)
			}
		}
		for _, w := range wantAllowed {
			if !slices.Contains(got.Allowed, w) {
				t.Errorf("%s: %q must stay dispatched (allowed %v excluded %v)", name, w, got.Allowed, got.Excluded)
			}
		}
		if addrs.calls != 1 || res.calls != 1 {
			t.Errorf("%s: lookups must be batched, got %d address and %d asset lookups", name, addrs.calls, res.calls)
		}
	}
}

func TestExclusionResolvingLookupFailsClosed(t *testing.T) {
	tenant := shared.NewID()
	svc := splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{}}, nil)
	svc.nameAddresses = &stubNameAddrs{err: errors.New("db down")}
	got, err := svc.ResolveDispatchTargets(context.Background(),
		DispatchTargetsInput{TenantID: tenant, Targets: []string{"app.example.com"}, AllowNonNetworkTargets: true, SkipZoneRouting: true})
	if err == nil {
		t.Fatalf("a failed resolution lookup must stop the dispatch, got %+v", got)
	}
}
