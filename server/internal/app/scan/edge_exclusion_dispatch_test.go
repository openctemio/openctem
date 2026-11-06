package scan

// An edge address the organization added to out of scope is never
// dispatched, by any tool on any path (owner decision 2026-10-30, research/274:
// the platform labels CDN and edge addresses and never refuses them by
// itself; the tenant's scope exclusion is the only stop). Every path that
// sends traffic goes through ResolveDispatchTargets (POST /commands through
// GateCommandPayload); this pins each path's input shape against one real
// exclusion from the scope service.

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/edgeaddr"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const edgeAddr = "104.16.1.1" // a Cloudflare edge address (published range)

func TestEdgeAddressOutOfScopeNeverDispatched(t *testing.T) {
	if r := edgeaddr.Default().Address(edgeAddr, "", ""); r.Class != edgeaddr.Edge {
		t.Fatalf("fixture %s is not an edge address: %+v", edgeAddr, r)
	}
	tenant := shared.NewID()
	excl := approvedExclusion(t, tenant, scopedom.ExclusionTypeIPAddress, edgeAddr)
	excl.SetKind(scopedom.ExclusionKindDoNotScan)
	svc := splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{tenant: {excl}}}, nil)

	tier := scopedom.TierActive
	// The input each dispatch path builds (see the callers of
	// ResolveDispatchTargets), with the tools a scan sends.
	paths := map[string]func(targets []string) DispatchTargetsInput{
		"scan trigger": func(ts []string) DispatchTargetsInput { return triggerInput(tenant, ts...) },
		"scan run and workflow hops": func(ts []string) DispatchTargetsInput {
			return DispatchTargetsInput{TenantID: tenant, Targets: ts, SplitRanges: true, Path: "scan_run"}
		},
		"coverage run": func(ts []string) DispatchTargetsInput {
			return DispatchTargetsInput{TenantID: tenant, Targets: ts, SystemPolicy: string(scan.ManagedByCoverage),
				Tier: &tier, SkipZoneRouting: true, Path: "auto_coverage"}
		},
		"enrichment": func(ts []string) DispatchTargetsInput {
			return DispatchTargetsInput{TenantID: tenant, Targets: ts, SystemPolicy: string(scan.ManagedByEnrichment),
				SkipZoneRouting: true, Path: "auto_enrichment"}
		},
		"web verify": func(ts []string) DispatchTargetsInput {
			return DispatchTargetsInput{TenantID: tenant, Targets: ts, SystemPolicy: string(scan.ManagedByWebVerify),
				SkipZoneRouting: true, Path: "web_verify"}
		},
		"retest and validation": func(ts []string) DispatchTargetsInput {
			return DispatchTargetsInput{TenantID: tenant, Targets: ts, Placement: attribution.PlacementTenant}
		},
		"connector coverage": func(ts []string) DispatchTargetsInput {
			return DispatchTargetsInput{TenantID: tenant, Targets: ts, Placement: attribution.PlacementTenant}
		},
	}
	tools := []scopedom.JobShape{
		{Tool: "naabu", Capability: "scan.ports@1", TopPorts: true},
		{Tool: "httpx"},
		{Tool: "nuclei"},
	}
	// The address in every form a target takes.
	forms := []string{edgeAddr, edgeAddr + ":443", "https://" + edgeAddr + ":8443/login"}

	for name, build := range paths {
		for _, tool := range tools {
			// Claim-time re-check of the same job carries its shape.
			for _, recheck := range []bool{false, true} {
				in := build(forms)
				if recheck {
					job := tool
					in.Job = &job
					in.Path = "claim_recheck"
				} else {
					in.Tool = tool.Tool
				}
				got, err := svc.ResolveDispatchTargets(context.Background(), in)
				if err != nil {
					t.Fatalf("%s/%s (recheck %v): %v", name, tool.Tool, recheck, err)
				}
				for _, f := range forms {
					if slices.Contains(got.Allowed, f) {
						t.Errorf("%s/%s (recheck %v): %q dispatched", name, tool.Tool, recheck, f)
					}
					if !slices.Contains(got.Excluded, f) {
						t.Errorf("%s/%s (recheck %v): %q not reported excluded (excluded %v)", name, tool.Tool, recheck, f, got.Excluded)
					}
				}
			}
		}
	}
}

// A port scan of a range that holds the edge address is cut around it.
func TestEdgeAddressOutOfScopeCutFromRange(t *testing.T) {
	tenant := shared.NewID()
	svc := splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{
		tenant: {approvedExclusion(t, tenant, scopedom.ExclusionTypeIPAddress, edgeAddr)},
	}}, nil)
	in := triggerInput(tenant, "104.16.1.0/29")
	in.Tool, in.Capability = "naabu", "scan.ports@1"
	got, err := svc.ResolveDispatchTargets(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if allowedSet(t, got.Allowed).Contains(netip.MustParseAddr(edgeAddr)) {
		t.Fatalf("the excluded edge address is in the dispatched pieces %v", got.Allowed)
	}
	if n, _ := allowedSet(t, got.Allowed).Size(); n != 7 {
		t.Fatalf("dispatched %d addresses of the /29, want 7", n)
	}
}

// POST /commands (a hand-written scan command) refuses the excluded edge
// address too.
func TestEdgeAddressOutOfScopeCommandRefused(t *testing.T) {
	tenant := shared.NewID()
	svc := splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{
		tenant: {approvedExclusion(t, tenant, scopedom.ExclusionTypeIPAddress, edgeAddr)},
	}}, nil)
	for _, scanner := range []string{"naabu", "httpx", "nuclei"} {
		payload, _ := json.Marshal(map[string]any{"scanner": scanner, "target": edgeAddr, "targets": []string{edgeAddr}})
		_, err := svc.GateCommandPayload(context.Background(), tenant, nil, payload)
		requireRefused(t, err, "")
	}
}

// Without the exclusion the edge address is only labeled: the platform does
// not refuse it by itself.
func TestEdgeAddressNotRefusedWithoutExclusion(t *testing.T) {
	tenant := shared.NewID()
	svc := splitGate(&tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{}}, nil)
	got, err := svc.ResolveDispatchTargets(context.Background(), triggerInput(tenant, edgeAddr))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Allowed, []string{edgeAddr}) {
		t.Fatalf("allowed = %v excluded = %v refused = %v; the edge address must not be refused without an exclusion",
			got.Allowed, got.Excluded, got.Refused)
	}
}

// An exclusion of a shared front end address stays on the address (owner
// decision 2026-10-30): a name the organization serves through that CDN
// still dispatches on every path, for every tool, while the address itself
// never does. An exclusion of a dedicated address still excludes the names
// that resolve to it, and so does one of an address only a network holder's
// name calls an edge (not proven shared: fail closed).
func TestEdgeExclusionDoesNotReachNamesBehindIt(t *testing.T) {
	const (
		dedicatedAddr = "203.0.113.10"
		heldAddr      = "198.51.100.20" // an edge only by its network holder's name
		behindEdge    = "shop.example.com"
		onDedicated   = "vpn.example.com"
		onHeld        = "media.example.com"
	)
	if _, shared := edgeaddr.Default().SharedFrontEnd(edgeAddr); !shared {
		t.Fatalf("fixture %s is not a shared front end", edgeAddr)
	}
	if r := edgeaddr.Default().Address(heldAddr, "", "Akamai International B.V."); r.Class != edgeaddr.Edge || r.Basis != edgeaddr.BasisNetwork {
		t.Fatalf("fixture %s is not an edge by its network holder: %+v", heldAddr, r)
	}
	if _, shared := edgeaddr.Default().SharedFrontEnd(heldAddr); shared {
		t.Fatalf("an address known only by its network holder must not count as shared")
	}
	tenant := shared.NewID()
	repo := &tenantExclusionRepo{byTenant: map[shared.ID][]*scopedom.Exclusion{tenant: {
		approvedExclusion(t, tenant, scopedom.ExclusionTypeIPAddress, edgeAddr),
		approvedExclusion(t, tenant, scopedom.ExclusionTypeIPAddress, dedicatedAddr),
		approvedExclusion(t, tenant, scopedom.ExclusionTypeCIDR, "198.51.100.16/28"),
	}}}
	svc := splitGate(repo, nil)
	svc.actScope = &stubActScope{} // the platform policies (coverage, enrichment, web verify) ask for it
	// The values each path matches a name by (scope.AssetExclusionValues,
	// as the trigger, the group members, the dry run and the triage read them).
	resolved := map[string][]string{
		behindEdge:  {edgeAddr, "104.16.2.2"},
		onDedicated: {dedicatedAddr},
		onHeld:      {heldAddr},
	}
	assets := map[string]DispatchAsset{}
	for name, ips := range resolved {
		vals := scope.AssetExclusionValues("subdomain", name, map[string]any{"ip_addresses": ips})
		assets[name] = DispatchAsset{AlsoMatch: vals} // typed: names only, as a URL on the asset
	}
	tier := scopedom.TierActive
	paths := map[string]func(targets []string) DispatchTargetsInput{
		"scan trigger": func(ts []string) DispatchTargetsInput { return triggerInput(tenant, ts...) },
		"scan run and workflow hops": func(ts []string) DispatchTargetsInput {
			return DispatchTargetsInput{TenantID: tenant, Targets: ts, SplitRanges: true, Path: "scan_run"}
		},
		"coverage run": func(ts []string) DispatchTargetsInput {
			return DispatchTargetsInput{TenantID: tenant, Targets: ts, SystemPolicy: string(scan.ManagedByCoverage),
				Tier: &tier, SkipZoneRouting: true, Path: "auto_coverage"}
		},
		"enrichment": func(ts []string) DispatchTargetsInput {
			return DispatchTargetsInput{TenantID: tenant, Targets: ts, SystemPolicy: string(scan.ManagedByEnrichment),
				SkipZoneRouting: true, Path: "auto_enrichment"}
		},
		"web verify": func(ts []string) DispatchTargetsInput {
			return DispatchTargetsInput{TenantID: tenant, Targets: ts, SystemPolicy: string(scan.ManagedByWebVerify),
				SkipZoneRouting: true, Path: "web_verify"}
		},
		"retest and validation": func(ts []string) DispatchTargetsInput {
			return DispatchTargetsInput{TenantID: tenant, Targets: ts, Placement: attribution.PlacementTenant}
		},
	}
	targets := []string{
		behindEdge, "https://" + behindEdge + "/login", behindEdge + ":443",
		onDedicated, onHeld,
		edgeAddr, edgeAddr + ":443", "https://" + edgeAddr + "/",
	}
	wantAllowed := []string{behindEdge, "https://" + behindEdge + "/login", behindEdge + ":443"}
	wantExcluded := []string{onDedicated, onHeld, edgeAddr, edgeAddr + ":443", "https://" + edgeAddr + "/"}
	for name, build := range paths {
		for _, tool := range []string{"naabu", "httpx", "nuclei"} {
			in := build(targets)
			in.Tool = tool
			in.Assets = map[string]DispatchAsset{}
			for _, tg := range targets {
				for n, a := range assets {
					if strings.Contains(tg, n) {
						in.Assets[tg] = a
					}
				}
			}
			got, err := svc.ResolveDispatchTargets(context.Background(), in)
			if err != nil {
				t.Fatalf("%s/%s: %v", name, tool, err)
			}
			for _, w := range wantAllowed {
				if !slices.Contains(got.Allowed, w) {
					t.Errorf("%s/%s: %q behind the excluded edge address not dispatched (excluded %v)", name, tool, w, got.Excluded)
				}
			}
			for _, w := range wantExcluded {
				if slices.Contains(got.Allowed, w) || !slices.Contains(got.Excluded, w) {
					t.Errorf("%s/%s: %q must be excluded (allowed %v excluded %v)", name, tool, w, got.Allowed, got.Excluded)
				}
			}
		}
	}
}
