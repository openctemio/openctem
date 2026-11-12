package scan

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A name with no DNS answer is a target of a job that only looks names up
// (resolve.dns / dnsx, passive enumeration): finding out whether it resolves
// is the work. The same gate input refuses it for a tool that probes the
// target (nuclei, naabu), and for a caller that names no tool. One rule,
// at dispatch (Tool/Capability) and at claim (Job).
func TestDispatchGate_UnresolvedNameForLookupOnlyJobs(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	svc := zonedCoverageService(t, tenant)
	tier := scopedom.TierPassive
	active := scopedom.TierActive
	targets := []string{"gone.example.com", "www.example.com", "intra.example.com"}

	cases := []struct {
		name         string
		in           DispatchTargetsInput
		wantGone     bool // gone.example.com allowed
		wantGoneCode string
	}{
		{"claim dnsx", DispatchTargetsInput{PassiveOnly: true, Tier: &tier, Job: &scopedom.JobShape{Tool: "dnsx"}}, true, ""},
		{"claim resolve.dns capability", DispatchTargetsInput{PassiveOnly: true, Tier: &tier, Job: &scopedom.JobShape{Tool: "dnsx", Capability: "resolve.dns@1"}}, true, ""},
		{"claim subfinder", DispatchTargetsInput{PassiveOnly: true, Tier: &tier, Job: &scopedom.JobShape{Tool: "subfinder"}}, true, ""},
		{"dispatch coverage resolve.dns", DispatchTargetsInput{PassiveOnly: true, Tier: &tier, Tool: "dnsx", Capability: "resolve.dns"}, true, ""},
		{"dispatch hop stage", DispatchTargetsInput{PassiveOnly: true, Tier: &tier, Capability: "resolve.dns"}, true, ""},
		{"claim nuclei", DispatchTargetsInput{PassiveOnly: true, Tier: &tier, Job: &scopedom.JobShape{Tool: "nuclei"}}, false, scopedom.RefusalUnresolved},
		{"claim naabu", DispatchTargetsInput{PassiveOnly: true, Tier: &tier, Job: &scopedom.JobShape{Tool: "naabu", Capability: "scan.ports@1"}}, false, scopedom.RefusalUnresolved},
		{"dnsx tool claiming a port scan", DispatchTargetsInput{PassiveOnly: true, Tier: &tier, Job: &scopedom.JobShape{Tool: "dnsx", Capability: "scan.ports"}}, false, scopedom.RefusalUnresolved},
		{"unknown tool", DispatchTargetsInput{PassiveOnly: true, Tier: &tier, Job: &scopedom.JobShape{Tool: "my-scanner"}}, false, scopedom.RefusalUnresolved},
		{"dispatch nuclei", DispatchTargetsInput{Tier: &active, Tool: "nuclei"}, false, scopedom.RefusalUnresolved},
		{"no tool named", DispatchTargetsInput{PassiveOnly: true, Tier: &tier}, false, scopedom.RefusalUnresolved},
		// Job wins over Tool: a claim of a nuclei job never borrows a lookup tool.
		{"job wins over tool", DispatchTargetsInput{PassiveOnly: true, Tier: &tier, Tool: "dnsx", Job: &scopedom.JobShape{Tool: "nuclei"}}, false, scopedom.RefusalUnresolved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			in.TenantID, in.Targets = tenant, targets
			got, err := svc.ResolveDispatchTargets(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			codes := refusalCodes(got)
			allowed := map[string]bool{}
			for _, a := range got.Allowed {
				allowed[a] = true
			}
			if allowed["gone.example.com"] != tc.wantGone || codes["gone.example.com"] != tc.wantGoneCode {
				t.Fatalf("gone.example.com allowed=%v code=%q; want %v %q", allowed["gone.example.com"], codes["gone.example.com"], tc.wantGone, tc.wantGoneCode)
			}
			// Everything else is unchanged: a public name runs, a name
			// resolving to a private address no zone holds is still refused.
			if !allowed["www.example.com"] {
				t.Fatalf("public name refused: %v", got.Refused)
			}
			if codes["intra.example.com"] != scopedom.RefusalZoneNone {
				t.Fatalf("private name refused %q, want zone_none (lookup-only never skips the other rules)", codes["intra.example.com"])
			}
		})
	}
}

// A lookup-only job still gets every scope check: an excluded name stays
// excluded even when it does not resolve.
func TestDispatchGate_LookupOnlyKeepsScopeChecks(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	svc := zonedCoverageService(t, tenant)
	svc.scopeExclusions = &stubExclusions{values: map[string]bool{"gone.example.com": true}}
	tier := scopedom.TierPassive
	got, err := svc.ResolveDispatchTargets(ctx, DispatchTargetsInput{TenantID: tenant, Targets: []string{"gone.example.com"},
		PassiveOnly: true, Tier: &tier, Job: &scopedom.JobShape{Tool: "dnsx"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Allowed) != 0 || len(got.Excluded) != 1 {
		t.Fatalf("excluded unresolved name: allowed %v excluded %v refused %v", got.Allowed, got.Excluded, got.Refused)
	}
}

// The trigger's own zone routing of a single-scanner scan follows the same
// rule: a dnsx scan keeps a name that does not resolve, a nuclei scan does
// not.
func TestRouteForScan_LookupOnlyKeepsUnresolvedNames(t *testing.T) {
	ctx, tenant := context.Background(), shared.NewID()
	svc := zonedCoverageService(t, tenant)
	zones, err := svc.loadZones(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	for tool, wantUncovered := range map[string]int{"dnsx": 0, "nuclei": 1} {
		sc := &scan.Scan{TenantID: tenant, ScannerName: tool}
		plan, err := svc.routeForScan(ctx, sc, zones, []string{"gone.example.com", "www.example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.Uncovered) != wantUncovered || len(plan.Unzoned)+len(plan.Uncovered) != 2 {
			t.Fatalf("%s: uncovered %v unzoned %v", tool, plan.Uncovered, plan.Unzoned)
		}
	}
}

// A run the coverage trigger did not route over the zones (a passive batch
// of public names) records it, so the claim does not route it either: the
// claim never asks more than the dispatch checked.
func TestScanDispatchGate_RecordsSkippedZoneRouting(t *testing.T) {
	sc := &scan.Scan{ScannerName: "dnsx", ManagedBy: scan.ManagedByCoverage}
	run := &scanrun.Run{Context: map[string]any{}}
	if g := scanDispatchGate(context.Background(), sc, run); g.NoZoneRouting {
		t.Fatal("a routed run recorded no zone routing")
	}
	if g := scanDispatchGate(withoutZoneRouting(context.Background()), sc, run); !g.NoZoneRouting {
		t.Fatal("a run dispatched without zone routing is routed at the claim")
	}
}
