package easm

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// unclassifiedFixture is a gate fixture with an exact entry (so exact.org
// is one of the organization's registrable domains without a wildcard) and
// the unclassified mode answered per tenant.
func unclassifiedFixture(t *testing.T, mode string) (*gateFixture, *ActiveGate, *[]shared.ID) {
	t.Helper()
	f := newGateFixture(t)
	exact, err := scopedom.NewTarget(f.tenant, scopedom.TargetTypeDomain, "www.exact.org", "", "")
	if err != nil {
		t.Fatal(err)
	}
	f.targets = append(f.targets, exact)
	f.resolves = map[string][]string{}
	g := NewActiveGate(f, f, f, f)
	asked := &[]shared.ID{}
	g.SetUnclassified(func(_ context.Context, tenantID shared.ID) (string, error) {
		*asked = append(*asked, tenantID)
		if !tenantID.Equals(f.tenant) {
			return unclassifiedOff, nil
		}
		return mode, nil
	}, f)
	return f, g, asked
}

func withProps(t *testing.T, a *asset.Asset, props map[string]any) *asset.Asset {
	t.Helper()
	for k, v := range props {
		a.SetProperty(k, v)
	}
	return a
}

// SECURITY (RFC-054 §16): an unclassified asset gets active checks only
// while no guardrail holds it; every guardrail, rejection, wildcard-only
// name and the deny list keep it passive.
func TestActiveGate_UnclassifiedGuardrails(t *testing.T) {
	f, g, _ := unclassifiedFixture(t, unclassifiedLowImpact)
	ctx := context.Background()
	owned := map[string]any{"asn": float64(64500), "asn_org": "Example Org Networks"}
	cases := []struct {
		name  string
		setup func() *asset.Asset
		want  attribution.State // "" = allowed
	}{
		{"name under one of the organization's domains", func() *asset.Asset {
			return f.add(t, "mail.exact.org", asset.AssetTypeSubdomain)
		}, ""},
		{"discovered name under the organization's domains", func() *asset.Asset {
			a := f.add(t, "dev.exact.org", asset.AssetTypeSubdomain)
			f.record(a, attribution.StateDiscovered, false)
			return a
		}, ""},
		{"confirmed asset no entry covers", func() *asset.Asset {
			a := f.add(t, "shop.exact.org", asset.AssetTypeSubdomain)
			f.record(a, attribution.StateConfirmed, true)
			return a
		}, ""},
		{"a third party's name (foreign registrable domain)", func() *asset.Asset {
			return f.add(t, "cdn.thirdparty.net", asset.AssetTypeSubdomain)
		}, attribution.StateGuardrailed},
		{"address with a known non-provider network", func() *asset.Asset {
			return withProps(t, f.add(t, "203.0.113.10", asset.AssetTypeIPAddress), owned)
		}, ""},
		{"address nothing is known about", func() *asset.Asset {
			return f.add(t, "203.0.113.11", asset.AssetTypeIPAddress)
		}, attribution.StateGuardrailed},
		{"address in a cloud provider's network", func() *asset.Asset {
			return withProps(t, f.add(t, "203.0.113.12", asset.AssetTypeIPAddress),
				map[string]any{"asn": float64(16509), "asn_org": "AMAZON-02"})
		}, attribution.StateGuardrailed},
		{"address its own record calls CDN", func() *asset.Asset {
			return withProps(t, f.add(t, "203.0.113.13", asset.AssetTypeIPAddress),
				map[string]any{"cdn": "somecdn", "asn_org": "Example Org Networks"})
		}, attribution.StateGuardrailed},
		{"address in a published CDN edge range", func() *asset.Asset {
			return withProps(t, f.add(t, "104.16.1.1", asset.AssetTypeIPAddress), owned)
		}, attribution.StateGuardrailed},
		{"shared hosting: names of three registrable domains", func() *asset.Asset {
			a := withProps(t, f.add(t, "203.0.113.14", asset.AssetTypeIPAddress), owned)
			f.resolves["a.one.com"] = []string{"203.0.113.14"}
			f.resolves["b.two.com"] = []string{"203.0.113.14"}
			f.resolves["c.three.com"] = []string{"203.0.113.14"}
			return a
		}, attribution.StateGuardrailed},
		{"service on a guardrailed address", func() *asset.Asset {
			return f.add(t, "203.0.113.11:22", asset.AssetTypeService)
		}, attribution.StateGuardrailed},
		{"service on an allowed address", func() *asset.Asset {
			return f.add(t, "203.0.113.10:443", asset.AssetTypeService)
		}, ""},
		{"rejected stays refused", func() *asset.Asset {
			a := f.add(t, "old.exact.org", asset.AssetTypeSubdomain)
			f.record(a, attribution.StateRejected, true)
			return a
		}, attribution.StateRejected},
		{"sent back to review by a person stays refused", func() *asset.Asset {
			a := f.add(t, "held.exact.org", asset.AssetTypeSubdomain)
			f.record(a, attribution.StateNeedsReview, true)
			return a
		}, attribution.StateNeedsReview},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := tc.setup()
			got, err := g.ActiveCheckBlocked(ctx, f.tenant, []string{a.ID().String()})
			if err != nil {
				t.Fatal(err)
			}
			if got[a.ID().String()] != tc.want {
				t.Fatalf("state = %q, want %q", got[a.ID().String()], tc.want)
			}
		})
	}
}

// SECURITY: with the setting off (or Strict, which the policy answers as
// off, or an unreadable setting) unclassified assets stay passive, as
// before RFC-054 §16.
func TestActiveGate_UnclassifiedOff(t *testing.T) {
	for _, mode := range []string{unclassifiedOff, "", "bogus"} {
		f, g, _ := unclassifiedFixture(t, mode)
		a := f.add(t, "mail.exact.org", asset.AssetTypeSubdomain)
		got, err := g.ActiveCheckBlocked(context.Background(), f.tenant, []string{a.ID().String()})
		if err != nil || got[a.ID().String()] != attribution.StateUnattributed {
			t.Fatalf("mode %q: %v %v", mode, got, err)
		}
	}
	f := newGateFixture(t)
	g := NewActiveGate(f, f, f, f)
	g.SetUnclassified(func(context.Context, shared.ID) (string, error) {
		return unclassifiedFull, errors.New("settings unreadable")
	}, f)
	a := withProps(t, f.add(t, "203.0.113.10", asset.AssetTypeIPAddress), map[string]any{"asn": float64(64500), "asn_org": "Example"})
	got, err := g.ActiveCheckBlocked(context.Background(), f.tenant, []string{a.ID().String()})
	if err != nil || got[a.ID().String()] != attribution.StateUnattributed {
		t.Fatalf("policy error must read as off: %v %v", got, err)
	}
}

// SECURITY: a failed guardrail lookup holds every unclassified asset
// (fail closed), and the scope-covered ones are unaffected.
func TestActiveGate_UnclassifiedClassifierErrorFailsClosed(t *testing.T) {
	f, g, _ := unclassifiedFixture(t, unclassifiedFull)
	ip := withProps(t, f.add(t, "203.0.113.10", asset.AssetTypeIPAddress), map[string]any{"asn": float64(64500), "asn_org": "Example"})
	covered := f.add(t, "app.scoped.com", asset.AssetTypeSubdomain)
	f.resolveErr = errors.New("db down")
	got, err := g.ActiveCheckBlocked(context.Background(), f.tenant, []string{ip.ID().String(), covered.ID().String()})
	if err != nil {
		t.Fatal(err)
	}
	if got[ip.ID().String()] != attribution.StateGuardrailed {
		t.Fatalf("classifier error must guardrail: %v", got)
	}
	if _, no := got[covered.ID().String()]; no {
		t.Fatalf("a covered asset does not depend on the classifier: %v", got)
	}
}

// SECURITY: another tenant's assets are never admitted, and the policy is
// asked for the caller's tenant only; typed text that names no inventory
// asset still needs a scope entry.
func TestActiveGate_UnclassifiedTenantIsolation(t *testing.T) {
	f, g, asked := unclassifiedFixture(t, unclassifiedFull)
	ctx := context.Background()
	a := f.add(t, "mail.exact.org", asset.AssetTypeSubdomain)
	other := shared.NewID()
	got, err := g.ActiveCheckBlocked(ctx, other, []string{a.ID().String()})
	if err != nil || got[a.ID().String()] != attribution.StateUnattributed {
		t.Fatalf("another tenant's asset: %v %v", got, err)
	}
	for _, id := range *asked {
		if id.Equals(f.tenant) {
			t.Fatalf("the owner tenant's policy was read for another tenant's call")
		}
	}
	free, err := g.BlockedTargets(ctx, f.tenant, []string{"notinventory.exact.org", "mail.exact.org"})
	if err != nil {
		t.Fatal(err)
	}
	if free["notinventory.exact.org"] != attribution.StateUnattributed {
		t.Fatalf("typed text without an asset needs an entry: %v", free)
	}
	if _, no := free["mail.exact.org"]; no {
		t.Fatalf("typed text naming an allowed asset is decided as the asset: %v", free)
	}
}

func TestActiveGate_GuardrailOf(t *testing.T) {
	f, g, _ := unclassifiedFixture(t, unclassifiedLowImpact)
	ctx := context.Background()
	foreign := f.add(t, "x.thirdparty.net", asset.AssetTypeSubdomain)
	unknown := f.add(t, "203.0.113.11", asset.AssetTypeIPAddress)
	ok := f.add(t, "mail.exact.org", asset.AssetTypeSubdomain)
	covered := f.add(t, "app.scoped.com", asset.AssetTypeSubdomain)
	got, err := g.GuardrailOf(ctx, f.tenant, []shared.ID{foreign.ID(), unknown.ID(), ok.ID(), covered.ID()})
	if err != nil {
		t.Fatal(err)
	}
	if got[foreign.ID().String()] != GuardrailForeignDomain || got[unknown.ID().String()] != GuardrailNetworkUnknown || len(got) != 2 {
		t.Fatalf("reasons: %v", got)
	}
	if x, _ := g.GuardrailOf(ctx, shared.NewID(), []shared.ID{foreign.ID()}); len(x) != 0 {
		t.Fatalf("another tenant sees reasons: %v", x)
	}
}

func lowImpactShape(t *testing.T, tool string, cfg map[string]any) scopedom.JobShape {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return scopedom.JobShape{Tool: tool, Ports: portsOf(cfg), Settings: string(b)}
}

func portsOf(cfg map[string]any) string {
	p, _ := cfg["ports"].(string)
	return p
}

// SECURITY (RFC-054 §16.3): jobs on an unclassified asset stay inside the
// low-impact profile, per tool; full mode lifts the cap, and a higher tier
// is refused.
func TestActiveGate_LowImpactCapPerTool(t *testing.T) {
	f, g, _ := unclassifiedFixture(t, unclassifiedLowImpact)
	ctx := context.Background()
	f.add(t, "mail.exact.org", asset.AssetTypeSubdomain)
	f.resolves["mail.exact.org"] = []string{"198.51.100.9"} // in a scope range
	target := []string{"mail.exact.org"}
	cases := []struct {
		name string
		tier scopedom.Tier
		job  scopedom.JobShape
		want string
	}{
		{"naabu common ports at a low rate", scopedom.TierActive, lowImpactShape(t, "naabu", map[string]any{"ports": "80,443", "rate": 5}), ""},
		{"naabu without a rate", scopedom.TierActive, lowImpactShape(t, "naabu", map[string]any{"ports": "80,443"}), scopedom.RefusalLowImpact},
		{"naabu full range", scopedom.TierActive, lowImpactShape(t, "naabu", map[string]any{"ports": "1-65535", "rate": 5}), scopedom.RefusalLowImpact},
		{"naabu top ports", scopedom.TierActive, lowImpactShape(t, "naabu", map[string]any{"top_ports": 100, "rate": 5}), scopedom.RefusalLowImpact},
		{"nuclei info tech", scopedom.TierActive, lowImpactShape(t, "nuclei", map[string]any{"severity": []any{"info"}, "tags": "tech", "rate_limit": 5, "concurrency": 2}), ""},
		{"nuclei medium", scopedom.TierActive, lowImpactShape(t, "nuclei", map[string]any{"severity": "info,medium", "tags": "tech", "rate_limit": 5, "concurrency": 2}), scopedom.RefusalLowImpact},
		{"nuclei cve tag", scopedom.TierActive, lowImpactShape(t, "nuclei", map[string]any{"severity": "info", "tags": "cve", "rate_limit": 5, "concurrency": 2}), scopedom.RefusalLowImpact},
		{"nuclei without filters", scopedom.TierActive, scopedom.JobShape{Tool: "nuclei"}, scopedom.RefusalLowImpact},
		{"crawler", scopedom.TierActive, scopedom.JobShape{Tool: "katana"}, scopedom.RefusalLowImpact},
		{"httpx well-known path", scopedom.TierActive, lowImpactShape(t, "httpx", map[string]any{"path": []any{"/", "/.well-known/security.txt"}, "rate_limit": 5}), ""},
		{"httpx other path", scopedom.TierActive, lowImpactShape(t, "httpx", map[string]any{"path": "/admin", "rate_limit": 5}), scopedom.RefusalLowImpact},
		{"unreadable settings", scopedom.TierActive, scopedom.JobShape{Tool: "httpx", Settings: scopedom.SettingsUnreadable}, scopedom.RefusalLowImpact},
		{"custom templates", scopedom.TierActive, scopedom.JobShape{Tool: "nuclei", CustomTemplates: true}, scopedom.RefusalLowImpact},
		{"intrusive tier", scopedom.TierIntrusive, lowImpactShape(t, "nuclei", map[string]any{"severity": "info", "tags": "tech", "rate_limit": 5, "concurrency": 2}), scopedom.RefusalTierExceeds},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := g.ConstraintRefused(ctx, f.tenant, target, tc.tier, tc.job)
			if err != nil {
				t.Fatal(err)
			}
			if got["mail.exact.org"] != tc.want {
				t.Fatalf("got %v, want %q", got, tc.want)
			}
		})
	}
	// An enforcing sensor does not lift the template and rate caps.
	enforced := scopedom.JobShape{Tool: "katana", LimitsEnforced: true}
	if got, _ := g.ConstraintRefused(ctx, f.tenant, target, scopedom.TierActive, enforced); got["mail.exact.org"] != scopedom.RefusalLowImpact {
		t.Fatalf("enforcing sensor: %v", got)
	}
	// In-scope targets are not capped.
	f.add(t, "app.scoped.com", asset.AssetTypeSubdomain)
	f.resolves["app.scoped.com"] = []string{"198.51.100.7"}
	if got, _ := g.ConstraintRefused(ctx, f.tenant, []string{"app.scoped.com"}, scopedom.TierActive, scopedom.JobShape{Tool: "katana"}); len(got) != 0 {
		t.Fatalf("in-scope target capped: %v", got)
	}
	// Full mode lifts the low-impact cap.
	f2, g2, _ := unclassifiedFixture(t, unclassifiedFull)
	f2.add(t, "mail.exact.org", asset.AssetTypeSubdomain)
	if got, _ := g2.ConstraintRefused(ctx, f2.tenant, target, scopedom.TierActive, scopedom.JobShape{Tool: "katana"}); len(got) != 0 {
		t.Fatalf("full mode: %v", got)
	}
}

// SECURITY (RFC-054 §16.4): a port scan of a name reaches every port only
// when every address it resolves to may be port-scanned on its own; a held
// address (or none known) limits it to the web ports, an unclassified one
// in low_impact mode to the low-impact ports. Other tools are not narrowed.
func TestActiveGate_NamePortCaps(t *testing.T) {
	f, g, _ := unclassifiedFixture(t, unclassifiedLowImpact)
	ctx := context.Background()
	owned := map[string]any{"asn": float64(64500), "asn_org": "Example Org Networks"}
	f.add(t, "a.scoped.com", asset.AssetTypeSubdomain)
	f.resolves["a.scoped.com"] = []string{"198.51.100.7"} // in a scope range
	f.add(t, "b.scoped.com", asset.AssetTypeSubdomain)
	f.add(t, "203.0.113.11", asset.AssetTypeIPAddress) // nothing known: guardrailed
	f.resolves["b.scoped.com"] = []string{"203.0.113.11"}
	f.add(t, "c.scoped.com", asset.AssetTypeSubdomain)
	withProps(t, f.add(t, "203.0.113.10", asset.AssetTypeIPAddress), owned) // unclassified, allowed
	f.resolves["c.scoped.com"] = []string{"203.0.113.10"}
	f.add(t, "d.scoped.com", asset.AssetTypeSubdomain) // no addresses known
	f.add(t, "e.scoped.com", asset.AssetTypeSubdomain)
	f.resolves["e.scoped.com"] = []string{"104.16.1.1"} // CDN edge, no asset
	targets := []string{"a.scoped.com", "b.scoped.com", "c.scoped.com", "d.scoped.com", "e.scoped.com"}

	full := scopedom.JobShape{Tool: "naabu", Ports: "1-65535"}
	got, err := g.ConstraintRefused(ctx, f.tenant, targets, scopedom.TierActive, full)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"b.scoped.com": scopedom.RefusalWebPortsOnly, "c.scoped.com": scopedom.RefusalWebPortsOnly,
		"d.scoped.com": scopedom.RefusalWebPortsOnly, "e.scoped.com": scopedom.RefusalWebPortsOnly}
	if len(got) != len(want) {
		t.Fatalf("full range: %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("full range: %v", got)
		}
	}
	// Web ports pass for every name; port 22 only where the cap is the
	// low-impact list (c) or there is none (a).
	if got, _ := g.ConstraintRefused(ctx, f.tenant, targets, scopedom.TierActive, scopedom.JobShape{Tool: "naabu", Ports: "443,8443"}); len(got) != 0 {
		t.Fatalf("web ports: %v", got)
	}
	ssh, _ := g.ConstraintRefused(ctx, f.tenant, targets, scopedom.TierActive, scopedom.JobShape{Tool: "naabu", Ports: "22"})
	if _, no := ssh["a.scoped.com"]; no {
		t.Fatalf("covered address: %v", ssh)
	}
	if _, no := ssh["c.scoped.com"]; no {
		t.Fatalf("low-impact address allows 22: %v", ssh)
	}
	if ssh["b.scoped.com"] != scopedom.RefusalWebPortsOnly {
		t.Fatalf("guardrailed address: %v", ssh)
	}
	// Not a port scanner: not narrowed.
	if got, _ := g.ConstraintRefused(ctx, f.tenant, targets, scopedom.TierActive, scopedom.JobShape{Tool: "httpx"}); len(got) != 0 {
		t.Fatalf("httpx: %v", got)
	}
	// SECURITY: the caps follow the capability, not a tool name. Another
	// port scanner (a name the platform has never heard of) running
	// scan.ports or discover.hosts is narrowed exactly like the default
	// one; before, only the default tool's name was capped.
	for _, capID := range []string{"scan.ports@1", "discover.hosts@1"} {
		other := scopedom.JobShape{Tool: "portscan-x", Capability: capID, Ports: "1-65535"}
		got, err := g.ConstraintRefused(ctx, f.tenant, targets, scopedom.TierActive, other)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want) {
			t.Fatalf("%s by another tool: %v", capID, got)
		}
		for k, v := range want {
			if got[k] != v {
				t.Fatalf("%s by another tool: %v", capID, got)
			}
		}
	}
	// A job the default port scanner runs for another capability is judged
	// by that capability.
	if got, _ := g.ConstraintRefused(ctx, f.tenant, targets, scopedom.TierActive, scopedom.JobShape{Tool: "naabu", Capability: "probe.http@1"}); len(got) != 0 {
		t.Fatalf("probe.http by naabu: %v", got)
	}
	// A lookup failure refuses the whole check (nothing dispatched).
	f.resolveErr = errors.New("db down")
	if _, err := g.ConstraintRefused(ctx, f.tenant, targets, scopedom.TierActive, full); err == nil {
		t.Fatal("a failed address lookup must fail the check")
	}
}

// Passive steps may take an unclassified inventory asset active checks may
// reach; a guardrailed one and typed text stay out.
func TestActiveGate_UncoveredTargetsUnclassified(t *testing.T) {
	f, g, _ := unclassifiedFixture(t, unclassifiedLowImpact)
	f.add(t, "mail.exact.org", asset.AssetTypeSubdomain)
	f.add(t, "x.thirdparty.net", asset.AssetTypeSubdomain)
	got, err := g.UncoveredTargets(context.Background(), f.tenant, []string{"mail.exact.org", "x.thirdparty.net", "typed.exact.org"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "x.thirdparty.net" || got[1] != "typed.exact.org" {
		t.Fatalf("uncovered: %v", got)
	}
}

// A host named by a public DNS name or address follows the same modes as a
// domain of the same name: refused as unattributed while unclassified scans
// are off, and past the guardrails otherwise (the deny list and a third
// party's name still hold it).
func TestActiveGate_PublicHostFollowsTheModes(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		mode string
		name string
		want attribution.State
	}{
		{unclassifiedOff, "mail.exact.org", attribution.StateUnattributed},
		{unclassifiedLowImpact, "mail.exact.org", ""},
		{unclassifiedFull, "mail.exact.org", ""},
		{unclassifiedLowImpact, "cdn.thirdparty.net", attribution.StateGuardrailed},
	} {
		state := func(typ asset.AssetType) attribution.State {
			f, g, _ := unclassifiedFixture(t, tc.mode)
			a := f.add(t, tc.name, typ)
			got, err := g.ActiveCheckBlocked(ctx, f.tenant, []string{a.ID().String()})
			if err != nil {
				t.Fatal(err)
			}
			return got[a.ID().String()]
		}
		host, dom := state(asset.AssetTypeHost), state(asset.AssetTypeSubdomain)
		if host != tc.want || dom != tc.want {
			t.Errorf("mode %s, %s: host %q, domain %q, want %q for both", tc.mode, tc.name, host, dom, tc.want)
		}
	}
}

func TestPublicBareName(t *testing.T) {
	for name, want := range map[string]bool{
		"victim.example.org": true, "Victim.Example.ORG.": true, "203.0.113.9": true, "2001:4860::1": true,
		"10.0.0.1": false, "127.0.0.1": false, "localhost": false, "web01": false, "db.corp": false,
		"host.local": false, "a.b.internal": false, "user@example.org": false, "example.org/path": false,
		"example.org:443": false, "https://example.org": false, "arn:aws:s3:::x": false, "": false,
		"-bad.example.org": false, "a..example.org": false, "x.123": false, "wild*.example.org": false,
	} {
		if got := publicBareName(name); got != want {
			t.Errorf("publicBareName(%q) = %v, want %v", name, got, want)
		}
	}
}
