package scanrun

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// tenantNameAddrs is the resolves_to relation of one tenant: a lookup for
// another tenant finds nothing.
type tenantNameAddrs struct {
	tenant shared.ID
	addrs  map[string][]string
	asked  [][]string
	err    error
}

func (r *tenantNameAddrs) AddressesOf(_ context.Context, tenantID shared.ID, names []string) (map[string][]string, error) {
	r.asked = append(r.asked, names)
	if r.err != nil {
		return nil, r.err
	}
	out := map[string][]string{}
	if tenantID != r.tenant {
		return out, nil
	}
	for _, n := range names {
		if a, ok := r.addrs[n]; ok {
			out[n] = a
		}
	}
	return out, nil
}

// portScanFixture: naabu scanned the name www.acme.com (and the address
// 198.51.100.9); its report put the open ports on the addresses.
func portScanFixture(t *testing.T, addrs *tenantNameAddrs) *chainFixture {
	t.Helper()
	f := newChainFixture(t)
	if addrs.tenant.IsZero() {
		addrs.tenant = f.run.TenantID
	}
	f.s.nameAddresses = addrs
	f.seed("ports", "www.acme.com", 0, nil)
	f.seed("ports", "198.51.100.9", 0, nil)
	f.settle("subs", scanrun.StepRunStatusCompleted)
	f.settle("dns", scanrun.StepRunStatusCompleted)
	f.settle("ports", scanrun.StepRunStatusCompleted)
	f.run.Context["targets"] = []string{}
	f.output("ports", "203.0.113.5:8443:tcp", "service", "open_port", "")
	f.output("ports", "203.0.113.6:443:tcp", "service", "open_port", "")
	f.output("ports", "198.51.100.9:22:tcp", "service", "open_port", "")
	return f
}

// A virtual host or CDN routes by name: the HTTP probe after a port scan of
// a name gets "<name>:<port>" for each open port on an address the name
// resolves to, besides the bare "<address>:<port>". A name the port scan
// did not scan is never added, even if it resolves to the same address.
func TestHopRouter_NamedOpenPortsReachTheProbe(t *testing.T) {
	addrs := &tenantNameAddrs{addrs: map[string][]string{
		"www.acme.com":   {"203.0.113.5", "203.0.113.6"},
		"other.acme.com": {"203.0.113.5"},
	}}
	f := portScanFixture(t, addrs)
	f.schedule(t)
	got := f.commandTargets(t, 0)
	for _, want := range []string{"www.acme.com:8443", "www.acme.com:443", "203.0.113.5:8443", "203.0.113.6:443", "198.51.100.9:22"} {
		if !contains(got, want) {
			t.Errorf("httpx targets %v lack %s", got, want)
		}
	}
	for _, no := range []string{"other.acme.com:8443", "www.acme.com:22", "198.51.100.9:8443"} {
		if contains(got, no) {
			t.Errorf("httpx targets %v hold %s", got, no)
		}
	}
	if len(addrs.asked) != 1 || len(addrs.asked[0]) != 1 || addrs.asked[0][0] != "www.acme.com" {
		t.Errorf("looked up %v, want only the scanned name", addrs.asked)
	}
	// The named port is recorded without an asset and with its parent's hop.
	for _, r := range f.hops.targets {
		if r.StageKey == "http" && r.TargetKey == "www.acme.com:8443" {
			if r.AssetID != nil || r.Hop != 0 || r.Relation != "same_host" {
				t.Errorf("row = %+v", r)
			}
		}
	}
}

// Every named port goes through the target gate: an exclusion in host:port
// form and a rejected name refuse it; the address form is unaffected.
func TestHopRouter_NamedOpenPortsAreGated(t *testing.T) {
	f := portScanFixture(t, &tenantNameAddrs{addrs: map[string][]string{"www.acme.com": {"203.0.113.5", "203.0.113.6"}}})
	f.excl["www.acme.com:8443"] = true
	f.attr.byName["www.acme.com:443"] = attribution.StateRejected
	f.schedule(t)
	got := f.commandTargets(t, 0)
	if contains(got, "www.acme.com:8443") || contains(got, "www.acme.com:443") {
		t.Fatalf("gated named ports dispatched: %v", got)
	}
	if !contains(got, "203.0.113.5:8443") {
		t.Fatalf("address port lost: %v", got)
	}
	p := f.hops.plan(t, f.run.ID, "http")
	if p.Skipped[scanrun.ReasonExcluded] != 1 || p.Skipped[scanrun.ReasonUnconfirmed] != 1 {
		t.Fatalf("skipped = %v", p.Skipped)
	}
}

// The relation is read for the run's tenant only: another tenant's
// resolves_to rows never add a name; a failed read keeps the address ports.
func TestHopRouter_NamedOpenPortsTenantScopedAndBestEffort(t *testing.T) {
	other := &tenantNameAddrs{tenant: shared.NewID(), addrs: map[string][]string{"www.acme.com": {"203.0.113.5"}}}
	f := portScanFixture(t, other)
	f.schedule(t)
	if got := f.commandTargets(t, 0); contains(got, "www.acme.com:8443") || !contains(got, "203.0.113.5:8443") {
		t.Fatalf("cross-tenant relation used: %v", got)
	}

	g := portScanFixture(t, &tenantNameAddrs{err: errors.New("db down")})
	g.schedule(t)
	if got := g.commandTargets(t, 0); !contains(got, "203.0.113.5:8443") || contains(got, "www.acme.com:8443") {
		t.Fatalf("failed lookup: %v", got)
	}
}
