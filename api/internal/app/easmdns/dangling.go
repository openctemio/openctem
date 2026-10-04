package easmdns

import (
	"context"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/pkg/dnsprobe"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
)

// Querier asks one DNS question. Satisfied by *dnsprobe.Client.
type Querier interface {
	Query(ctx context.Context, name string, t dnsprobe.Type) (dnsprobe.Answer, error)
}

// Outcome of one name's dangling check, stored in easm_dns_check_state.
const (
	OutcomeOK            = "ok"
	OutcomeDanglingCNAME = "dangling_cname"
	OutcomeDanglingNS    = "dangling_ns"
	OutcomeUnknown       = "unknown" // the resolver failed (SERVFAIL, timeout): nothing concluded
)

// Dangling is what the check found for one name. Zero value: nothing wrong.
type Dangling struct {
	Outcome string
	// Target is the CNAME target that does not exist (dangling_cname), or the
	// missing name servers joined by "," (dangling_ns).
	Target  string
	Missing []string // dangling_ns: the name servers that do not exist
	Total   int      // dangling_ns: all name servers of the delegation
	// Provider is the hosting service the target belongs to, if the
	// fingerprint list knows it.
	Provider *Provider
	// Unregistered: the registrable domain of the target does not exist at
	// all, so anyone can register it and answer for the tenant's name.
	Unregistered bool
	Severity     exposuredom.Severity
	Reason       string
}

// checkDangling resolves name and its delegation, DNS only. It never contacts
// the target over HTTP: confirming a takeover is a sensor check (T1).
//
// Severity:
//   - CNAME (or NS) target whose registrable domain is unregistered: high —
//     registering that domain takes the name over;
//   - CNAME to a provider the can-i-take-over-xyz list marks vulnerable, with
//     the target NXDOMAIN: medium until a sensor confirms (RFC-036 P1);
//   - all name servers of a delegation missing: high when unregistered,
//     otherwise medium; some missing: low;
//   - any other CNAME to a missing target: low (a broken record, not a known
//     takeover path).
func checkDangling(ctx context.Context, q Querier, name string) (Dangling, error) {
	a, err := q.Query(ctx, name, dnsprobe.TypeA)
	if err != nil {
		return Dangling{Outcome: OutcomeUnknown}, err
	}
	target := lastCNAME(a)
	switch {
	case a.RCode == dnsprobe.RCodeNXDomain && target != "":
		return danglingCNAME(ctx, q, target), nil
	case a.RCode != dnsprobe.RCodeSuccess && a.RCode != dnsprobe.RCodeNXDomain:
		return Dangling{Outcome: OutcomeUnknown, Reason: "resolver answered " + a.RCode.String()}, nil
	case target != "":
		// A CNAME that resolves; no NS can live at the same name.
		return Dangling{Outcome: OutcomeOK}, nil
	}
	return danglingNS(ctx, q, name)
}

// lastCNAME returns the end of the CNAME chain in an answer.
func lastCNAME(a dnsprobe.Answer) string {
	last := ""
	for _, r := range a.Records {
		if r.Type == dnsprobe.TypeCNAME {
			last = r.Value
		}
	}
	return last
}

func danglingCNAME(ctx context.Context, q Querier, target string) Dangling {
	d := Dangling{Outcome: OutcomeDanglingCNAME, Target: target, Severity: exposuredom.SeverityLow,
		Reason: "the CNAME target does not exist"}
	if p, ok := providerFor(target); ok {
		d.Provider = &p
		if p.Takeoverable() {
			d.Severity = exposuredom.SeverityMedium
			d.Reason = "the CNAME points at " + p.Service + ", where an unclaimed name can be registered by anyone"
		} else {
			d.Reason = "the CNAME points at " + p.Service + " and the target does not exist"
		}
	}
	if unregistered(ctx, q, target) {
		d.Unregistered = true
		d.Severity = exposuredom.SeverityHigh
		d.Reason = "the CNAME target's domain is not registered: whoever registers it controls this name"
	}
	return d
}

func danglingNS(ctx context.Context, q Querier, name string) (Dangling, error) {
	ns, err := q.Query(ctx, name, dnsprobe.TypeNS)
	if err != nil {
		return Dangling{Outcome: OutcomeUnknown}, err
	}
	var servers []string
	for _, r := range ns.Records {
		if r.Type == dnsprobe.TypeNS && r.Name == name {
			servers = append(servers, r.Value)
		}
	}
	if len(servers) == 0 {
		return Dangling{Outcome: OutcomeOK}, nil
	}
	sort.Strings(servers)
	var missing []string
	for _, s := range servers {
		a, err := q.Query(ctx, s, dnsprobe.TypeA)
		if err != nil {
			return Dangling{Outcome: OutcomeUnknown}, err
		}
		if a.RCode == dnsprobe.RCodeNXDomain {
			missing = append(missing, s)
		}
	}
	if len(missing) == 0 {
		return Dangling{Outcome: OutcomeOK}, nil
	}
	d := Dangling{Outcome: OutcomeDanglingNS, Missing: missing, Total: len(servers),
		Target: strings.Join(missing, ","), Severity: exposuredom.SeverityLow,
		Reason: "some name servers of this delegation do not exist"}
	if len(missing) == len(servers) {
		d.Severity = exposuredom.SeverityMedium
		d.Reason = "none of the name servers of this delegation exist"
		for _, m := range missing {
			if unregistered(ctx, q, m) {
				d.Unregistered = true
				d.Severity = exposuredom.SeverityHigh
				d.Reason = "the name servers' domain is not registered: whoever registers it controls this zone"
				break
			}
		}
	}
	return d, nil
}

// unregistered reports whether the registrable domain of host answers
// NXDOMAIN. A resolver failure counts as "not shown unregistered".
func unregistered(ctx context.Context, q Querier, host string) bool {
	reg := registrableDomain(host)
	if reg == "" {
		return false
	}
	a, err := q.Query(ctx, reg, dnsprobe.TypeNS)
	return err == nil && a.RCode == dnsprobe.RCodeNXDomain
}

// registrableDomain is host's domain one label below its ICANN public suffix
// ("gone.example.co.uk" -> "example.co.uk"). Private suffixes in the Public
// Suffix List (azurewebsites.net, herokuapp.com …) are deliberately ignored:
// a missing "x.azurewebsites.net" is a provider-claimable name, not an
// unregistered domain, and is reported as such.
func registrableDomain(host string) string {
	labels := strings.Split(strings.Trim(strings.ToLower(host), "."), ".")
	for i := 1; i < len(labels); i++ {
		cand := strings.Join(labels[i:], ".")
		if ps, icann := publicsuffix.PublicSuffix(cand); icann && ps == cand {
			return strings.Join(labels[i-1:], ".")
		}
	}
	return ""
}
