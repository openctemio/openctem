package easmdns

// Lame delegation (RFC-036 P1, docs/architecture/easm-dns-checks.md): a
// sub-zone delegated to name servers that exist but do not answer for it. A
// recursive resolver only says SERVFAIL there, so the check asks the parent
// zone's authoritative server for the referral (no recursion) and then asks
// each delegated name server directly whether it is authoritative.
//
// Boundaries:
//   - it runs only for a name whose A lookup returned SERVFAIL;
//   - the parent zone must be at or below the name's registrable domain, so
//     public-suffix (TLD) servers are never asked;
//   - at most maxParentServers parent servers and maxChildServers delegated
//     servers are asked, each once, through the shared rate limiter;
//   - every server address comes from DNS data and is refused unless it is a
//     public IP literal (dnsprobe.QueryServer, the SSRF policy);
//   - only DNS questions about the tenant's own name are sent, on port 53.

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/dnsprobe"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
)

// AuthQuerier asks one authoritative server a non-recursive question.
// Satisfied by *dnsprobe.Client.
type AuthQuerier interface {
	QueryServer(ctx context.Context, ip, name string, t dnsprobe.Type) (dnsprobe.Answer, error)
}

const (
	maxParentServers = 3
	maxChildServers  = 8
)

// checkLame decides whether name, which the resolver answered SERVFAIL for,
// is a lame delegation. ok=false means nothing could be concluded (no parent
// in reach, no referral, not delegated, or every delegated server answered
// authoritatively so the failure has another cause).
func checkLame(ctx context.Context, q Querier, aq AuthQuerier, name string) (Dangling, bool) {
	parent, parentNS := findParentZone(ctx, q, name)
	if parent == "" {
		return Dangling{}, false
	}
	children := referral(ctx, q, aq, name, parentNS)
	if len(children) == 0 {
		return Dangling{}, false
	}
	var lame, missing []string
	judged := 0
	for _, ns := range children {
		ips, nx := addressesOf(ctx, q, ns)
		if nx {
			missing = append(missing, ns)
			judged++
			continue
		}
		answered, checked := answersFor(ctx, aq, ips, name)
		if !checked {
			continue // no address could be asked: no conclusion about this server
		}
		judged++
		if !answered {
			lame = append(lame, ns)
		}
	}
	broken := len(lame) + len(missing)
	if broken == 0 {
		return Dangling{}, false
	}
	d := Dangling{
		Outcome: OutcomeDanglingNS, Lame: lame, Missing: missing, Total: len(children),
		Target:   strings.Join(append(append([]string{}, missing...), lame...), ","),
		Severity: exposuredom.SeverityLow,
		Reason:   "some name servers of this delegation do not answer for the zone (lame delegation)",
	}
	if broken == len(children) && judged == len(children) {
		d.Severity = exposuredom.SeverityMedium
		d.Reason = "no name server of this delegation answers for the zone (lame delegation): " +
			"the name does not resolve, and whoever can create the zone at that DNS provider controls it"
	}
	return d, true
}

// findParentZone walks up from name's parent to its registrable domain and
// returns the first zone with name servers, with those servers.
func findParentZone(ctx context.Context, q Querier, name string) (string, []string) {
	reg := registrableDomain(name)
	if reg == "" || name == reg {
		return "", nil
	}
	labels := strings.Split(name, ".")
	for i := 1; i < len(labels); i++ {
		zone := strings.Join(labels[i:], ".")
		if len(zone) < len(reg) {
			break
		}
		a, err := q.Query(ctx, zone, dnsprobe.TypeNS)
		if err != nil || a.RCode != dnsprobe.RCodeSuccess {
			continue
		}
		var ns []string
		for _, r := range a.Records {
			if r.Type == dnsprobe.TypeNS && r.Name == zone {
				ns = append(ns, r.Value)
			}
		}
		if len(ns) > 0 {
			sort.Strings(ns)
			return zone, ns
		}
	}
	return "", nil
}

// referral asks the parent zone's servers (non-recursive) for name's NS and
// returns the delegated name servers from the authority section. A server
// that answers authoritatively for name itself means name is not delegated.
func referral(ctx context.Context, q Querier, aq AuthQuerier, name string, parentNS []string) []string {
	asked := 0
	for _, ns := range parentNS {
		ips, _ := addressesOf(ctx, q, ns)
		for _, ip := range ips {
			if asked >= maxParentServers {
				return nil
			}
			asked++
			a, err := aq.QueryServer(ctx, ip, name, dnsprobe.TypeNS)
			if err != nil || a.RCode != dnsprobe.RCodeSuccess {
				continue
			}
			if a.Authoritative && a.Has(dnsprobe.TypeNS) {
				return nil // the parent serves name itself: not a delegation
			}
			var out []string
			seen := map[string]bool{}
			for _, r := range a.Authority {
				if r.Type == dnsprobe.TypeNS && r.Name == name && !seen[r.Value] {
					seen[r.Value] = true
					out = append(out, r.Value)
				}
			}
			if len(out) > maxChildServers {
				out = out[:maxChildServers]
			}
			sort.Strings(out)
			return out
		}
	}
	return nil
}

// addressesOf resolves host's IPv4 addresses through the recursive resolver.
// nx reports that host does not exist.
func addressesOf(ctx context.Context, q Querier, host string) (ips []string, nx bool) {
	a, err := q.Query(ctx, host, dnsprobe.TypeA)
	if err != nil {
		return nil, false
	}
	if a.RCode == dnsprobe.RCodeNXDomain {
		return nil, true
	}
	for _, r := range a.Records {
		if r.Type == dnsprobe.TypeA {
			ips = append(ips, r.Value)
		}
	}
	return ips, false
}

// answersFor reports whether any address of a delegated server answers
// authoritatively for name. checked is false when no address could be asked
// (none resolved, or the SSRF policy refused every one): then nothing is
// concluded about the server, so a private name server is never called lame.
func answersFor(ctx context.Context, aq AuthQuerier, ips []string, name string) (answered, checked bool) {
	for _, ip := range ips {
		a, err := aq.QueryServer(ctx, ip, name, dnsprobe.TypeSOA)
		if errors.Is(err, dnsprobe.ErrServerNotAllowed) {
			continue
		}
		checked = true
		if err == nil && a.Authoritative && (a.RCode == dnsprobe.RCodeSuccess || a.RCode == dnsprobe.RCodeNXDomain) {
			return true, true
		}
	}
	return false, checked
}
