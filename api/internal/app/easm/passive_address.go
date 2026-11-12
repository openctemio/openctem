package easm

// Passive steps on the addresses the organization's in-scope names resolve
// to (research/425 F5). A passive (T0) step sends nothing to its target: an
// address's network lookup (origin AS, holder, announced prefix) reads public
// routing data through the egress proxy. RFC-071 keeps the passive path from
// being a free lookup service for arbitrary targets: a target no scope
// authority covers is refused. An address one of the organization's own
// in-scope names resolves to is not arbitrary, and its network data is what
// a person needs to decide whether the address is the organization's. Before
// this rule such an address had no network data, so the unknown-network
// guardrail kept it out of passive steps too, so it never got network data:
// every address on the Decisions card stayed "Network unknown".
//
// The rule only widens what a passive step may look up; active checks still
// need a scope entry (or pass the unclassified guardrails), exclusions, the
// deny list and rejections are refused before this check, and a failed
// lookup leaves the address refused (fail closed).

import (
	"context"
	"net/netip"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/scopeauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// addressesBehindScope returns the bare public addresses among targets that
// a name of the tenant the authority covers resolves to. Anything it cannot
// read is left out.
func (g *ActiveGate) addressesBehindScope(ctx context.Context, tenantID shared.ID, auth *scopeauth.Authority, targets []string) map[string]bool {
	out := map[string]bool{}
	if g.resolving == nil || auth == nil {
		return out
	}
	byName := map[string]string{} // canonical address -> target as given
	names := make([]string, 0, len(targets))
	for _, t := range targets {
		ip, err := netip.ParseAddr(strings.TrimSpace(t))
		if err != nil {
			continue // a name, a range, a URL or host:port: not an address
		}
		ip = ip.Unmap()
		if !ip.IsGlobalUnicast() || ip.IsPrivate() {
			continue
		}
		a := ip.String()
		byName[a] = t
		names = append(names, a)
	}
	if len(names) == 0 {
		return out
	}
	assets, err := g.assets.GetByNames(ctx, tenantID, names)
	if err != nil {
		return out
	}
	ids := make([]string, 0, len(assets))
	addrOf := map[string]string{} // asset id -> canonical address
	for n, a := range assets {
		if a == nil {
			continue
		}
		ip, err := netip.ParseAddr(strings.Trim(n, "[]"))
		if err != nil {
			continue
		}
		addr := ip.Unmap().String()
		if _, asked := byName[addr]; !asked {
			continue
		}
		ids = append(ids, a.ID().String())
		addrOf[a.ID().String()] = addr
	}
	if len(ids) == 0 {
		return out
	}
	resolving, err := g.resolving.NamesResolvingTo(ctx, tenantID, ids)
	if err != nil {
		return out
	}
	for id, list := range resolving {
		addr, ok := addrOf[id]
		if !ok {
			continue
		}
		for _, n := range list {
			if _, covered := auth.Covers(n); covered {
				out[byName[addr]] = true
				break
			}
		}
	}
	return out
}
