package easm

// Ranges from chosen addresses and the network lookup retry of the
// addresses card (research/425).

import (
	"context"
	"net/netip"
	"sort"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// ExactCover returns the fewest prefixes whose union is exactly addrs: a
// prefix is emitted only when every address in it is in addrs, so the result
// never reaches an address nobody chose. Duplicates and invalid addresses are
// ignored; IPv4-mapped IPv6 addresses count as IPv4.
func ExactCover(addrs []netip.Addr) []netip.Prefix {
	set := make([]netip.Addr, 0, len(addrs))
	seen := map[netip.Addr]bool{}
	for _, a := range addrs {
		if !a.IsValid() {
			continue
		}
		a = a.Unmap().WithZone("")
		if !seen[a] {
			seen[a] = true
			set = append(set, a)
		}
	}
	sort.Slice(set, func(i, j int) bool { return set[i].Less(set[j]) })
	var out []netip.Prefix
	for i := 0; i < len(set); {
		// One run of consecutive addresses of one family.
		j := i
		for j+1 < len(set) && set[j].Next() == set[j+1] {
			j++
		}
		out = append(out, rangePrefixes(set[i], set[j])...)
		i = j + 1
	}
	return out
}

// rangePrefixes splits the inclusive range lo..hi into the fewest aligned
// prefixes.
func rangePrefixes(lo, hi netip.Addr) []netip.Prefix {
	var out []netip.Prefix
	bits := lo.BitLen()
	for lo.IsValid() && !hi.Less(lo) {
		best := netip.PrefixFrom(lo, bits)
		for b := bits - 1; b >= 0; b-- {
			p := netip.PrefixFrom(lo, b)
			if p.Masked().Addr() != lo || hi.Less(lastOf(p)) {
				break
			}
			best = p
		}
		out = append(out, best)
		last := lastOf(best)
		if last == hi {
			break
		}
		lo = last.Next()
	}
	return out
}

// lastOf is the last address of a prefix.
func lastOf(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr()
	b := a.AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	out, _ := netip.AddrFromSlice(b)
	return out
}

// NetworkLookupQueue re-queues the network lookup (lookup.asn) of address
// assets: their coverage pairs become due now, so the coverage loop sends
// them to a sensor (the platform itself looks nothing up). Tenant-scoped; a
// pair already queued is left alone (*postgres.AttributionRepository).
type NetworkLookupQueue interface {
	RequeueNetworkLookup(ctx context.Context, tenantID shared.ID, assetIDs []string) (int, error)
}

// SetLookupQueue wires the lookup retry.
func (d *AddressDecisions) SetLookupQueue(q NetworkLookupQueue) { d.lookups = q }

// LookupRetryResult is the answer to a lookup retry.
type LookupRetryResult struct {
	// Queued: lookups due now.
	Queued int `json:"queued"`
	// Addresses: the addresses whose lookup was asked for.
	Addresses []string `json:"addresses"`
}

// RetryLookup asks again for the network of chosen addresses of the
// caller's card whose network is still unknown. An address on the card
// whose network is known is skipped; one not on the card refuses the whole
// request.
func (d *AddressDecisions) RetryLookup(ctx context.Context, tenantID shared.ID, sel AddressSelection) (*LookupRetryResult, error) {
	if d == nil || d.lookups == nil {
		return nil, errDecisionsUnavailable
	}
	card, err := d.callerCard(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	offered, sharedItems, _, err := expand(card, indexCard(card), sel)
	if err != nil {
		return nil, err
	}
	out := &LookupRetryResult{Addresses: []string{}}
	ids := []string{}
	for _, it := range append(append([]SuggestionAddress{}, offered...), sharedItems...) {
		if it.Network.Known {
			continue
		}
		ids = append(ids, it.AssetID)
		out.Addresses = append(out.Addresses, it.Address)
	}
	if len(ids) == 0 {
		return out, nil
	}
	n, err := d.lookups.RequeueNetworkLookup(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}
	out.Queued = n
	return out, nil
}
