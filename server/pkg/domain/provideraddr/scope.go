package provideraddr

import (
	"net/netip"
	"strings"

	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
)

// ScopeEntry is a scope entry of an address kind (ip_address, cidr,
// ip_range), as stored. The move only reads entries: it never writes
// scope_targets or scope_exclusions.
type ScopeEntry struct {
	Type    string
	Pattern string
	Origin  string
}

type addrRange struct{ lo, hi netip.Addr }

// Entries answers whether a scope entry covers an address the way the move
// keeps it: an entry for exactly that address, or a CIDR or range lying
// wholly inside a published shared range (such an entry names provider
// space only; a wider entry also names the organization's own addresses and
// does not hold a provider address).
type Entries struct {
	exact  map[netip.Addr]bool
	ranges []addrRange
	// Card counts the entries the scope card lists, by CardEntryKey.
	Card Counts
}

// NewEntries reads entries with the classifier.
func NewEntries(entries []ScopeEntry, c *edgeaddr.Classifier) *Entries {
	out := &Entries{exact: map[netip.Addr]bool{}, Card: Counts{}}
	for _, e := range entries {
		lo, hi, ok := parseEntry(e.Pattern)
		if !ok {
			continue
		}
		origin := e.Origin
		if origin == "" {
			origin = "manual"
		}
		if lo == hi {
			out.exact[lo] = true
			if _, shared := c.SharedFrontEnd(lo.String()); shared {
				out.Card.Add(CountCardEntriesExact, 1)
				out.Card.Add(CardEntryKey("exact", origin), 1)
			}
			continue
		}
		if r := c.Range(lo, hi); r.Shared() && r.Basis == edgeaddr.BasisRange {
			out.ranges = append(out.ranges, addrRange{lo: lo, hi: hi})
			out.Card.Add(CountCardEntriesRange, 1)
			out.Card.Add(CardEntryKey("range", origin), 1)
		}
	}
	return out
}

// Covers reports whether an entry holds the address.
func (e *Entries) Covers(addr string) bool {
	a, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(addr), "[]"))
	if err != nil {
		return false
	}
	a = a.Unmap()
	if e.exact[a] {
		return true
	}
	for _, r := range e.ranges {
		if r.lo.BitLen() == a.BitLen() && !a.Less(r.lo) && !r.hi.Less(a) {
			return true
		}
	}
	return false
}

// parseEntry reads an address, a CIDR or an "a-b" range as an inclusive
// range of unmapped addresses.
func parseEntry(p string) (lo, hi netip.Addr, ok bool) {
	p = strings.TrimSpace(p)
	if pfx, err := netip.ParsePrefix(p); err == nil {
		pfx = pfx.Masked()
		lo = pfx.Addr().Unmap()
		hi = lastAddr(pfx)
		return lo, hi, lo.IsValid() && hi.IsValid()
	}
	if a, b, found := strings.Cut(p, "-"); found {
		x, err1 := netip.ParseAddr(strings.TrimSpace(a))
		y, err2 := netip.ParseAddr(strings.TrimSpace(b))
		if err1 != nil || err2 != nil {
			return lo, hi, false
		}
		x, y = x.Unmap(), y.Unmap()
		if x.BitLen() != y.BitLen() || y.Less(x) {
			return lo, hi, false
		}
		return x, y, true
	}
	a, err := netip.ParseAddr(strings.Trim(p, "[]"))
	if err != nil || a.Zone() != "" {
		return lo, hi, false
	}
	a = a.Unmap()
	return a, a, true
}

// lastAddr is the last address of a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().Unmap()
	bits := p.Bits()
	if a.Is4() && p.Addr().Is4In6() {
		bits -= 96
	}
	b := a.AsSlice()
	for i := bits; i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	out, _ := netip.AddrFromSlice(b)
	return out
}
