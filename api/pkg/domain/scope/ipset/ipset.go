// Package ipset is exact address-set arithmetic for scan targets: a set is a
// sorted list of disjoint inclusive address ranges, so a /16 is one entry and
// no operation ever lists addresses one by one. Design:
// docs/rfcs/RFC-088-scope-aware-target-allocation.md.
//
// IPv4 and IPv6 never mix inside one range; an IPv4-mapped IPv6 address is
// read as IPv4 ("::ffff:10.0.0.5" and "10.0.0.5" are the same address), and
// an address zone is dropped.
package ipset

import (
	"errors"
	"math/bits"
	"net/netip"
	"slices"
	"strings"
)

// ErrTooManyPieces is returned when a set cannot be written as at most the
// requested number of prefixes. Callers refuse the work rather than cut it
// short (fail closed).
var ErrTooManyPieces = errors.New("address set splits into too many pieces")

// Range is an inclusive address range of one family.
type Range struct {
	Lo, Hi netip.Addr
}

// Valid reports whether r is a well-formed range: both ends valid, one
// family, Lo <= Hi.
func (r Range) Valid() bool {
	return r.Lo.IsValid() && r.Hi.IsValid() && r.Lo.Is4() == r.Hi.Is4() && !r.Hi.Less(r.Lo)
}

// Size is the number of addresses in r, saturated at the largest uint64
// (an IPv6 range can hold more); full reports the saturation.
func (r Range) Size() (n uint64, full bool) {
	if !r.Valid() {
		return 0, false
	}
	lo, hi := r.Lo.As16(), r.Hi.As16()
	loH, loL := be64(lo[:8]), be64(lo[8:])
	hiH, hiL := be64(hi[:8]), be64(hi[8:])
	diffL, borrow := bits.Sub64(hiL, loL, 0)
	diffH, _ := bits.Sub64(hiH, loH, borrow)
	if diffH != 0 {
		return ^uint64(0), true
	}
	n, carry := bits.Add64(diffL, 1, 0)
	if carry != 0 {
		return ^uint64(0), true
	}
	return n, false
}

// String writes r as an address, a CIDR when r is exactly one prefix, else
// "lo-hi".
func (r Range) String() string {
	if r.Lo == r.Hi {
		return r.Lo.String()
	}
	if p, ok := r.Prefix(); ok {
		return p.String()
	}
	return r.Lo.String() + "-" + r.Hi.String()
}

// Prefix returns r as one prefix when it is exactly one.
func (r Range) Prefix() (netip.Prefix, bool) {
	if !r.Valid() {
		return netip.Prefix{}, false
	}
	p, ok := largestPrefixAt(r.Lo, r.Hi, 0)
	if !ok || LastAddr(p) != r.Hi {
		return netip.Prefix{}, false
	}
	return p, true
}

func be64(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

// Parse reads an address, a CIDR (host bits are masked off) or an "a-b"
// range. It never resolves names.
func Parse(s string) (Range, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Range{}, false
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return Range{}, false
		}
		return PrefixRange(p)
	}
	if lo, hi, ok := strings.Cut(s, "-"); ok {
		a, errA := netip.ParseAddr(strings.TrimSpace(lo))
		b, errB := netip.ParseAddr(strings.TrimSpace(hi))
		if errA != nil || errB != nil {
			return Range{}, false
		}
		r := Range{Lo: a.Unmap().WithZone(""), Hi: b.Unmap().WithZone("")}
		return r, r.Valid()
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return Range{}, false
	}
	a = a.Unmap().WithZone("")
	return Range{Lo: a, Hi: a}, true
}

// PrefixRange is the range a prefix covers. An IPv4-mapped IPv6 prefix of
// /96 or longer is read as the IPv4 prefix it maps.
func PrefixRange(p netip.Prefix) (Range, bool) {
	if !p.IsValid() {
		return Range{}, false
	}
	p = p.Masked()
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	} else if a.Is4In6() {
		// Wider than the mapped block: it spans non-IPv4 space too; keep
		// it as IPv6.
		p = netip.PrefixFrom(a, p.Bits())
	}
	p = netip.PrefixFrom(p.Addr().WithZone(""), p.Bits())
	return Range{Lo: p.Addr(), Hi: LastAddr(p)}, true
}

// LastAddr is the highest address of a prefix.
func LastAddr(p netip.Prefix) netip.Addr {
	p = p.Masked()
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= byte(0x80) >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// Set is a set of addresses: sorted, disjoint, non-adjacent ranges (IPv4
// first). The zero value is the empty set.
type Set struct {
	r []Range
}

// Of builds the set of the given ranges; invalid ranges are ignored.
func Of(rs ...Range) Set {
	in := make([]Range, 0, len(rs))
	for _, r := range rs {
		if r.Valid() {
			in = append(in, r)
		}
	}
	slices.SortFunc(in, func(a, b Range) int {
		if c := a.Lo.Compare(b.Lo); c != 0 {
			return c
		}
		return a.Hi.Compare(b.Hi)
	})
	out := make([]Range, 0, len(in))
	for _, r := range in {
		if n := len(out); n > 0 {
			last := &out[n-1]
			if last.Lo.Is4() == r.Lo.Is4() && touches(*last, r) {
				if last.Hi.Less(r.Hi) {
					last.Hi = r.Hi
				}
				continue
			}
		}
		out = append(out, r)
	}
	return Set{r: out}
}

// touches reports whether b (which starts at or after a) overlaps a or
// starts right after it.
func touches(a, b Range) bool {
	if !a.Hi.Less(b.Lo) {
		return true
	}
	next := a.Hi.Next()
	return next.IsValid() && next == b.Lo
}

// Ranges returns a copy of the set's ranges.
func (s Set) Ranges() []Range { return slices.Clone(s.r) }

// Empty reports whether the set holds no address.
func (s Set) Empty() bool { return len(s.r) == 0 }

// Equal reports whether both sets hold the same addresses.
func (s Set) Equal(o Set) bool { return slices.Equal(s.r, o.r) }

// Contains reports whether a is in the set.
func (s Set) Contains(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	i, _ := slices.BinarySearchFunc(s.r, a, func(r Range, a netip.Addr) int {
		switch {
		case r.Hi.Less(a):
			return -1
		case a.Less(r.Lo):
			return 1
		}
		return 0
	})
	return i < len(s.r) && !a.Less(s.r[i].Lo) && !s.r[i].Hi.Less(a)
}

// Overlaps reports whether both sets share an address.
func (s Set) Overlaps(o Set) bool { return !s.Intersect(o).Empty() }

// Size is the number of addresses in the set, saturated like Range.Size.
func (s Set) Size() (n uint64, full bool) {
	for _, r := range s.r {
		m, f := r.Size()
		var carry uint64
		n, carry = bits.Add64(n, m, 0)
		if f || carry != 0 {
			return ^uint64(0), true
		}
	}
	return n, false
}

// Intersect returns the addresses in both sets.
func (s Set) Intersect(o Set) Set {
	var out []Range
	i, j := 0, 0
	for i < len(s.r) && j < len(o.r) {
		a, b := s.r[i], o.r[j]
		lo, hi := a.Lo, a.Hi
		if lo.Less(b.Lo) {
			lo = b.Lo
		}
		if b.Hi.Less(hi) {
			hi = b.Hi
		}
		if !hi.Less(lo) && lo.Is4() == hi.Is4() {
			out = append(out, Range{Lo: lo, Hi: hi})
		}
		if a.Hi.Less(b.Hi) {
			i++
		} else {
			j++
		}
	}
	return Set{r: out}
}

// Subtract returns the addresses of s that are not in o: a range is cut
// around what o removes, never dropped whole.
func (s Set) Subtract(o Set) Set {
	var out []Range
	j := 0
	for _, a := range s.r {
		for j < len(o.r) && o.r[j].Hi.Less(a.Lo) {
			j++
		}
		cur, alive := a, true
		for k := j; k < len(o.r) && alive; k++ {
			b := o.r[k]
			if cur.Hi.Less(b.Lo) {
				break
			}
			if cur.Lo.Less(b.Lo) {
				out = append(out, Range{Lo: cur.Lo, Hi: b.Lo.Prev()})
			}
			if !b.Hi.Less(cur.Hi) {
				alive = false
				break
			}
			cur.Lo = b.Hi.Next()
		}
		if alive {
			out = append(out, cur)
		}
	}
	return Set{r: out}
}

// PieceBits bounds the size of the prefixes Prefixes returns: no piece is
// wider than /V4 (IPv4) or /V6 (IPv6). Zero means no bound (the minimal
// prefix cover).
type PieceBits struct {
	V4, V6 int
}

// Prefixes writes the set as prefixes, in order: the fewest prefixes that
// cover exactly the set's addresses, each cut further so that none is wider
// than bits allows. More than limit prefixes (limit > 0) is ErrTooManyPieces;
// nothing is returned then.
func (s Set) Prefixes(pb PieceBits, limit int) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, r := range s.r {
		minBits := pb.V6
		if r.Lo.Is4() {
			minBits = pb.V4
		}
		lo := r.Lo
		for {
			p, ok := largestPrefixAt(lo, r.Hi, minBits)
			if !ok {
				return nil, errors.New("ipset: no prefix fits a valid range")
			}
			if limit > 0 && len(out) >= limit {
				return nil, ErrTooManyPieces
			}
			out = append(out, p)
			last := LastAddr(p)
			if last == r.Hi {
				break
			}
			lo = last.Next()
		}
	}
	return out, nil
}

// CountPrefixes is how many prefixes Prefixes would return, stopping at
// limit+1 (so a caller can refuse without building the list).
func (s Set) CountPrefixes(pb PieceBits, limit int) int {
	n := 0
	for _, r := range s.r {
		minBits := pb.V6
		if r.Lo.Is4() {
			minBits = pb.V4
		}
		lo := r.Lo
		for {
			p, ok := largestPrefixAt(lo, r.Hi, minBits)
			if !ok {
				return n
			}
			n++
			if limit > 0 && n > limit {
				return n
			}
			last := LastAddr(p)
			if last == r.Hi {
				break
			}
			lo = last.Next()
		}
	}
	return n
}

// largestPrefixAt is the widest prefix that starts at lo, ends at or before
// hi and is no wider than /minBits.
func largestPrefixAt(lo, hi netip.Addr, minBits int) (netip.Prefix, bool) {
	bitLen := lo.BitLen()
	minBits = max(0, minBits)
	for b := minBits; b <= bitLen; b++ {
		p := netip.PrefixFrom(lo, b)
		if p.Masked().Addr() != lo {
			continue
		}
		if !hi.Less(LastAddr(p)) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}
