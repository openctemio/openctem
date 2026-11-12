package ipset

import (
	"errors"
	"math/rand/v2"
	"net/netip"
	"testing"
)

func mustSet(t *testing.T, ss ...string) Set {
	t.Helper()
	rs := make([]Range, 0, len(ss))
	for _, s := range ss {
		r, ok := Parse(s)
		if !ok {
			t.Fatalf("parse %q", s)
		}
		rs = append(rs, r)
	}
	return Of(rs...)
}

func prefixStrings(t *testing.T, s Set, pb PieceBits, limit int) []string {
	t.Helper()
	ps, err := s.Prefixes(pb, limit)
	if err != nil {
		t.Fatalf("prefixes: %v", err)
	}
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParse(t *testing.T) {
	cases := []struct {
		in     string
		ok     bool
		lo, hi string
	}{
		{"10.0.0.5", true, "10.0.0.5", "10.0.0.5"},
		{"10.0.0.9/30", true, "10.0.0.8", "10.0.0.11"},
		{"10.0.0.250-10.0.1.5", true, "10.0.0.250", "10.0.1.5"},
		{"::ffff:10.0.0.5", true, "10.0.0.5", "10.0.0.5"},
		{"::ffff:10.0.0.0/120", true, "10.0.0.0", "10.0.0.255"},
		{"2001:db8::/126", true, "2001:db8::", "2001:db8::3"},
		{"fe80::1%eth0", true, "fe80::1", "fe80::1"},
		{"10.0.0.9-10.0.0.1", false, "", ""},    // reversed
		{"10.0.0.1-2001:db8::1", false, "", ""}, // mixed families
		{"example.com", false, "", ""},
		{"", false, "", ""},
		{"10.0.0.0/33", false, "", ""},
	}
	for _, c := range cases {
		r, ok := Parse(c.in)
		if ok != c.ok {
			t.Fatalf("Parse(%q) ok = %v, want %v", c.in, ok, c.ok)
		}
		if !ok {
			continue
		}
		if r.Lo.String() != c.lo || r.Hi.String() != c.hi {
			t.Fatalf("Parse(%q) = %s-%s, want %s-%s", c.in, r.Lo, r.Hi, c.lo, c.hi)
		}
	}
}

// An exclusion inside a range splits it: the rest stays, the excluded
// addresses are gone, and the pieces are the fewest prefixes.
func TestSubtract_ExclusionInsideRange(t *testing.T) {
	got := mustSet(t, "198.51.100.0/24").Subtract(mustSet(t, "198.51.100.7"))
	want := []string{
		"198.51.100.0/30", "198.51.100.4/31", "198.51.100.6/32",
		"198.51.100.8/29", "198.51.100.16/28", "198.51.100.32/27",
		"198.51.100.64/26", "198.51.100.128/25",
	}
	if ps := prefixStrings(t, got, PieceBits{}, 0); !equalStrings(ps, want) {
		t.Fatalf("pieces = %v, want %v", ps, want)
	}
	if got.Contains(netip.MustParseAddr("198.51.100.7")) {
		t.Fatal("excluded address is still in the set")
	}
	if n, _ := got.Size(); n != 255 {
		t.Fatalf("size = %d, want 255", n)
	}
}

func TestSubtract_ExclusionCoversWholeRange(t *testing.T) {
	for _, ex := range []string{"198.51.100.0/24", "198.51.0.0/16", "0.0.0.0/0", "198.51.99.0-198.51.101.0"} {
		if got := mustSet(t, "198.51.100.0/24").Subtract(mustSet(t, ex)); !got.Empty() {
			t.Fatalf("minus %s: %v, want empty", ex, got.Ranges())
		}
	}
}

func TestSubtract_DisjointAndOtherFamilyLeaveRangeWhole(t *testing.T) {
	s := mustSet(t, "198.51.100.0/24")
	for _, ex := range []string{"198.51.101.0/24", "2001:db8::/32", "::ffff:198.51.101.1"} {
		if got := s.Subtract(mustSet(t, ex)); !got.Equal(s) {
			t.Fatalf("minus %s changed the set: %v", ex, got.Ranges())
		}
	}
}

func TestSubtract_OverlappingExclusionsAndEdges(t *testing.T) {
	got := mustSet(t, "203.0.113.0/24").Subtract(mustSet(t,
		"203.0.113.0", "203.0.113.255", // both edges
		"203.0.113.10-203.0.113.20", "203.0.113.15-203.0.113.30", // overlapping
		"203.0.113.31", // adjacent to the previous
	))
	want := []Range{
		{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.9")},
		{netip.MustParseAddr("203.0.113.32"), netip.MustParseAddr("203.0.113.254")},
	}
	if r := got.Ranges(); len(r) != 2 || r[0] != want[0] || r[1] != want[1] {
		t.Fatalf("ranges = %v, want %v", r, want)
	}
}

func TestOf_MergesOverlappingAndAdjacentEntries(t *testing.T) {
	s := mustSet(t, "10.0.0.0/25", "10.0.0.128/25", "10.0.0.5", "10.0.1.0-10.0.1.9")
	if r := s.Ranges(); len(r) != 1 || r[0].String() != "10.0.0.0-10.0.1.9" {
		t.Fatalf("ranges = %v, want one 10.0.0.0-10.0.1.9", r)
	}
	// The last IPv4 address and the first IPv6 one are not adjacent.
	s = mustSet(t, "255.255.255.255", "::")
	if len(s.Ranges()) != 2 {
		t.Fatalf("families merged: %v", s.Ranges())
	}
}

func TestIPv6(t *testing.T) {
	got := mustSet(t, "2001:db8::/120").Subtract(mustSet(t, "2001:db8::80/121"))
	if ps := prefixStrings(t, got, PieceBits{}, 0); !equalStrings(ps, []string{"2001:db8::/121"}) {
		t.Fatalf("pieces = %v", ps)
	}
	// Huge IPv6 sets are fine: nothing is listed per address.
	all := mustSet(t, "::/0").Subtract(mustSet(t, "2001:db8::1"))
	if n, full := all.Size(); !full || n != ^uint64(0) {
		t.Fatalf("size = %d full=%v, want saturated", n, full)
	}
	if c := all.CountPrefixes(PieceBits{}, 0); c != 128 {
		t.Fatalf("::/0 minus one address = %d prefixes, want 128", c)
	}
}

// Huge ranges are bounded: cutting them into small pieces stops at the limit
// instead of building millions of strings.
func TestPrefixes_LimitOnHugeRanges(t *testing.T) {
	s := mustSet(t, "0.0.0.0/0")
	if _, err := s.Prefixes(PieceBits{V4: 24}, 4096); !errors.Is(err, ErrTooManyPieces) {
		t.Fatalf("err = %v, want ErrTooManyPieces", err)
	}
	if c := s.CountPrefixes(PieceBits{V4: 24}, 4096); c != 4097 {
		t.Fatalf("count = %d, want to stop at 4097", c)
	}
	v6 := mustSet(t, "2001:db8::/32")
	if _, err := v6.Prefixes(PieceBits{V6: 120}, 4096); !errors.Is(err, ErrTooManyPieces) {
		t.Fatalf("v6 err = %v, want ErrTooManyPieces", err)
	}
	ps := prefixStrings(t, mustSet(t, "198.51.0.0/22"), PieceBits{V4: 24}, 0)
	if !equalStrings(ps, []string{"198.51.0.0/24", "198.51.1.0/24", "198.51.2.0/24", "198.51.3.0/24"}) {
		t.Fatalf("pieces = %v", ps)
	}
}

func TestRange_PrefixAndString(t *testing.T) {
	r, _ := Parse("10.0.0.0-10.0.0.255")
	if r.String() != "10.0.0.0/24" {
		t.Fatalf("String = %s", r.String())
	}
	r, _ = Parse("10.0.0.1-10.0.0.2")
	if _, ok := r.Prefix(); ok || r.String() != "10.0.0.1-10.0.0.2" {
		t.Fatalf("String = %s", r.String())
	}
	r, _ = Parse("0.0.0.0/0")
	if n, full := r.Size(); full || n != 1<<32 {
		t.Fatalf("size of 0.0.0.0/0 = %d", n)
	}
}

// Property test against brute force: random ranges and exclusions inside a
// /22, every address checked one by one. Subtract never keeps an excluded
// address and never drops one that is not excluded; the pieces cover the
// result exactly.
func TestSubtract_PropertyAgainstBruteForce(t *testing.T) {
	rng := rand.New(rand.NewPCG(118, 4))
	base := netip.MustParseAddr("192.0.2.0").As4()
	addr := func(i int) netip.Addr {
		b := base
		b[2] = byte(i >> 8)
		b[3] = byte(i)
		return netip.AddrFrom4(b)
	}
	const space = 1024
	randRange := func() Range {
		a, b := rng.IntN(space), rng.IntN(space)
		if b < a {
			a, b = b, a
		}
		return Range{Lo: addr(a), Hi: addr(b)}
	}
	for iter := 0; iter < 400; iter++ {
		var in, ex []Range
		var inSet, exSet [space]bool
		for range 1 + rng.IntN(3) {
			r := randRange()
			in = append(in, r)
			for i := 0; i < space; i++ {
				if a := addr(i); !a.Less(r.Lo) && !r.Hi.Less(a) {
					inSet[i] = true
				}
			}
		}
		for range rng.IntN(6) {
			r := randRange()
			ex = append(ex, r)
			for i := 0; i < space; i++ {
				if a := addr(i); !a.Less(r.Lo) && !r.Hi.Less(a) {
					exSet[i] = true
				}
			}
		}
		got := Of(in...).Subtract(Of(ex...))
		inter := Of(in...).Intersect(Of(ex...))
		pieces, err := got.Prefixes(PieceBits{V4: 24}, 0)
		if err != nil {
			t.Fatal(err)
		}
		covered := Of()
		var count uint64
		for _, p := range pieces {
			if p.Bits() < 24 {
				t.Fatalf("piece %s wider than /24", p)
			}
			r, _ := PrefixRange(p)
			if covered.Overlaps(Of(r)) {
				t.Fatalf("pieces overlap at %s", p)
			}
			covered = Of(append(covered.Ranges(), r)...)
			n, _ := r.Size()
			count += n
		}
		var want uint64
		for i := 0; i < space; i++ {
			a := addr(i)
			keep := inSet[i] && !exSet[i]
			if keep {
				want++
			}
			if got.Contains(a) != keep {
				t.Fatalf("iter %d: %s kept=%v want %v (in=%v ex=%v)", iter, a, got.Contains(a), keep, in, ex)
			}
			if covered.Contains(a) != keep {
				t.Fatalf("iter %d: pieces cover %s = %v, want %v", iter, a, covered.Contains(a), keep)
			}
			if inter.Contains(a) != (inSet[i] && exSet[i]) {
				t.Fatalf("iter %d: intersect wrong at %s", iter, a)
			}
		}
		if n, _ := got.Size(); n != want || count != want {
			t.Fatalf("iter %d: size %d, pieces %d, want %d", iter, n, count, want)
		}
	}
}
