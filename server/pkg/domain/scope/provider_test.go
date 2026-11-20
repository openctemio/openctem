package scope

import (
	"net/netip"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
)

// Which entries name a provider's shared addresses (research/531 B2): an
// address inside a shared range, a CIDR or range wholly inside one; never a
// range that only partly overlaps, a dedicated or unknown address, or a
// name.
func TestSharedProviderEntry(t *testing.T) {
	c := edgeaddr.Default()
	var p netip.Prefix
	for _, q := range c.SharedFrontEndPrefixes() {
		if q.Addr().Is4() && q.Bits() >= 9 && q.Bits() <= 28 {
			if r, ok := c.SharedFrontEnd(q.Addr().String()); ok && r.Provider == "Microsoft 365" {
				p = q
				break
			}
		}
	}
	if !p.IsValid() {
		t.Fatal("no Microsoft 365 prefix in the dataset")
	}
	inner := netip.PrefixFrom(p.Addr(), p.Bits()+1).Masked()
	last := netip.PrefixFrom(p.Addr(), p.Bits()+1).Masked().Addr()
	for i := 0; i < 3; i++ {
		last = last.Next()
	}
	wide := netip.MustParsePrefix("0.0.0.0/1")
	if p.Addr().As4()[0] >= 128 {
		wide = netip.MustParsePrefix("128.0.0.0/1")
	}
	ga := c.DedicatedPrefixes()

	for _, tc := range []struct {
		name    string
		typ     TargetType
		pattern string
		want    bool
	}{
		{"address", TargetTypeIPAddress, p.Addr().Next().String(), true},
		{"mapped address", TargetTypeIPAddress, "::ffff:" + p.Addr().Next().String(), true},
		{"cidr inside", TargetTypeCIDR, inner.String(), true},
		{"range inside", TargetTypeIPRange, inner.Addr().String() + "-" + last.String(), true},
		{"cidr partly overlapping", TargetTypeCIDR, wide.String(), false},
		{"documentation address", TargetTypeIPAddress, "192.0.2.10", false},
		{"dedicated provider prefix", TargetTypeIPAddress, ga[0].Addr().Next().String(), false},
		{"a name", TargetTypeDomain, "*.example.com", false},
		{"unparsable", TargetTypeCIDR, "not-a-cidr", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, ok := SharedProviderEntry(tc.typ, tc.pattern)
			if ok != tc.want {
				t.Fatalf("SharedProviderEntry(%s, %s) = %+v, %v", tc.typ, tc.pattern, r, ok)
			}
			if ok && r.Provider != "Microsoft 365" {
				t.Fatalf("provider %q", r.Provider)
			}
		})
	}
}
