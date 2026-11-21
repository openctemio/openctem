package edgeaddr

// Invariants of the shipped dataset and the edge cases of the shared
// front-end rule (research/531 §11.3 A5-A10): provider addresses are taken
// from the dataset at test time, so the tests follow every refresh;
// dedicated and unknown addresses use the documentation ranges.

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// maxDatasetAge is how old the built-in dataset may get before CI asks for a
// refresh (server/scripts/edgeaddr-dataset.py).
const maxDatasetAge = 30 * 24 * time.Hour

func builtin(t *testing.T) Dataset {
	t.Helper()
	var d Dataset
	if err := json.Unmarshal(builtinDataset, &d); err != nil {
		t.Fatalf("built-in dataset: %v", err)
	}
	return d
}

// hostOf is an address inside the first prefix of provider's range entry
// of the wanted family (4 or 6): the prefix's first address plus one.
func hostOf(t *testing.T, provider string, family int) netip.Addr {
	t.Helper()
	for _, r := range builtin(t).Ranges {
		if r.Provider != provider {
			continue
		}
		for _, s := range r.Prefixes {
			p := netip.MustParsePrefix(s).Masked()
			if (family == 4) != p.Addr().Is4() {
				continue
			}
			return p.Addr().Next()
		}
	}
	t.Fatalf("no IPv%d prefix for %s in the dataset", family, provider)
	return netip.Addr{}
}

// inAnyRange reports whether any published range holds a.
func inAnyRange(t *testing.T, a netip.Addr) bool {
	t.Helper()
	for _, r := range builtin(t).Ranges {
		for _, s := range r.Prefixes {
			if netip.MustParsePrefix(s).Contains(a) {
				return true
			}
		}
	}
	return false
}

// TestEdgeaddr_DatasetAge fails once the built-in dataset is more than 30
// days old: providers add and withdraw ranges, and a stale list misses new
// shared addresses (they fall back to the normal path) and keeps withdrawn
// ones.
func TestEdgeaddr_DatasetAge(t *testing.T) {
	v := builtin(t).Version
	day, _, _ := strings.Cut(v, ".")
	at, err := time.Parse("2006-01-02", day)
	if err != nil {
		t.Fatalf("dataset version %q does not start with a date (YYYY-MM-DD.N): %v", v, err)
	}
	if age := time.Since(at); age > maxDatasetAge {
		t.Fatalf("the address classifier's dataset (version %s) is %d days old, more than %d: "+
			"refresh it with `python3 -I server/scripts/edgeaddr-dataset.py fetch <empty dir>` then "+
			"`python3 -I server/scripts/edgeaddr-dataset.py build <that dir> server/pkg/domain/edgeaddr/dataset.json`, "+
			"review the diff and commit it", v, int(age.Hours()/24), int(maxDatasetAge.Hours()/24))
	}
}

// A dedicated prefix (AWS Global Accelerator) never overlaps a shared one:
// otherwise Address, Range and Name (first match) and SharedFrontEnd (any
// dedicated match wins) could disagree.
func TestEdgeaddr_DatasetNoDedicatedSharedOverlap(t *testing.T) {
	var shared, dedicated []netip.Prefix
	for _, r := range builtin(t).Ranges {
		for _, s := range r.Prefixes {
			p := netip.MustParsePrefix(s).Masked()
			if r.Class == Dedicated {
				dedicated = append(dedicated, p)
			} else {
				shared = append(shared, p)
			}
		}
	}
	if len(dedicated) == 0 {
		t.Fatal("the dataset lists no dedicated prefix (AWS Global Accelerator stays dedicated)")
	}
	for _, d := range dedicated {
		for _, s := range shared {
			if d.Overlaps(s) {
				t.Fatalf("dedicated prefix %s overlaps shared prefix %s", d, s)
			}
		}
	}
}

// For the first host of every prefix, Address, Range (the single address)
// and Name answer "shared" exactly when SharedFrontEnd does.
func TestEdgeaddr_ClassPrecedenceConsistent(t *testing.T) {
	c := Default()
	for _, r := range builtin(t).Ranges {
		for _, s := range r.Prefixes {
			a := netip.MustParsePrefix(s).Masked().Addr()
			res, shared := c.SharedFrontEnd(a.String())
			if shared != (r.Class != Dedicated) {
				t.Fatalf("%s (%s %s): SharedFrontEnd = %v", a, r.Provider, r.Class, shared)
			}
			if got := c.Address(a.String(), "", "").Shared(); got != shared {
				t.Fatalf("%s: Address shared = %v, SharedFrontEnd = %v", a, got, shared)
			}
			if got := c.Range(a, a).Shared(); got != shared {
				t.Fatalf("%s: Range shared = %v, SharedFrontEnd = %v", a, got, shared)
			}
			if got := c.Name("app.example.com", nil, []string{a.String()}).Shared(); got != shared {
				t.Fatalf("%s: Name shared = %v, SharedFrontEnd = %v", a, got, shared)
			}
			if shared && res.Provider == "" {
				t.Fatalf("%s: shared with no provider", a)
			}
		}
	}
}

// An address in an Amazon network outside the CLOUDFRONT, S3 and
// API_GATEWAY lists (an EC2 instance, an Elastic IP, a load balancer) is
// never a shared front end: the dataset holds the service lists only.
func TestEdgeaddr_EC2AddressNotShared(t *testing.T) {
	c := Default()
	for _, s := range []string{"3.80.0.10", "52.0.0.10", "18.204.0.10"} {
		a := netip.MustParseAddr(s)
		if inAnyRange(t, a) {
			continue // a refresh moved it into a list: try the next one
		}
		if r, ok := c.SharedFrontEnd(s); ok {
			t.Fatalf("%s: shared %+v", s, r)
		}
		if r := c.Range(a, a); r.Class != Dedicated || r.Provider != "" {
			t.Fatalf("%s: Range = %+v, want dedicated", s, r)
		}
		if r := c.Name("app.example.com", nil, []string{s}); r.Shared() {
			t.Fatalf("%s: Name = %+v", s, r)
		}
		// The network holder labels it, and never as a range.
		if r := c.Address(s, "", "AMAZON-AES"); r.Basis == BasisRange {
			t.Fatalf("%s: Address = %+v, want a network label at most", s, r)
		}
		return
	}
	t.Fatal("every sample Amazon address is inside a published list; pick another")
}

// A provider-held address outside the provider's published lists (a
// customer's own address in the provider's network: BYOIP, an Azure public
// address, a static address) is not shared; the holder only labels it.
func TestEdgeaddr_ProviderHolderOutsidePublishedRange_NotShared(t *testing.T) {
	c := Default()
	const addr = "198.51.100.7"
	if inAnyRange(t, netip.MustParseAddr(addr)) {
		t.Fatal("documentation address inside a published range")
	}
	if _, ok := c.SharedFrontEnd(addr); ok {
		t.Fatal("a holder name made the address shared")
	}
	r := c.Address(addr, "", "Cloudflare, Inc.")
	if r.Class != Edge || r.Provider != "Cloudflare" || r.Basis != BasisNetwork {
		t.Fatalf("Address = %+v, want an edge label on a network basis", r)
	}
}

// IPv6 forms: upper case and uncompressed text and an IPv4-mapped address
// classify as their canonical form; an address with a zone is never shared.
func TestEdgeaddr_IPv6Forms(t *testing.T) {
	c := Default()
	v6 := hostOf(t, "Cloudflare", 6)
	v4 := hostOf(t, "Microsoft 365", 4)
	full := v6.StringExpanded()
	for _, s := range []string{v6.String(), strings.ToUpper(full), full, "[" + v6.String() + "]", "::ffff:" + v4.String()} {
		if _, ok := c.SharedFrontEnd(s); !ok {
			t.Fatalf("%s: not shared", s)
		}
	}
	for _, s := range []string{v6.String() + "%eth0", "fe80::1%eth0"} {
		if _, ok := c.SharedFrontEnd(s); ok {
			t.Fatalf("%s: shared with a zone", s)
		}
	}
	// A range written in a non-canonical form is classified by value.
	hi := v6.Next()
	if r := c.Range(netip.MustParseAddr(strings.ToUpper(full)), hi); !r.Shared() {
		t.Fatalf("Range(%s, %s) = %+v", full, hi, r)
	}
}

// A NAT64 answer (64:ff9b::/96 + a shared IPv4 address, from a sensor
// behind DNS64) is not read as its embedded address yet: it takes the
// normal path. This pins today's behavior.
func TestEdgeaddr_NAT64_NotSharedYet(t *testing.T) {
	c := Default()
	v4 := hostOf(t, "Microsoft 365", 4).As4()
	nat := netip.AddrFrom16([16]byte{0, 0x64, 0xff, 0x9b, 10: 0, 11: 0, 12: v4[0], 13: v4[1], 14: v4[2], 15: v4[3]})
	if _, ok := c.SharedFrontEnd(nat.String()); ok {
		t.Fatalf("%s: NAT64 form read as shared", nat)
	}
}
