package scanzone

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

func mustZone(t *testing.T, name string, isDefault bool, ranges ...string) *Zone {
	t.Helper()
	z, err := NewZone(shared.NewID(), name, "", isDefault, ranges, nil)
	if err != nil {
		t.Fatalf("NewZone(%q, %v): %v", name, ranges, err)
	}
	return z
}

func TestParseRanges_NormalizesAndDedupes(t *testing.T) {
	got, err := ParseRanges([]string{
		" 10.1.2.3/16 ", // host bits set: masked to 10.1.0.0/16
		"10.1.5.0/24",   // inside 10.1.0.0/16: dropped
		"10.1.0.0/16",   // duplicate
		"192.168.1.7",   // bare address: /32
		"fd00:1::/48",
		"::ffff:10.9.0.0/112", // IPv4-mapped: unmapped to 10.9.0.0/16
	})
	if err != nil {
		t.Fatalf("ParseRanges: %v", err)
	}
	want := []string{"10.1.0.0/16", "10.9.0.0/16", "192.168.1.7/32", "fd00:1::/48"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, p := range got {
		if p.String() != want[i] {
			t.Errorf("range %d = %s, want %s", i, p, want[i])
		}
	}
}

func TestParseRanges_IPRange(t *testing.T) {
	got, err := ParseRanges([]string{"10.0.0.0-10.0.0.255", "10.0.1.0 - 10.0.1.1"})
	if err != nil {
		t.Fatalf("ParseRanges: %v", err)
	}
	want := []string{"10.0.0.0/24", "10.0.1.0/31"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("range %d = %s, want %s", i, got[i], want[i])
		}
	}
	// An unaligned range expands to several prefixes.
	got, err = ParseRanges([]string{"10.0.0.1-10.0.0.6"})
	if err != nil {
		t.Fatalf("ParseRanges: %v", err)
	}
	var s []string
	for _, p := range got {
		s = append(s, p.String())
	}
	if strings.Join(s, ",") != "10.0.0.1/32,10.0.0.2/31,10.0.0.4/31,10.0.0.6/32" {
		t.Errorf("unaligned range = %v", s)
	}
}

func TestParseRanges_Rejects(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0/0":            "deny",      // overlaps the deny list
		"::/0":                 "deny",      // same for IPv6
		"127.0.0.0/8":          "deny",      // loopback
		"10.0.0.0/7":           "too large", // wider than /8
		"169.254.169.254":      "deny",      // IMDS
		"169.254.0.0/16":       "deny",      // link-local
		"::/128":               "deny",      // unspecified
		"::1":                  "deny",      // loopback
		"fe80::/64":            "deny",      // link-local
		"ff02::1":              "deny",      // multicast
		"224.0.0.1":            "deny",      // multicast
		"255.255.255.255":      "deny",      // broadcast
		"0.0.0.0":              "deny",      // this network
		"2001:db8::/16":        "too large", // wider than /32
		"not-an-ip":            "invalid",   // garbage
		"10.0.0.9-10.0.0.1":    "invalid",   // reversed range
		"10.0.0.1-fd00::1":     "invalid",   // mixed families
		"10.0.0.0-10.255.0.0":  "",          // valid, many prefixes but bounded
		"10.0.0.1-10.200.0.77": "too many",  // explodes into too many prefixes
		"":                     "invalid",   // empty
		"10.0.0.0/33":          "invalid",   // bad length
		"10.0.0.0/8; rm -rf":   "invalid",   // injection-shaped input
	}
	for in, want := range cases {
		_, err := ParseRanges([]string{in})
		if want == "" {
			if err != nil {
				t.Errorf("ParseRanges(%q) = %v, want ok", in, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("ParseRanges(%q) accepted, want error containing %q", in, want)
			continue
		}
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("ParseRanges(%q) error %v is not a validation error", in, err)
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ParseRanges(%q) = %q, want it to mention %q", in, err, want)
		}
	}
}

func TestParseRanges_Bounded(t *testing.T) {
	in := make([]string, 0, MaxRangesPerZone+1)
	for i := 0; i <= MaxRangesPerZone; i++ {
		in = append(in, netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}).String()+"/24")
	}
	if _, err := ParseRanges(in); err == nil {
		t.Fatal("more than MaxRangesPerZone ranges accepted")
	}
}

func TestNewZone_Validation(t *testing.T) {
	tenant := shared.NewID()
	if _, err := NewZone(tenant, "  ", "", false, []string{"10.0.0.0/8"}, nil); err == nil {
		t.Error("blank name accepted")
	}
	if _, err := NewZone(tenant, strings.Repeat("x", MaxNameLength+1), "", false, []string{"10.0.0.0/8"}, nil); err == nil {
		t.Error("over-long name accepted")
	}
	if _, err := NewZone(tenant, "a", strings.Repeat("x", MaxDescriptionLength+1), false, []string{"10.0.0.0/8"}, nil); err == nil {
		t.Error("over-long description accepted")
	}
	if _, err := NewZone(tenant, "a", "", false, nil, nil); err == nil {
		t.Error("non-default zone without ranges accepted")
	}
	if _, err := NewZone(shared.ID{}, "a", "", false, []string{"10.0.0.0/8"}, nil); err == nil {
		t.Error("zone without tenant accepted")
	}
	z, err := NewZone(tenant, "Internet", "", true, nil, nil)
	if err != nil {
		t.Fatalf("default zone without ranges rejected: %v", err)
	}
	if !z.IsDefault || len(z.Ranges) != 0 {
		t.Errorf("default zone = %+v", z)
	}
}

func TestZone_Update(t *testing.T) {
	z := mustZone(t, "dc1", false, "10.1.0.0/16")
	before := z.UpdatedAt
	name, ranges := "dc-1", []string{"10.2.0.0/16"}
	if err := z.Update(&name, nil, nil, &ranges); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if z.Name != "dc-1" || z.Ranges[0].String() != "10.2.0.0/16" {
		t.Errorf("zone after update = %+v", z)
	}
	if z.UpdatedAt.Before(before) {
		t.Error("UpdatedAt went backwards")
	}
	bad := []string{"127.0.0.1"}
	if err := z.Update(nil, nil, nil, &bad); err == nil {
		t.Error("update to a denied range accepted")
	}
	if z.Ranges[0].String() != "10.2.0.0/16" {
		t.Error("failed update changed the zone")
	}
	empty := []string{}
	if err := z.Update(nil, nil, nil, &empty); err == nil {
		t.Error("removing every range from a non-default zone accepted")
	}
}

func TestZone_HasPrivateRange(t *testing.T) {
	if !mustZone(t, "a", false, "10.0.0.0/8").HasPrivateRange() {
		t.Error("10/8 not reported private")
	}
	if !mustZone(t, "b", false, "fd12::/48").HasPrivateRange() {
		t.Error("ULA not reported private")
	}
	if mustZone(t, "c", false, "203.0.113.0/24").HasPrivateRange() {
		t.Error("public range reported private")
	}
}

func TestIsPrivate(t *testing.T) {
	for _, s := range []string{"10.1.1.1", "172.16.0.1", "192.168.3.4", "100.64.0.1", "fd00::1"} {
		if !IsPrivate(netip.MustParseAddr(s)) {
			t.Errorf("IsPrivate(%s) = false", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "2001:4860::8888"} {
		if IsPrivate(netip.MustParseAddr(s)) {
			t.Errorf("IsPrivate(%s) = true", s)
		}
	}
}
