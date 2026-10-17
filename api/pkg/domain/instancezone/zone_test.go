package instancezone

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestNew_RangesArePrivateAndCanonical(t *testing.T) {
	z, err := New(" HQ ", "", []string{"10.1.0.0/16", "192.168.1.7", "10.1.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	if z.Name != "HQ" || len(z.Ranges) != 2 || z.Ranges[0] != "10.1.0.0/16" || z.Ranges[1] != "192.168.1.7/32" {
		t.Fatalf("zone = %+v", z)
	}
	for _, bad := range [][]string{nil, {"8.8.8.0/24"}, {"127.0.0.0/8"}, {"169.254.169.254"}, {"100.64.0.0/10"}, {"10.0.0.0/7"}, {"db.internal"}} {
		if _, err := New("x", "", bad); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("ranges %v: err = %v", bad, err)
		}
	}
	if _, err := New(" ", "", []string{"10.0.0.0/8"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("empty name accepted")
	}
}

func zone(id string, ranges ...string) *Zone {
	z, _ := New(id, "", ranges)
	z.ID, _ = shared.IDFromString(id)
	return z
}

func prefixes(t *testing.T, targets ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(targets))
	for _, s := range targets {
		p, ok := TargetPrefix(s)
		if !ok {
			t.Fatalf("not a prefix: %s", s)
		}
		out = append(out, p)
	}
	return out
}

func TestCovering(t *testing.T) {
	wide := zone("11111111-1111-4111-8111-111111111111", "10.0.0.0/8")
	narrow := zone("22222222-2222-4222-8222-222222222222", "10.5.0.0/16")
	other := zone("33333333-3333-4333-8333-333333333333", "192.168.0.0/16")
	zones := []*Zone{wide, narrow, other}

	if got := Covering(zones, prefixes(t, "10.5.1.1")); got != narrow {
		t.Fatalf("narrowest zone should win, got %v", got)
	}
	if got := Covering(zones, prefixes(t, "10.5.1.1", "10.6.0.1")); got != wide {
		t.Fatalf("only the wide zone holds both, got %v", got)
	}
	if got := Covering(zones, prefixes(t, "10.5.1.1", "192.168.1.1")); got != nil {
		t.Fatalf("targets in two zones must not route, got %v", got)
	}
	if got := Covering(zones, prefixes(t, "10.5.0.0/15")); got != wide {
		t.Fatalf("a range must lie wholly inside, got %v", got)
	}
	if got := Covering(zones, prefixes(t, "https://10.5.9.9:8443/x", "[fd00::1]:22")); got != nil {
		t.Fatalf("an IPv6 target outside every zone: got %v", got)
	}
	if Covering(nil, prefixes(t, "10.5.1.1")) != nil || Covering(zones, nil) != nil {
		t.Fatal("no zones or no targets must give nil")
	}
	if _, ok := TargetPrefix("db.internal"); ok {
		t.Fatal("a name is not a prefix")
	}
}
