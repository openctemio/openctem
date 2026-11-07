package scanzone

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestWithinLAN(t *testing.T) {
	for in, want := range map[string]bool{
		"10.0.0.0/16":         true,
		"10.0.0.0/8":          true,
		"172.16.4.0/24":       true,
		"192.168.1.10/32":     true,
		"fd00:1::/48":         true,
		"172.0.0.0/8":         false, // wider than 172.16.0.0/12
		"100.64.0.0/16":       false, // carrier-grade NAT: refused by the sensor
		"203.0.113.0/24":      false,
		"2001:db8::/32":       false,
		"192.168.0.0/15":      false,
		"::ffff:10.1.0.0/112": true,
	} {
		if got := WithinLAN(netip.MustParsePrefix(in)); got != want {
			t.Errorf("WithinLAN(%s) = %v, want %v", in, got, want)
		}
	}
}

func TestParseLANRanges(t *testing.T) {
	got, err := ParseLANRanges([]string{" 10.0.0.0/16", "10.0.5.0/24", "192.168.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].String() != "10.0.0.0/16" || got[1].String() != "192.168.1.1/32" {
		t.Fatalf("normalized = %v", got)
	}
	for _, bad := range [][]string{nil, {"203.0.113.0/24"}, {"10.0.0.0/16", "8.8.8.8"}, {"127.0.0.1"}, {"10.0.0.0/7"}, {"not-a-range"}} {
		if _, err := ParseLANRanges(bad); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("ParseLANRanges(%v) err = %v, want a validation error", bad, err)
		}
	}
}
