package proxypool

import (
	"net/netip"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestVerifiedExitsKeepsOnlyObservedAddresses(t *testing.T) {
	e1, e2 := shared.NewID(), shared.NewID()
	claimed := []EndpointExit{
		{EndpointID: e1, Address: netip.MustParseAddr("203.0.113.9")},
		{EndpointID: e1, Address: netip.MustParseAddr("::ffff:203.0.113.9")}, // the same address, mapped: one row
		{EndpointID: e2, Address: netip.MustParseAddr("198.51.100.7")},       // never seen by the echo
		{EndpointID: e2, Address: netip.Addr{}},                              // no address
		{EndpointID: e2, Address: netip.MustParseAddr("fe80::1%eth0")},       // zoned
	}
	observed := []netip.Addr{netip.MustParseAddr("::ffff:203.0.113.9"), netip.MustParseAddr("192.0.2.1")}
	got := VerifiedExits(claimed, observed)
	if len(got) != 1 || got[0].EndpointID != e1 || got[0].Address.String() != "203.0.113.9" {
		t.Fatalf("verified = %+v", got)
	}
	if out := VerifiedExits(claimed, nil); len(out) != 0 {
		t.Fatalf("no observation verified %+v", out)
	}
}
