package ingest

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
)

type fakeDNS map[string][]netip.Addr

func (f fakeDNS) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f[host]; ok {
		return a, nil
	}
	// Random-label probes under a wildcard zone answer.
	if i := strings.Index(host, "."); i > 0 && strings.HasPrefix(host, "oc-") {
		if a, ok := f["*."+host[i+1:]]; ok {
			return a, nil
		}
	}
	if strings.HasPrefix(host, "servfail.") {
		return nil, &net.DNSError{Err: "server misbehaving", Name: host}
	}
	if host == "boom.example.com" {
		return nil, errors.New("boom")
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func TestDNSNameProber(t *testing.T) {
	wild := netip.MustParseAddr("203.0.113.9")
	own := netip.MustParseAddr("203.0.113.50")
	p := NewDNSNameProber(fakeDNS{
		"*.wild.example.com":     {wild},
		"guess.wild.example.com": {wild},
		"real.wild.example.com":  {own},
		"api.example.com":        {own},
	})
	for name, want := range map[string]NameClass{
		"gone.example.com":       NameNoAnswer,
		"guess.wild.example.com": NameWildcardOnly,
		"real.wild.example.com":  NameResolves,
		"api.example.com":        NameResolves,
		"boom.example.com":       NameUnknown,
		"servfail.example.com":   NameUnknown,
	} {
		if got := p.Probe(context.Background(), name); got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
}
