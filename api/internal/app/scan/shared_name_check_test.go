package scan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// publicResolver answers a documentation address (public) for every name.
type publicResolver struct{}

func (publicResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
}

// mapResolver answers from a map; a missing name does not exist.
type mapResolver struct {
	addrs map[string][]string
	err   error
	calls *int
}

func (r mapResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if r.calls != nil {
		*r.calls++
	}
	if r.err != nil {
		return nil, r.err
	}
	raw, ok := r.addrs[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]netip.Addr, 0, len(raw))
	for _, a := range raw {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

// A public-looking name that resolves inside (private, metadata, loopback,
// CGNAT, IPv6 unique-local) never goes to shared sensors; before, only
// literal addresses and internal suffixes were refused.
func TestPlatformTargetRefusal_NamesResolvingInside(t *testing.T) {
	ctx := context.Background()
	res := mapResolver{addrs: map[string][]string{
		"www.example.com":      {"203.0.113.10"},
		"intranet.example.com": {"203.0.113.11", "10.1.2.3"}, // one internal answer is enough
		"imds.example.com":     {"169.254.169.254"},
		"lo.example.com":       {"127.0.0.1"},
		"cgnat.example.com":    {"100.64.1.1"},
		"ula.example.com":      {"fd00::1"},
	}}
	svc := &Service{logger: logger.NewNop(), zoneResolver: res}
	for _, tc := range []struct {
		targets []string
		refused bool
	}{
		{[]string{"www.example.com", "https://www.example.com/login"}, false},
		{[]string{"missing.example.com"}, false}, // does not exist: nothing to reach
		{[]string{"*.example.com"}, false},       // a selector: the sensor checks what it finds
		{[]string{"www.example.com", "intranet.example.com"}, true},
		{[]string{"https://imds.example.com/latest/meta-data"}, true},
		{[]string{"lo.example.com:8080"}, true},
		{[]string{"cgnat.example.com"}, true},
		{[]string{"ula.example.com"}, true},
	} {
		err := svc.PlatformTargetRefusal(ctx, shared.NewID(), tc.targets, false)
		var de *shared.DomainError
		if tc.refused != (errors.As(err, &de) && de.Code == codePlatformRefused) {
			t.Errorf("%v: refusal %v, want refused=%v", tc.targets, err, tc.refused)
		}
	}
}

// A lookup that fails (other than "no such host"), no resolver, or too many
// names: the check fails closed.
func TestPlatformTargetRefusal_NameCheckFailsClosed(t *testing.T) {
	ctx := context.Background()
	failing := &Service{logger: logger.NewNop(), zoneResolver: mapResolver{err: errors.New("SERVFAIL")}}
	if err := failing.PlatformTargetRefusal(ctx, shared.NewID(), []string{"www.example.com"}, false); err == nil {
		t.Error("a failed lookup allowed shared sensors")
	}
	unwired := &Service{logger: logger.NewNop()}
	if err := unwired.PlatformTargetRefusal(ctx, shared.NewID(), []string{"www.example.com"}, false); err == nil {
		t.Error("no resolver allowed shared sensors")
	}
	// Addresses alone need no resolver.
	if err := unwired.PlatformTargetRefusal(ctx, shared.NewID(), []string{"203.0.113.5"}, false); err != nil {
		t.Errorf("a public address was refused without a resolver: %v", err)
	}
	many := make([]string, maxSharedNameLookups+1)
	for i := range many {
		many[i] = "h" + strconv.Itoa(i) + ".example.com"
	}
	calls := 0
	svc := &Service{logger: logger.NewNop(), zoneResolver: mapResolver{addrs: map[string][]string{}, calls: &calls}}
	err := svc.PlatformTargetRefusal(ctx, shared.NewID(), many, false)
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != codePlatformRefused || calls != 0 {
		t.Errorf("too many names: %v after %d lookups; want a refusal before any lookup", err, calls)
	}
}
