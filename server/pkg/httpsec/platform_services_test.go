package httpsec

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"
	"time"
)

// withPlatformServices registers ips for one test and clears them after.
func withPlatformServices(t *testing.T, ips ...string) {
	t.Helper()
	parsed := make([]net.IP, 0, len(ips))
	for _, s := range ips {
		parsed = append(parsed, net.ParseIP(s))
	}
	SetPlatformServiceAddrs(parsed)
	t.Cleanup(func() { SetPlatformServiceAddrs(nil) })
}

// withConsoleRanges opens ranges in the console policy for one test.
func withConsoleRanges(t *testing.T, cidrs ...string) {
	t.Helper()
	if err := SetConsolePrivateCIDRs(cidrs); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = SetConsolePrivateCIDRs(nil) })
}

// A private range opened in the console reaches every organization's
// webhooks and integrations, but never the platform's own services in it.
func TestPlatformServices_NotOpenedByConsoleRange(t *testing.T) {
	withConsoleRanges(t, "172.16.0.0/12", "10.0.0.0/8")
	withPlatformServices(t, "172.18.0.5", "10.0.0.7")
	for _, ip := range []string{"172.18.0.5", "10.0.0.7", "::ffff:172.18.0.5"} {
		if !IsIPBlocked(net.ParseIP(ip)) {
			t.Errorf("%s (platform service) reachable through an opened range", ip)
		}
	}
	for _, ip := range []string{"172.18.0.6", "10.0.0.8"} {
		if IsIPBlocked(net.ParseIP(ip)) {
			t.Errorf("%s (an opened private address) refused", ip)
		}
	}
	if r, hard := hardBlockReason(net.ParseIP("172.18.0.5")); !hard || r != HardBlockPlatformService {
		t.Fatalf("reason %q %v", r, hard)
	}
}

// The never-openable addresses: loopback, link-local and cloud metadata
// (every provider's) and the platform services, refused with every private
// range opened and with the per-call private switch.
func TestPlatformServices_NeverOpenable(t *testing.T) {
	withConsoleRanges(t, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00:ec2::/48", "fd20:ce::/48")
	withPlatformServices(t, "10.0.0.7")
	never := []string{
		"127.0.0.1", "::1", // loopback (the API)
		"169.254.169.254", "fd00:ec2::254", "fd20:ce::254", // AWS, Azure, GCP, OpenStack metadata
		"100.100.100.200", // Alibaba Cloud metadata
		"192.0.0.192",     // Oracle Cloud metadata
		"fe80::1",         // link-local
		"10.0.0.7",        // a platform service
	}
	for _, ip := range never {
		p := net.ParseIP(ip)
		if !IsIPBlocked(p) || !isIPBlocked(p, true) || !isIPBlockedStrict(p) {
			t.Errorf("%s reachable", ip)
		}
	}
}

// A host name that resolves to a platform service is refused (a tenant
// cannot reach the database through a DNS name it controls).
func TestPlatformServices_NameResolvingToServiceRefused(t *testing.T) {
	withConsoleRanges(t, "10.0.0.0/8")
	withPlatformServices(t, "10.0.0.7")
	res := &tableResolver{answers: map[string][]string{
		"db.example.com":     {"10.0.0.7"},
		"mixed.example.com":  {"10.0.0.9", "10.0.0.7"},
		"gitlab.example.com": {"10.0.0.9"},
	}}
	for _, privateOK := range []bool{false, true} {
		for _, host := range []string{"db.example.com", "mixed.example.com"} {
			if _, err := resolveSafeIPsPolicy(context.Background(), res, host, privateOK); !errors.Is(err, ErrBlockedDestination) {
				t.Errorf("%s (privateOK=%v): %v", host, privateOK, err)
			}
		}
		if _, err := resolveSafeIPsPolicy(context.Background(), res, "gitlab.example.com", privateOK); err != nil {
			t.Errorf("gitlab (privateOK=%v): %v", privateOK, err)
		}
	}
}

// The per-call private switch (a self-hosted model server set by a platform
// administrator) reaches an ordinary private address, never a service or a
// metadata address.
func TestPlatformServices_PrivateSwitchKeepsGuard(t *testing.T) {
	withPlatformServices(t, "192.168.10.5")
	if isIPBlocked(net.ParseIP("192.168.10.6"), true) {
		t.Fatal("ordinary private address refused with the private switch")
	}
	for _, ip := range []string{"192.168.10.5", "169.254.169.254", "fd00:ec2::254"} {
		if !isIPBlocked(net.ParseIP(ip), true) {
			t.Errorf("%s reachable with the private switch", ip)
		}
	}
}

func TestResolvePlatformServices(t *testing.T) {
	res := &tableResolver{answers: map[string][]string{
		"postgres": {"172.18.0.2"},
		"redis":    {"172.18.0.3", "172.18.0.2"},
		"web":      {"172.18.0.4"},
	}}
	got := resolvePlatformServices(context.Background(), res,
		[]string{"postgres", "redis:6379", "http://web:3000/api/health", "", "/run/signer.sock", "10.9.0.1", "[fd00::5]:443", "missing"},
		func() []net.IP { return []net.IP{net.ParseIP("172.18.0.9")} })
	var s []string
	for _, ip := range got {
		s = append(s, ip.String())
	}
	want := []string{"172.18.0.2", "172.18.0.3", "172.18.0.4", "10.9.0.1", "fd00::5", "172.18.0.9"}
	if !slices.Equal(s, want) {
		t.Fatalf("got %v want %v", s, want)
	}
}

// A refresh that resolves nothing keeps the list, and an address a service
// had before stays blocked after it moves.
func TestRefreshPlatformServices_KeepsKnown(t *testing.T) {
	withPlatformServices(t, "10.0.0.7")
	SetPlatformServiceAddrs(mergeKnown([]net.IP{net.ParseIP("10.0.0.8")}))
	for _, ip := range []string{"10.0.0.7", "10.0.0.8"} {
		if !isPlatformService(net.ParseIP(ip)) {
			t.Errorf("%s dropped", ip)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	RefreshPlatformServices(ctx, []string{"name.invalid"}, time.Hour)
	if !isPlatformService(net.ParseIP("10.0.0.7")) {
		t.Fatal("a failed refresh cleared the list")
	}
}

func TestPlatformHostsFromEnv(t *testing.T) {
	if got := PlatformHostsFromEnv(" console , ,signer:9000"); !slices.Equal(got, []string{"console", "signer:9000"}) {
		t.Fatalf("%v", got)
	}
}
