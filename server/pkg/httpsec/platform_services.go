package httpsec

// Platform service addresses: the addresses of the platform's own services
// (its database, cache, signer and gateway, and the API process itself).
// They are refused like the hard-blocked ranges: no private range opened on
// the server or in the platform console, and no per-call private switch
// (PrivateAllowedHTTPClient), ever makes them reachable. Opening a private
// range is an installation-wide act, so without this list a range that
// happens to hold the platform's own network (a container network such as
// 172.16.0.0/12) would let every organization's webhooks and integrations
// talk to the platform's database or cache.
//
// The server registers the addresses at start-up (RefreshPlatformServices)
// and refreshes them, so a service that restarts on a new address stays
// covered. Design: docs/architecture/outbound-requests.md.

import (
	"context"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// EnvPlatformHosts lists more platform service hosts (comma-separated host
// names, IP addresses, host:port or URLs) beyond the ones the server finds
// in its own settings (database, cache, web and gateway health URLs).
const EnvPlatformHosts = "OPENCTEM_HTTPSEC_PLATFORM_HOSTS"

// PlatformHostsFromEnv splits EnvPlatformHosts.
func PlatformHostsFromEnv(v string) []string {
	var out []string
	for _, h := range strings.Split(v, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// HardBlockPlatformService: the address is one of the platform's own
// services.
const HardBlockPlatformService HardBlockReason = "platform_service"

// platformServices holds the registered addresses (never nil after the
// first Store; an empty list blocks nothing extra).
var platformServices atomic.Pointer[[]net.IP]

// SetPlatformServiceAddrs replaces the platform service addresses. Loopback
// and other hard-blocked addresses may be included; they are refused anyway.
func SetPlatformServiceAddrs(ips []net.IP) {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		out = append(out, ip)
	}
	platformServices.Store(&out)
}

// PlatformServiceAddrs returns a copy of the registered addresses.
func PlatformServiceAddrs() []net.IP {
	p := platformServices.Load()
	if p == nil {
		return nil
	}
	return append([]net.IP(nil), (*p)...)
}

// isPlatformService reports whether ip is a registered platform service
// address (an IPv4-mapped IPv6 address matches its IPv4 form).
func isPlatformService(ip net.IP) bool {
	p := platformServices.Load()
	if p == nil {
		return false
	}
	for _, s := range *p {
		if s.Equal(ip) {
			return true
		}
	}
	return false
}

// platformResolveTimeout bounds the lookup of one service host.
const platformResolveTimeout = 5 * time.Second

// ResolvePlatformServices resolves each entry of hosts (a host name, an IP
// address, host:port or a URL; empty entries are skipped) and adds the
// addresses of this process's own network interfaces. A name that does not
// resolve is skipped: the next refresh tries again.
func ResolvePlatformServices(ctx context.Context, hosts []string) []net.IP {
	return resolvePlatformServices(ctx, net.DefaultResolver, hosts, interfaceAddrs)
}

func resolvePlatformServices(ctx context.Context, resolver ipResolver, hosts []string, ifaces func() []net.IP) []net.IP {
	var out []net.IP
	seen := map[string]bool{}
	add := func(ip net.IP) {
		if ip == nil || seen[ip.String()] {
			return
		}
		seen[ip.String()] = true
		out = append(out, ip)
	}
	for _, h := range hosts {
		h = serviceHost(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			add(ip)
			continue
		}
		lctx, cancel := context.WithTimeout(ctx, platformResolveTimeout)
		addrs, err := resolver.LookupIPAddr(lctx, h)
		cancel()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			add(a.IP)
		}
	}
	if ifaces != nil {
		for _, ip := range ifaces() {
			add(ip)
		}
	}
	return out
}

// serviceHost is the bare host of a host name, host:port or URL entry.
func serviceHost(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "/") {
		return "" // a Unix socket path
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return ""
		}
		return u.Hostname()
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return strings.Trim(s, "[]")
}

// interfaceAddrs are the addresses of this process's network interfaces:
// the API itself, reachable from its own network.
func interfaceAddrs() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			out = append(out, n.IP)
		}
	}
	return out
}

// RefreshPlatformServices registers the platform service addresses of hosts
// now, then again every interval until ctx ends (interval <= 0: once). A
// refresh that finds nothing keeps the previous list, so a passing DNS
// failure never unblocks a service.
func RefreshPlatformServices(ctx context.Context, hosts []string, interval time.Duration) {
	refresh := func() {
		if ips := ResolvePlatformServices(ctx, hosts); len(ips) > 0 {
			SetPlatformServiceAddrs(mergeKnown(ips))
		}
	}
	refresh()
	if interval <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				refresh()
			}
		}
	}()
}

// maxPlatformServiceAddrs caps the remembered addresses, so a host whose
// service moves often cannot grow the list without bound.
const maxPlatformServiceAddrs = 256

// mergeKnown keeps the addresses registered before alongside the new ones:
// an address a service used a minute ago may still be served by it (or by
// a sibling replica), and blocking a stale platform address costs nothing.
func mergeKnown(ips []net.IP) []net.IP {
	out := append([]net.IP(nil), ips...)
	for _, old := range PlatformServiceAddrs() {
		dup := false
		for _, ip := range out {
			if ip.Equal(old) {
				dup = true
				break
			}
		}
		if !dup && len(out) < maxPlatformServiceAddrs {
			out = append(out, old)
		}
	}
	return out
}
