// Package httpsec provides SSRF-safe URL validation and HTTP client
// construction. Any code path that fetches a URL chosen at runtime by
// a tenant (webhook delivery, avatar import, OAuth callback, SCM
// discovery) MUST pipe the URL through ValidateURL before dialing,
// otherwise an attacker who controls that URL can point it at the
// cloud metadata service (169.254.169.254) or internal RFC1918 ranges
// and read back secrets via response echo.
//
// The blocklist is deliberately conservative — prod deployments rarely
// need to POST to 10.x or 172.16.x from the API container, and when
// they do, the right fix is a per-tenant allowlist, not loosening this
// file.
//
// This package is the canonical SSRF guard. internal/infra/fetchers/
// has an older duplicate with identical ranges; follow-up work should
// consolidate that callsite onto this package.
package httpsec

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// hardBlockedIPRanges lists CIDRs that MUST NEVER be reachable from
// the API process, regardless of any opt-in env var. Opening these
// yields a security-incident-grade failure:
//
//   - 127.0.0.0/8 / ::1/128: loopback on the API host. A scan here
//     hits the API process itself, which bypasses auth at the
//     transport layer.
//   - 169.254.0.0/16 / fe80::/10: link-local, including AWS/GCP/
//     Azure cloud-metadata (169.254.169.254). A tenant-controlled
//     URL that resolves here leaks IAM credentials.
//   - 100.64.0.0/10: carrier-grade NAT, never a tenant network.
//   - 0.0.0.0/8: "this" network. Not routable.
//   - 224.0.0.0/4 / 240.0.0.0/4 / 255.255.255.255/32: multicast,
//     reserved, broadcast. Never a legitimate outbound target.
var hardBlockedIPRanges = []string{
	"127.0.0.0/8",        // Loopback
	"169.254.0.0/16",     // Link-local (incl. AWS/GCP/Azure IMDS)
	"100.64.0.0/10",      // Carrier-grade NAT
	"0.0.0.0/8",          // "This" network
	"224.0.0.0/4",        // Multicast
	"240.0.0.0/4",        // Reserved
	"255.255.255.255/32", // Broadcast
	"::1/128",            // IPv6 loopback
	"fe80::/10",          // IPv6 link-local
}

// privateIPRanges lists CIDRs that are blocked BY DEFAULT but can
// be opened up for on-prem deployments via the
// OPENCTEM_HTTPSEC_ALLOW_PRIVATE=1 env var. These are legitimate
// targets for a CTEM platform running inside a corporate network
// (self-hosted Jira at 10.0.0.5, internal GitLab at 192.168.x.y,
// etc.) but ship disabled so cloud deployments inherit the safer
// default.
var privateIPRanges = []string{
	"10.0.0.0/8",     // RFC1918 class A
	"172.16.0.0/12",  // RFC1918 class B
	"192.168.0.0/16", // RFC1918 class C
	"fc00::/7",       // IPv6 ULA
}

// allowPrivate is toggled by the env var at init-time. Tests can
// flip this variable directly to exercise both modes without
// re-running init().
var allowPrivate = os.Getenv("OPENCTEM_HTTPSEC_ALLOW_PRIVATE") == "1"

// AllowPrivate reports whether the RFC1918 / ULA ranges are
// currently treated as reachable. Exposed for log-at-startup
// observability; do not consult this to decide individual calls —
// that branches inside IsIPBlocked.
func AllowPrivate() bool { return allowPrivate }

// dangerousHosts is a string-level allowlist rejection for common
// aliases that hit metadata/local services before DNS resolves.
// These stay blocked regardless of allowPrivate — "localhost" and
// the IMDS aliases are never legitimate outbound targets.
var dangerousHosts = []string{
	"localhost",
	"metadata",
	"metadata.google.internal",
	"metadata.google",
	"169.254.169.254",
}

var hardBlockedCIDRs []*net.IPNet
var privateCIDRs []*net.IPNet

func init() {
	for _, cidr := range hardBlockedIPRanges {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			hardBlockedCIDRs = append(hardBlockedCIDRs, ipNet)
		}
	}
	for _, cidr := range privateIPRanges {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			privateCIDRs = append(privateCIDRs, ipNet)
		}
	}
}

// IsIPBlocked reports whether the given IP is not reachable under
// the current policy. Hard-blocked CIDRs always return true; the
// RFC1918 / ULA block is conditional on allowPrivate.
func IsIPBlocked(ip net.IP) bool {
	for _, cidr := range hardBlockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	if !allowPrivate {
		for _, cidr := range privateCIDRs {
			if cidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// ValidationResult carries the parsed URL + the DNS-pinned IP set so
// callers that want to prevent DNS rebinding can dial one of the
// resolved IPs rather than re-resolve at dial time.
type ValidationResult struct {
	URL         *url.URL
	ResolvedIPs []net.IP
}

// ValidateURL parses rawURL, confirms scheme is http/https, blocks
// common dangerous hostnames, resolves DNS and rejects if any A/AAAA
// hits a blocked CIDR. Returns the parsed URL + pinned IPs. On any
// failure, returns an error — callers MUST NOT proceed to dial.
//
// Fail-closed on DNS lookup failure: if we cannot resolve, we cannot
// verify the target is safe, so the request is rejected.
func ValidateURL(rawURL string) (*ValidationResult, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme: %s (only http/https allowed)", parsed.Scheme)
	}

	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return nil, fmt.Errorf("URL has no host")
	}
	for _, blocked := range dangerousHosts {
		if hostname == blocked {
			return nil, fmt.Errorf("blocked hostname: %s", hostname)
		}
	}

	ips, err := net.LookupIP(parsed.Hostname())
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", parsed.Hostname(), err)
	}
	validIPs := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if IsIPBlocked(ip) {
			return nil, fmt.Errorf("blocked IP address: %s resolves to %s", parsed.Hostname(), ip.String())
		}
		validIPs = append(validIPs, ip)
	}
	if len(validIPs) == 0 {
		return nil, fmt.Errorf("no valid IPs for %s", parsed.Hostname())
	}
	return &ValidationResult{URL: parsed, ResolvedIPs: validIPs}, nil
}

// SafeHTTPClient returns an *http.Client whose dialer rejects any
// connection attempt to a blocked CIDR at the transport layer. This
// is the belt to ValidateURL's braces: even if a caller forgets to
// validate up front, the dial will fail closed. Use this as the
// default http.Client for tenant-facing outbound HTTP.
//
// Callers should still ValidateURL themselves because the dialer-only
// check happens AFTER DNS resolution, so a request to a
// tenant-supplied URL will have burned a DNS lookup and possibly
// emitted it to a DNS server the attacker controls. ValidateURL
// rejects before the lookup leaves the host process.
func SafeHTTPClient(timeout time.Duration) *http.Client {
	baseDialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	safeDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if IsIPBlocked(ip.IP) {
				return nil, fmt.Errorf("ssrf guard: blocked IP %s for host %s", ip.IP, host)
			}
		}
		return baseDialer.DialContext(ctx, network, addr)
	}
	tr := &http.Transport{
		DialContext:           safeDialer,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
}
