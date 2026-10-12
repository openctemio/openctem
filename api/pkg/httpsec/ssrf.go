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
	"errors"
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
	"::/128",             // IPv6 unspecified
	"fe80::/10",          // IPv6 link-local
	"ff00::/8",           // IPv6 multicast
	"fd00:ec2::254/128",  // AWS IMDS over IPv6 (inside fc00::/7)
	"fd20:ce::254/128",   // GCP metadata server over IPv6 (inside fc00::/7)
	// Ranges that embed an IPv4 address the network may translate to: on a
	// NAT64/DNS64 or 6to4 network 64:ff9b::a9fe:a9fe reaches 169.254.169.254.
	"64:ff9b::/96",   // NAT64 well-known prefix
	"64:ff9b:1::/48", // NAT64 local-use prefix
	"2002::/16",      // 6to4
	"2001::/32",      // Teredo
	// IPv4 special-purpose ranges that are never a tenant service.
	"192.0.0.0/24",  // IETF protocol assignments (DS-Lite, NAT64 discovery)
	"198.18.0.0/15", // Benchmarking
}

// privateIPRanges lists the RFC 1918 / ULA CIDRs. They are blocked by
// default: a tenant-supplied URL must not reach the platform's own network
// (database, Redis, the sensor gateway, other services on the same network).
// An operator opens them in one of two ways (see loadPrivateEgress):
//
//   - OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS: the named private ranges only, in
//     any environment. This is the production setting for an on-prem install
//     whose self-managed GitLab, Jira or SMTP relay sits on a private address;
//     the operator lists that subnet and nothing else.
//   - OPENCTEM_HTTPSEC_ALLOW_PRIVATE=1: every private range, honored only with
//     APP_ENV=development. Anywhere else it would open the platform's own
//     network to every tenant at once, so it is ignored and the API refuses to
//     start (PrivateEgressError).
var privateIPRanges = []string{
	"10.0.0.0/8",     // RFC1918 class A
	"172.16.0.0/12",  // RFC1918 class B
	"192.168.0.0/16", // RFC1918 class C
	"fc00::/7",       // IPv6 ULA
}

// Environment variables read once at start-up.
const (
	EnvAllowPrivate      = "OPENCTEM_HTTPSEC_ALLOW_PRIVATE"
	EnvAllowPrivateCIDRs = "OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS"
)

// allowPrivate opens every private range (development only). Tests flip it
// directly to exercise both modes.
var allowPrivate bool

// allowedPrivateCIDRs are the private ranges the operator opened by name.
var allowedPrivateCIDRs []*net.IPNet

// privateEgressErr is the reason the private-egress settings were refused;
// nothing was opened when it is set.
var privateEgressErr error

// AllowPrivate reports whether every RFC1918 / ULA range is reachable (the
// development-only switch). For start-up logging only; IsIPBlocked decides
// individual calls.
func AllowPrivate() bool { return allowPrivate }

// AllowedPrivateCIDRs returns the private ranges opened by
// OPENCTEM_HTTPSEC_ALLOW_PRIVATE_CIDRS, for start-up logging.
func AllowedPrivateCIDRs() []string {
	out := make([]string, 0, len(allowedPrivateCIDRs))
	for _, n := range allowedPrivateCIDRs {
		out = append(out, n.String())
	}
	return out
}

// PrivateEgressError returns why the private-egress settings were refused, or
// nil. The server refuses to start on it; the guard already ignores a refused
// setting, so a binary that does not check it still keeps every private range
// blocked.
func PrivateEgressError() error { return privateEgressErr }

// ValidatePrivateEgress checks the private-egress settings for appEnv
// (APP_ENV) without applying them. Config validation calls it so the server
// refuses to start on a setting the guard would ignore.
func ValidatePrivateEgress(appEnv, allowAll, cidrs string) error {
	_, _, err := loadPrivateEgress(appEnv, allowAll, cidrs)
	return err
}

// loadPrivateEgress parses the private-egress settings. On any error nothing
// is opened (fail closed).
func loadPrivateEgress(appEnv, allowAll, cidrs string) (bool, []*net.IPNet, error) {
	var all bool
	switch strings.TrimSpace(allowAll) {
	case "", "0":
	case "1":
		if appEnv != "development" {
			return false, nil, fmt.Errorf("%s=1 opens every private network range to every tenant and is honored only with APP_ENV=development (APP_ENV=%q); list the ranges the API must reach in %s instead", EnvAllowPrivate, appEnv, EnvAllowPrivateCIDRs)
		}
		all = true
	default:
		return false, nil, fmt.Errorf("%s must be empty or \"1\", got %q", EnvAllowPrivate, allowAll)
	}

	nets := make([]*net.IPNet, 0, strings.Count(cidrs, ",")+1)
	for _, raw := range strings.Split(cidrs, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return false, nil, fmt.Errorf("%s: %q is not a CIDR", EnvAllowPrivateCIDRs, raw)
		}
		if !insidePrivateRange(n) {
			return false, nil, fmt.Errorf("%s: %s is not inside a private range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)", EnvAllowPrivateCIDRs, n)
		}
		nets = append(nets, n)
	}
	return all, nets, nil
}

// insidePrivateRange reports whether n lies wholly inside one private range.
func insidePrivateRange(n *net.IPNet) bool {
	ones, bits := n.Mask.Size()
	for _, p := range privateCIDRs {
		pOnes, pBits := p.Mask.Size()
		if bits == pBits && ones >= pOnes && p.Contains(n.IP) {
			return true
		}
	}
	return false
}

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

// guardedDialer is the SSRF-guarded dial: resolve once with resolver, vet
// every answer, connect to the vetted IPs with dial. Production uses
// defaultDialer; tests build their own value (a scripted DNS server, a
// recording dial) instead of mutating package state.
type guardedDialer struct {
	resolver *net.Resolver
	// dial connects to an already-vetted IP literal; it never resolves.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

var defaultDialer = guardedDialer{
	resolver: net.DefaultResolver,
	dial:     (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
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
	appEnv := os.Getenv("APP_ENV")
	if appEnv == "" {
		appEnv = "production" // the internal/config default
	}
	allowPrivate, allowedPrivateCIDRs, privateEgressErr = loadPrivateEgress(
		appEnv, os.Getenv(EnvAllowPrivate), os.Getenv(EnvAllowPrivateCIDRs))
}

// IsIPBlocked reports whether the given IP is not reachable under
// the current policy. Hard-blocked CIDRs always return true; a private
// (RFC1918 / ULA) address is reachable only when allowPrivate is set or it is
// inside a range the operator opened.
func IsIPBlocked(ip net.IP) bool {
	for _, cidr := range hardBlockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	if allowPrivate {
		return false
	}
	for _, cidr := range allowedPrivateCIDRs {
		if cidr.Contains(ip) {
			return false
		}
	}
	for _, cidr := range privateCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateHost resolves host (a bare hostname or host:port) and rejects it if
// any resolved A/AAAA record falls in a blocked CIDR, under the same policy as
// the HTTP SSRF guard. For non-HTTP outbound targets such as SMTP relays.
// Fail-closed on DNS resolution failure. Internal targets (RFC1918) are only
// permitted when the operator sets the allow-private flag (same as webhooks).
func ValidateHost(ctx context.Context, host string) error {
	_, err := ResolveSafeHost(ctx, host)
	return err
}

// ResolveSafeHost validates host (a bare hostname or host:port) exactly like
// ValidateHost — every resolved A/AAAA record must be out of the blocked
// ranges under the current policy — and additionally returns one safe resolved
// IP. Callers that dial a non-HTTP target (e.g. SMTP) should dial this pinned
// IP rather than re-resolve the hostname at dial time; re-resolving reopens a
// DNS-rebinding TOCTOU window where the second lookup returns an internal IP.
// Fail-closed on DNS resolution failure.
func ResolveSafeHost(ctx context.Context, host string) (net.IP, error) {
	ips, err := resolveSafeIPs(ctx, net.DefaultResolver, host)
	if err != nil {
		return nil, err
	}
	return ips[0], nil
}

// resolveSafeIPs is ResolveSafeHost returning every vetted address, in
// resolver order, so a dialer can fall back across them without resolving
// again.
func resolveSafeIPs(ctx context.Context, resolver *net.Resolver, host string) ([]net.IP, error) {
	if host == "" {
		return nil, fmt.Errorf("empty host")
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	lower := strings.ToLower(strings.TrimSpace(host))
	for _, blocked := range dangerousHosts {
		if lower == blocked {
			return nil, fmt.Errorf("host %q is blocked", host)
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		if IsIPBlocked(ip) {
			return nil, fmt.Errorf("host %s resolves to a blocked address", host)
		}
		return []net.IP{ip}, nil
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dns lookup failed for %q: %w", host, err)
	}
	safe := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if IsIPBlocked(ip.IP) {
			return nil, fmt.Errorf("host %q resolves to blocked address %s", host, ip.IP)
		}
		safe = append(safe, ip.IP)
	}
	if len(safe) == 0 {
		return nil, fmt.Errorf("no resolved addresses for %q", host)
	}
	return safe, nil
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
		// url.Parse wraps its error in *url.Error, whose text repeats the whole
		// input. The input is often a credential (a Slack or Teams webhook URL,
		// a URL with a token in its query), and this error reaches status
		// fields and logs, so keep only the reason.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
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

	lookupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(lookupCtx, parsed.Hostname())
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %s: %w", parsed.Hostname(), err)
	}
	validIPs := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ip := a.IP
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
// The dialer resolves the host ONCE, vets every answer, and then dials the
// vetted IP itself. It must never hand the hostname to net.Dialer: that
// resolves it a second time, and a DNS-rebinding attacker answers the second
// query with an internal address (TTL 0) after the first one passed the
// check. Only the TCP connection is pinned — the transport still uses the
// request's hostname for the Host header and for TLS SNI and certificate
// verification, so HTTPS keeps working unchanged.
//
// Callers should still ValidateURL themselves because the dialer-only
// check happens AFTER DNS resolution, so a request to a
// tenant-supplied URL will have burned a DNS lookup and possibly
// emitted it to a DNS server the attacker controls. ValidateURL
// rejects before the lookup leaves the host process.
func SafeHTTPClient(timeout time.Duration) *http.Client {
	return newSafeHTTPClient(timeout, defaultDialer)
}

// SafeHTTPClientWithHeaderTimeout is SafeHTTPClient for upstreams that take
// longer than the default 15 s to start answering (crt.sh builds a large JSON
// answer before sending headers). Same SSRF guard; only the wait for response
// headers differs. A non-positive responseHeaderTimeout keeps the default.
func SafeHTTPClientWithHeaderTimeout(timeout, responseHeaderTimeout time.Duration) *http.Client {
	c := newSafeHTTPClient(timeout, defaultDialer)
	if responseHeaderTimeout > 0 {
		if tr, ok := c.Transport.(*http.Transport); ok {
			tr.ResponseHeaderTimeout = responseHeaderTimeout
		}
	}
	return c
}

func newSafeHTTPClient(timeout time.Duration, d guardedDialer) *http.Client {
	tr := &http.Transport{
		DialContext:           d.dialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
}

// SafeDialContext is the SSRF-guarded dial function behind SafeHTTPClient,
// exported for transports that need their own http.Transport settings (an
// SDK client, a custom TLS config). It resolves addr's host once, refuses it
// if any answer is in a blocked range, and connects to the vetted addresses
// only — trying each in resolver order — so a second DNS answer can never
// redirect the connection.
func SafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return defaultDialer.dialContext(ctx, network, addr)
}

func (d guardedDialer) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := resolveSafeIPs(ctx, d.resolver, host)
	if err != nil {
		return nil, fmt.Errorf("ssrf guard: %w", err)
	}
	var lastErr error
	for _, ip := range ips {
		conn, dialErr := d.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}
