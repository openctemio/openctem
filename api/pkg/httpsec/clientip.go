// Package httpsec — client IP extraction with trusted-proxy enforcement.
//
// SECURITY (S-4): The previous implementations of getClientIP in
// middleware/ratelimit.go and handler/local_auth_handler.go honored
// X-Real-IP / X-Forwarded-For from any peer. That let attackers spoof IPs
// to defeat per-IP rate limits and to corrupt audit logs (login attempts,
// password resets recorded under fake IPs).
//
// This package centralises the logic and only honors the proxy headers when
// the immediate TCP peer (r.RemoteAddr) sits inside a configured trusted
// CIDR. For requests originating outside that CIDR the headers are ignored
// and r.RemoteAddr wins.
package httpsec

import (
	"net"
	"net/http"
	"strings"
)

// TrustedProxySet holds a parsed allowlist of CIDR ranges that the API
// trusts to populate forwarding headers. Construct once at startup.
type TrustedProxySet struct {
	cidrs []*net.IPNet
}

// NewTrustedProxySet parses a list of CIDR strings (or bare IPs).
// Invalid entries are silently dropped; callers should validate up-front
// during config parsing if strict mode is desired.
func NewTrustedProxySet(entries []string) *TrustedProxySet {
	set := &TrustedProxySet{cidrs: make([]*net.IPNet, 0, len(entries))}
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// Accept bare IP by treating it as a /32 (IPv4) or /128 (IPv6)
		if !strings.Contains(raw, "/") {
			if ip := net.ParseIP(raw); ip != nil {
				if ip.To4() != nil {
					raw += "/32"
				} else {
					raw += "/128"
				}
			} else {
				continue
			}
		}
		_, ipnet, err := net.ParseCIDR(raw)
		if err == nil && ipnet != nil {
			set.cidrs = append(set.cidrs, ipnet)
		}
	}
	return set
}

// Contains reports whether ip is inside any trusted CIDR.
func (s *TrustedProxySet) Contains(ip net.IP) bool {
	if s == nil || ip == nil {
		return false
	}
	for _, c := range s.cidrs {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

// IsEmpty reports whether the allowlist contains zero CIDRs (i.e. no proxy
// is trusted, behave as if directly Internet-facing).
func (s *TrustedProxySet) IsEmpty() bool {
	return s == nil || len(s.cidrs) == 0
}

// ClientIP returns the apparent client IP. If the immediate TCP peer
// (r.RemoteAddr) is inside the trusted-proxy set, it honors X-Real-IP and
// the leftmost X-Forwarded-For entry. Otherwise it returns the TCP peer.
//
// Returns an empty string only if r.RemoteAddr is malformed.
func ClientIP(r *http.Request, trusted *TrustedProxySet) string {
	peer := remoteAddrIP(r)
	if trusted != nil && !trusted.IsEmpty() && peer != nil && trusted.Contains(peer) {
		// Trusted proxy in front; honor forwarding headers.
		if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
			return xrip
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// First entry = original client; subsequent entries = chain of
			// proxies. We take the leftmost client-asserted value because the
			// trusted proxy is what populated the header in the first place.
			if idx := strings.Index(xff, ","); idx != -1 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
	}
	if peer != nil {
		return peer.String()
	}
	// Last-ditch fallback when RemoteAddr can't be parsed (shouldn't happen
	// with net/http, but stay defensive).
	return strings.TrimSpace(r.RemoteAddr)
}

func remoteAddrIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr without port (rare, e.g. unix socket) — try direct parse
		host = r.RemoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}
