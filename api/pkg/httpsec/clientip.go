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
// and r.RemoteAddr wins. Code outside this package must not read the
// forwarding headers itself; scripts/security-lint.sh Rule 7 enforces that.
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

// ClientIP returns the apparent client IP. It is the ONLY place in the API
// that may read X-Real-IP / X-Forwarded-For (scripts/security-lint.sh Rule 7).
//
// The immediate TCP peer (r.RemoteAddr) is authoritative. Forwarding headers
// are consulted only when that peer is inside the trusted-proxy set:
//
//  1. X-Forwarded-For, walked from the RIGHT: each proxy appends the address
//     it received the request from (or, like Caddy, replaces the header when
//     its own peer is untrusted), so entries are skipped while they are
//     themselves trusted proxies and the first untrusted entry is the client.
//     Everything to its left was supplied by that client and is never
//     believed. (Taking the left-most entry, as this function used to, let a
//     client behind an appending proxy such as nginx's
//     $proxy_add_x_forwarded_for choose its own address.) A malformed entry
//     ends the walk: nothing left of it can be attributed to a trusted hop.
//  2. Only when X-Forwarded-For is absent: X-Real-IP, when it is a well-formed
//     IP. It comes second because a proxy that does not know the header
//     passes the client's value through untouched (Caddy's reverse_proxy does,
//     unless told to overwrite it), whereas every standard proxy maintains
//     X-Forwarded-For.
//  3. Otherwise the TCP peer.
//
// With no trusted proxies configured the headers are never read.
//
// The result is always a bare IP (no port) except in the last-ditch case of
// an unparseable RemoteAddr, where the trimmed RemoteAddr is returned.
func ClientIP(r *http.Request, trusted *TrustedProxySet) string {
	peer := remoteAddrIP(r)
	if peer == nil {
		// net/http always sets host:port; stay defensive.
		return strings.TrimSpace(r.RemoteAddr)
	}
	if trusted.IsEmpty() || !trusted.Contains(peer) {
		return peer.String()
	}
	if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
		if ip := forwardedForClient(xff, trusted); ip != nil {
			return ip.String()
		}
		return peer.String()
	}
	if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); ip != nil {
		return ip.String()
	}
	return peer.String()
}

// forwardedForClient returns the right-most X-Forwarded-For entry that is not
// a trusted proxy. Multiple header lines are one list, in order (RFC 7230
// section 3.2.2). When every entry is a trusted proxy the left-most one is
// returned, being the hop furthest from the API that a trusted proxy vouched
// for. Nil when the header is absent or its right-most entry is malformed.
func forwardedForClient(values []string, trusted *TrustedProxySet) net.IP {
	var entries []string
	for _, v := range values {
		entries = append(entries, strings.Split(v, ",")...)
	}
	var last net.IP
	for i := len(entries) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(entries[i]))
		if ip == nil {
			return last
		}
		if !trusted.Contains(ip) {
			return ip
		}
		last = ip
	}
	return last
}

func remoteAddrIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr without port (rare, e.g. unix socket) — try direct parse
		host = r.RemoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}
