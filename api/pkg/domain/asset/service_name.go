package asset

import (
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Service names. The inventory stores a service (open port) as
// "host:port:proto" (normalizePortIdentifier), for example
// "vndirect.com.vn:443:tcp", "203.0.113.5:443:tcp" or, for IPv6,
// "2001:db8::1:443:tcp". Reports and older code write "host:port/proto" and
// "[2001:db8::1]:443/tcp". SplitServiceName reads all of them, and HostOf is
// the one answer to "which host does this asset name point at?" for scope,
// attribution and dispatch code, so a service always follows its host.

var serviceNameRe = regexp.MustCompile(`^(.+):(\d{1,5})(?:[:/](tcp|udp|sctp))?$`)

// SplitServiceName parses a service name in any of the accepted forms
// ("host:port:proto", "host:port/proto", "host:port", "[v6]:port:proto",
// "[v6]:port/proto", "[v6]:port" and the stored "v6:port:proto"). The host
// is lower-cased without brackets or a trailing dot; proto defaults to tcp.
// ok is false for anything else (a URL, a bare name or address, a path).
func SplitServiceName(name string) (host string, port int, proto string, ok bool) {
	s := strings.ToLower(strings.TrimSpace(name))
	if s == "" || strings.Contains(s, "://") {
		return "", 0, "", false
	}
	m := serviceNameRe.FindStringSubmatch(s)
	if m == nil {
		return "", 0, "", false
	}
	host, proto = m[1], m[3]
	port, err := strconv.Atoi(m[2])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, "", false
	}
	switch {
	case strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]"):
		host = host[1 : len(host)-1]
		if _, err := netip.ParseAddr(host); err != nil {
			return "", 0, "", false
		}
	case strings.Contains(host, ":"):
		// An unbracketed IPv6 host is read only with an explicit protocol:
		// "2001:db8::1:443" is itself an address.
		if proto == "" {
			return "", 0, "", false
		}
		if _, err := netip.ParseAddr(host); err != nil {
			return "", 0, "", false
		}
	case strings.ContainsAny(host, "/?#[]@ "):
		return "", 0, "", false
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", 0, "", false
	}
	if proto == "" {
		proto = "tcp"
	}
	return host, port, proto, true
}

// HostOf is the lower-case host an asset name or scan target points at: the
// host of a URL, of a service name in any form, or of "host:port/path"; the
// name itself otherwise. Brackets and one trailing dot are dropped. It does
// not validate the host.
func HostOf(name string) string {
	s := strings.TrimSpace(name)
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return ""
		}
		return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	}
	if h, _, _, ok := SplitServiceName(s); ok {
		return h
	}
	// A network ("203.0.113.0/24") names no single host: it is returned as
	// it is, never cut to its first address.
	if _, err := netip.ParsePrefix(s); err == nil {
		return strings.ToLower(s)
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
		if h, _, _, ok := SplitServiceName(s); ok {
			return h
		}
	}
	return strings.TrimSuffix(strings.ToLower(strings.Trim(s, "[]")), ".")
}
