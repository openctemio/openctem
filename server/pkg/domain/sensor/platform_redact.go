package sensor

import (
	"net"
	"regexp"
)

// Text a platform sensor wrote (a log line, an error, a result) is shown to
// the tenant whose job it ran, but the sensor is shared infrastructure: its
// own addresses and file system are not the tenant's to see. A platform
// sensor scans public targets only (internal targets stay on the tenant's
// own sensors), so a private, loopback or link-local address in its output
// is the platform's, never a target; the same holds for an absolute path on
// the sensor host. RedactPlatformText masks both. Public addresses and host
// names are left alone: they are the tenant's own targets.

// PlatformRedacted replaces what RedactPlatformText masks.
const PlatformRedacted = "[platform]"

var (
	// Candidate IPv4 and IPv6 literals; each match is parsed and only
	// non-public ones are masked.
	platformIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	platformIPv6 = regexp.MustCompile(`[0-9A-Fa-f]*:[0-9A-Fa-f:]*:[0-9A-Fa-f.]*`)
	// Absolute paths under the roots a sensor host's file system shows
	// (the sensor's working directories, templates, caches, home).
	platformPath = regexp.MustCompile(`(?:^|[\s"'=(\[:,])(/(?:home|root|opt|var|tmp|etc|usr|srv|run|app|data|mnt|proc|sys)(?:/[^\s"'<>)\],;:]*|\b))`)
)

// RedactPlatformText masks a platform sensor's own infrastructure details in
// s: private, loopback, link-local and unspecified IP addresses, and
// absolute host paths.
func RedactPlatformText(s string) string {
	if s == "" {
		return s
	}
	s = platformIPv4.ReplaceAllStringFunc(s, maskInternalIP)
	s = platformIPv6.ReplaceAllStringFunc(s, maskInternalIP)
	return platformPath.ReplaceAllStringFunc(s, func(m string) string {
		i := 0
		for i < len(m) && m[i] != '/' {
			i++
		}
		return m[:i] + PlatformRedacted
	})
}

func maskInternalIP(m string) string {
	ip := net.ParseIP(m)
	if ip == nil {
		return m
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || isSharedAddressSpace(ip) {
		return PlatformRedacted
	}
	return m
}

// isSharedAddressSpace: 100.64.0.0/10 (RFC 6598, carrier-grade NAT and many
// container overlays).
func isSharedAddressSpace(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64
}

// RedactPlatformValue applies RedactPlatformText to every string in v (a
// decoded JSON value: strings, maps, slices); other values are kept.
func RedactPlatformValue(v any) any {
	switch t := v.(type) {
	case string:
		return RedactPlatformText(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = RedactPlatformValue(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = RedactPlatformValue(x)
		}
		return out
	default:
		return v
	}
}
