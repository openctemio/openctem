package jobsign

// Feed relay statements (docs/rfcs/RFC-142-feed-relay.md). A platform with
// no outbound access receives its signed feeds through a platform-owned
// sensor that has internet access. The platform asks that sensor for named
// files of a feed with a statement of command_type feed_relay: it belongs to
// no organization (tenant_id is PlatformTenantID), is only for a shared
// sensor (sensor_scope instance), names no tool, templates, content, zone or
// limits, and its targets are the feed origins the sensor may download from.
// The signer signs only origins in its own allowlist; the sensor fetches only
// origins in its own. The files themselves are verified by the platform
// against the feed's pinned root, so the relay adds no trust.

import (
	"net/url"
	"strings"
)

// CommandTypeFeedRelay is the command type of a feed relay round.
const CommandTypeFeedRelay = "feed_relay"

// PlatformTenantID is the tenant_id of a statement that belongs to the
// platform, not to an organization: the nil UUID. Only a feed relay
// statement may carry it.
const PlatformTenantID = "00000000-0000-0000-0000-000000000000"

// DefaultFeedOrigins are the official feed origins a feed relay may name
// when the signer's allowlist is not configured: the vulnerability feed
// releases and the release (version check) feed.
var DefaultFeedOrigins = []string{
	"https://github.com/openctemio/vulnfeed-bundles/releases/latest/download",
	"https://github.com/openctemio/openctem/releases/latest/download",
}

// MaxFeedOrigins caps the origins of one feed relay statement.
const MaxFeedOrigins = 8

// NormalizeFeedOrigin returns the canonical spelling of a feed origin, or ""
// when s is not one: an absolute https URL with a host, no user info, query
// or fragment, and no trailing slash. Scheme and host are lower-cased; the
// path is kept as written (release paths are case sensitive).
func NormalizeFeedOrigin(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 1024 || strings.ContainsAny(s, " \t\r\n\\") {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.Hostname() == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return ""
	}
	if strings.Contains(u.Path, "/../") || strings.HasSuffix(u.Path, "/..") || strings.Contains(u.Path, "/./") {
		return ""
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	return "https://" + strings.ToLower(u.Host) + path
}

// ParseFeedOrigins reads a comma-separated origin list (SIGNER_FEED_ORIGINS
// and the like). Empty: DefaultFeedOrigins. "none": no origin at all (feed
// relay statements are refused). An entry that is not an origin is an error.
func ParseFeedOrigins(v string) ([]string, bool) {
	v = strings.TrimSpace(v)
	switch v {
	case "":
		return append([]string(nil), DefaultFeedOrigins...), true
	case "none":
		return []string{}, true
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			continue
		}
		o := NormalizeFeedOrigin(p)
		if o == "" {
			return nil, false
		}
		out = append(out, o)
	}
	return out, true
}
