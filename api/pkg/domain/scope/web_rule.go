package scope

// Path- and method-aware exclusions (docs/rfcs/RFC-056-web-attack-surface.md
// §5): an exclusion of type `path` is a web rule, a host pattern (its
// Pattern), a segment-aware path prefix and the methods it blocks. It never
// excludes a whole asset: it matches a URL whose host and path it covers,
// for the methods it blocks.
//
// Each such exclusion has a testing mode a scope approver sets (owner,
// 2026-10-07): blocked (the default: nothing is sent), read_only (GET and
// HEAD only) or allowed (treated as in scope), with an optional deadline
// after which it is blocked again. Lifting an exclusion never widens scope:
// the target must still pass the one authority check (RFC-054).

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/ctis/weburl"
)

// Testing is the testing mode of a path exclusion.
type Testing string

// Testing modes.
const (
	TestingBlocked  Testing = "blocked"
	TestingReadOnly Testing = "read_only"
	TestingAllowed  Testing = "allowed"
)

// Valid reports whether t is a known mode.
func (t Testing) Valid() bool {
	return t == TestingBlocked || t == TestingReadOnly || t == TestingAllowed
}

// Bounds of a web rule.
const (
	MaxPathPrefixLen = 500
	// MaxTestingWindow bounds allowed_until.
	MaxTestingWindow = 90 * 24 * time.Hour
)

// WebMethods are the methods a rule can name.
var WebMethods = []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}

// readOnlyMethods are what read_only still lets through.
var readOnlyMethods = []string{"GET", "HEAD"}

// WebRule is the path part of a `path` exclusion.
type WebRule struct {
	// PathPrefix is a normalised, segment-aware prefix ("/admin/debug");
	// a segment "*" matches any one segment ("/api/*/admin").
	PathPrefix string
	// Methods are the methods the rule blocks; empty blocks every method.
	Methods []string
	// Testing is the mode a scope approver set; TestingUntil, when set,
	// ends a read_only or allowed mode.
	Testing          Testing
	TestingUntil     *time.Time
	TestingChangedBy string
	TestingChangedAt *time.Time
}

// NormalizePathPrefix checks and normalises a path prefix: absolute, no
// query or fragment, no dot segment, no percent-encoded slash, backslash or
// NUL, "*" only as a whole segment, empty segments and a trailing "/" or
// "/*" removed. "/" is the whole origin.
func NormalizePathPrefix(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || p[0] != '/' || len(p) > MaxPathPrefixLen || strings.ContainsAny(p, "?#\\\x00") {
		return "", fmt.Errorf("%w: path prefix must be an absolute path without query or fragment", ErrInvalidPattern)
	}
	lower := strings.ToLower(p)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%00") {
		return "", fmt.Errorf("%w: path prefix must not encode a slash, backslash or NUL", ErrInvalidPattern)
	}
	segs := make([]string, 0, strings.Count(p, "/"))
	for _, s := range strings.Split(p, "/") {
		switch {
		case s == "":
			continue
		case s == "." || s == "..":
			return "", fmt.Errorf("%w: path prefix must not contain dot segments", ErrInvalidPattern)
		case strings.Contains(s, "*") && s != "*":
			return "", fmt.Errorf("%w: '*' must be a whole path segment", ErrInvalidPattern)
		}
		for _, r := range s {
			if r < 0x20 || r == 0x7f {
				return "", fmt.Errorf("%w: path prefix contains a control character", ErrInvalidPattern)
			}
		}
		segs = append(segs, s)
	}
	for len(segs) > 0 && segs[len(segs)-1] == "*" {
		segs = segs[:len(segs)-1]
	}
	return "/" + strings.Join(segs, "/"), nil
}

// NormalizeMethods upper-cases and de-duplicates methods; an unknown one is
// an error. Empty means every method.
func NormalizeMethods(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, m := range in {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" || m == "*" {
			return []string{}, nil
		}
		if !slices.Contains(WebMethods, m) {
			return nil, fmt.Errorf("%w: method %q is not one of %v", ErrInvalidPattern, m, WebMethods)
		}
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out, nil
}

// ValidateHostPattern checks the host pattern of a path exclusion: "*"
// (every host in scope), "*.example.com" (the domain and every name under
// it, RFC-054 S1), a host name or address, or an origin URL
// ("https://api.example.com:8443").
func ValidateHostPattern(p string) error {
	if p == "*" {
		return nil
	}
	h := hostOfPattern(p)
	if h == "" || strings.ContainsAny(h, "/?#@ ") || strings.Count(h, "*") > 1 ||
		(strings.Contains(h, "*") && !strings.HasPrefix(h, "*.")) {
		return fmt.Errorf("%w: host pattern must be *, *.example.com, a host or an origin URL", ErrInvalidPattern)
	}
	return nil
}

// hostOfPattern is the host of a pattern: the host of an origin URL, else
// the pattern itself, lower-cased, without a trailing dot.
func hostOfPattern(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if strings.Contains(p, "://") {
		u, err := url.Parse(p)
		if err != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
			return ""
		}
		p = u.Hostname()
	}
	return strings.TrimSuffix(p, ".")
}

// HostPatternMatches reports whether a host pattern covers host.
func HostPatternMatches(pattern, host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if pattern == "*" {
		return host != ""
	}
	p := hostOfPattern(pattern)
	if base, ok := strings.CutPrefix(p, "*."); ok {
		return host == base || strings.HasSuffix(host, "."+base)
	}
	if ip := net.ParseIP(p); ip != nil {
		hip := net.ParseIP(host)
		return hip != nil && hip.Equal(ip)
	}
	return host == p
}

// PathUnder reports whether path lies at or under prefix, segment by
// segment ("/admin" covers "/admin" and "/admin/x", not "/administrator").
// Paths are compared as written (case-sensitive), after removing empty
// segments.
func PathUnder(path, prefix string) bool {
	ps := splitSegments(prefix)
	vs := splitSegments(path)
	if len(vs) < len(ps) {
		return false
	}
	for i, s := range ps {
		if s != "*" && s != vs[i] {
			return false
		}
	}
	return true
}

func splitSegments(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// EffectiveTesting is the mode in force at now: a read_only or allowed mode
// past its deadline is blocked again.
func (r *WebRule) EffectiveTesting(now time.Time) Testing {
	if r == nil || !r.Testing.Valid() {
		return TestingBlocked
	}
	if r.Testing != TestingBlocked && r.TestingUntil != nil && !now.Before(*r.TestingUntil) {
		return TestingBlocked
	}
	return r.Testing
}

// BlockedMethods are the methods the rule blocks at now (nil: none).
func (r *WebRule) BlockedMethods(now time.Time) []string {
	if r == nil {
		return nil
	}
	methods := r.Methods
	if len(methods) == 0 {
		methods = WebMethods
	}
	switch r.EffectiveTesting(now) {
	case TestingAllowed:
		return nil
	case TestingReadOnly:
		out := make([]string, 0, len(methods))
		for _, m := range methods {
			if !slices.Contains(readOnlyMethods, m) {
				out = append(out, m)
			}
		}
		return out
	}
	return slices.Clone(methods)
}

// Blocks reports whether the rule blocks method on path at now.
func (r *WebRule) Blocks(method, path string, now time.Time) bool {
	if r == nil || !PathUnder(path, r.PathPrefix) {
		return false
	}
	m := strings.ToUpper(method)
	if m == "" || m == "ANY" {
		m = "GET"
	}
	return slices.Contains(r.BlockedMethods(now), m)
}

// SetWeb attaches the web rule of a `path` exclusion.
func (e *Exclusion) SetWeb(r *WebRule) { e.web = r }

// PathRulePattern is the stored pattern of a path rule: the host pattern
// followed by the prefix ("*/admin/debug"), one row per host and prefix.
func PathRulePattern(host, prefix string) string {
	return strings.TrimSpace(host) + prefix
}

// HostPattern is the host part of a path exclusion's pattern (the whole
// pattern for any other exclusion).
func (e *Exclusion) HostPattern() string {
	if e.web != nil {
		if h, ok := strings.CutSuffix(e.pattern, e.web.PathPrefix); ok && h != "" {
			return h
		}
	}
	return e.pattern
}

// Web returns the web rule of a `path` exclusion (nil otherwise).
func (e *Exclusion) Web() *WebRule { return e.web }

// BlocksWeb reports whether this exclusion, in effect, blocks a request:
// a `path` exclusion whose host pattern covers host and whose rule blocks
// method on path now.
func (e *Exclusion) BlocksWeb(host, path, method string, now time.Time) bool {
	if e == nil || e.exclusionType != ExclusionTypePath || e.web == nil {
		return false
	}
	return HostPatternMatches(e.HostPattern(), host) && e.web.Blocks(method, path, now)
}

// matchesWebURL is the asset-level match of a `path` exclusion: value is a
// URL whose host and path the rule covers for GET (a URL target is
// requested with GET). A value without a path (a host, an IP) is never
// matched: a path rule never excludes a whole asset.
func (e *Exclusion) matchesWebURL(value string) bool {
	if !strings.Contains(value, "://") {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" {
		return false
	}
	path, err := weburl.NormalizePath(u.EscapedPath())
	if err != nil {
		// A path that does not normalise is refused as excluded: the
		// safe side.
		return HostPatternMatches(e.HostPattern(), u.Hostname())
	}
	return e.BlocksWeb(u.Hostname(), path, "GET", time.Now())
}
