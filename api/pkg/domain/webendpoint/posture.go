package webendpoint

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/openctemio/ctis/v2"
)

// HTTP response header posture of an origin (research: web content
// intelligence, decision D2/D8). The posture is an attribute of the origin
// asset (`http_posture`), never a finding, and it holds names and flags only:
// no header value, no cookie value. A producer may send anything; the
// platform keeps only the allow-listed keys below, each coerced to its own
// type or enum, so a hostile or careless sensor cannot store a value.

// PostureKey is the attribute name on the http_service asset.
const PostureKey = "http_posture"

// PostureNotSent is the frame_options and referrer_policy value of a header
// the response did not send.
const PostureNotSent = "none"

// postureOther is the enum value of a header sent with a value outside the
// list.
const postureOther = "other"

// Bounds of the posture attribute.
const (
	// MaxPostureCookies caps the cookie flag list.
	MaxPostureCookies = 20
	// MaxCookieNameBytes caps a cookie name.
	MaxCookieNameBytes = 64
	// maxHSTSMaxAge is ten years in seconds; a larger value is not a max-age.
	maxHSTSMaxAge = 10 * 365 * 24 * 3600
)

var (
	postureBools = []string{
		"hsts", "hsts_include_subdomains", "hsts_preload",
		"csp", "csp_unsafe_inline", "csp_unsafe_eval",
		"nosniff", "permissions_policy", "cors_credentials",
	}
	postureEnums = map[string][]string{
		// none: the response did not send the header (a template check
		// that reports the missing header says so).
		"frame_options":   {"deny", "sameorigin", "allow_from", postureOther, PostureNotSent},
		"referrer_policy": {PostureNotSent, "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url", postureOther},
		"cors_origin":     {"none", "wildcard", "specific", "reflected"},
	}
	cookieNameRE   = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,64}$`)
	cookieSameSite = []string{"strict", "lax", "none"}
)

// SanitizePosture reduces a producer's posture value to the allow-listed,
// typed form. It returns nil when nothing valid is left (absent, wrong type
// or only unknown keys), so an old producer that sends no posture changes
// nothing and a hostile one stores nothing.
func SanitizePosture(raw any) map[string]any {
	in, ok := raw.(map[string]any)
	if !ok || len(in) == 0 {
		return nil
	}
	out := map[string]any{}
	for _, k := range postureBools {
		if b, ok := in[k].(bool); ok {
			out[k] = b
		}
	}
	for k, allowed := range postureEnums {
		if s, ok := in[k].(string); ok {
			s = strings.ToLower(strings.TrimSpace(s))
			if containsStr(allowed, s) {
				out[k] = s
			}
		}
	}
	if n, ok := intOf(in["hsts_max_age"]); ok && n >= 0 && n <= maxHSTSMaxAge {
		out["hsts_max_age"] = n
	}
	if cs := sanitizeCookies(in["cookies"]); len(cs) > 0 {
		out["cookies"] = cs
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeCookies(raw any) []any {
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	out := make([]map[string]any, 0, min(len(list), MaxPostureCookies))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		if !cookieNameRE.MatchString(name) || seen[name] {
			continue
		}
		seen[name] = true
		c := map[string]any{"name": name}
		for _, f := range []string{"secure", "httponly"} {
			if b, ok := m[f].(bool); ok {
				c[f] = b
			}
		}
		if s, ok := m["samesite"].(string); ok {
			if s = strings.ToLower(strings.TrimSpace(s)); containsStr(cookieSameSite, s) {
				c["samesite"] = s
			}
		}
		out = append(out, c)
		if len(out) == MaxPostureCookies {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
	res := make([]any, len(out))
	for i, c := range out {
		res[i] = c
	}
	return res
}

func intOf(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		if n == float64(int(n)) {
			return int(n), true
		}
	case int:
		return n, true
	case int64:
		return int(n), true
	}
	return 0, false
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// PostureFromSecurityHeaders reduces the CTIS 2.0 security headers of a web
// origin (technical.http.security_headers) to the stored posture: flags and
// enums derived from the header values, never a value itself. The result
// goes through SanitizePosture like any other input; nil when nothing is
// left.
func PostureFromSecurityHeaders(h *ctis.SecurityHeaders) map[string]any {
	if h == nil {
		return nil
	}
	raw := map[string]any{}
	if hsts := strings.ToLower(strings.TrimSpace(h.StrictTransportSecurity)); hsts != "" {
		raw["hsts"] = true
		raw["hsts_include_subdomains"] = strings.Contains(hsts, "includesubdomains")
		raw["hsts_preload"] = strings.Contains(hsts, "preload")
		for _, part := range strings.Split(hsts, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok && strings.TrimSpace(k) == "max-age" {
				if n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(v), `"`)); err == nil {
					raw["hsts_max_age"] = n
				}
			}
		}
	}
	if csp := strings.ToLower(strings.TrimSpace(h.ContentSecurityPolicy)); csp != "" {
		raw["csp"] = true
		raw["csp_unsafe_inline"] = strings.Contains(csp, "'unsafe-inline'")
		raw["csp_unsafe_eval"] = strings.Contains(csp, "'unsafe-eval'")
	}
	if strings.EqualFold(strings.TrimSpace(h.XContentTypeOptions), "nosniff") {
		raw["nosniff"] = true
	}
	if strings.TrimSpace(h.PermissionsPolicy) != "" {
		raw["permissions_policy"] = true
	}
	if fo := strings.ToLower(strings.TrimSpace(h.XFrameOptions)); fo != "" {
		switch {
		case fo == "deny", fo == "sameorigin":
			raw["frame_options"] = fo
		case strings.HasPrefix(fo, "allow-from"):
			raw["frame_options"] = "allow_from"
		default:
			raw["frame_options"] = postureOther
		}
	}
	if rp := strings.ToLower(strings.TrimSpace(h.ReferrerPolicy)); rp != "" {
		// A sent header is never "none" (that value means not sent).
		if rp == PostureNotSent || !containsStr(postureEnums["referrer_policy"], rp) {
			rp = postureOther
		}
		raw["referrer_policy"] = rp
	}
	switch origin := strings.TrimSpace(h.AccessControlAllowOrigin); origin {
	case "":
	case "*":
		raw["cors_origin"] = "wildcard"
	default:
		raw["cors_origin"] = "specific"
	}
	if strings.EqualFold(strings.TrimSpace(h.AccessControlAllowCredentials), "true") {
		raw["cors_credentials"] = true
	}
	if len(h.Cookies) > 0 {
		cookies := make([]any, 0, len(h.Cookies))
		for _, c := range h.Cookies {
			m := map[string]any{"name": c.Name, "secure": c.IsSecure, "httponly": c.IsHTTPOnly}
			if c.SameSite != "" {
				m["samesite"] = c.SameSite
			}
			cookies = append(cookies, m)
		}
		raw["cookies"] = cookies
	}
	return SanitizePosture(raw)
}
