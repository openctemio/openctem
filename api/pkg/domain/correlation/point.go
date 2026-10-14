package correlation

import (
	"net/url"
	"sort"
	"strings"
)

// InjectionPoint is where a web finding was observed, with the payload the
// template inserted removed: scheme, host and port, path, method, and the
// parameter names with their location. Path segments are never generalized
// (/user/123 and /user/456 stay apart).
type InjectionPoint struct {
	Origin string // scheme://host[:port], lower-case host
	Path   string
	Method string
	Params []string // "location:name", sorted
	// Stripped is the payload removed from the path, "" when none.
	Stripped string
}

// Key is the injection point as one comparable string.
func (p InjectionPoint) Key() string {
	return p.Origin + p.Path + " " + p.Method + " " + strings.Join(p.Params, ",")
}

// Valid reports whether the point names an origin and a path.
func (p InjectionPoint) Valid() bool { return p.Origin != "" && p.Path != "" }

// PointInput is what one detection reports.
type PointInput struct {
	MatchedURL string
	Method     string
	// Params are "location:name" (query names come from the URL itself).
	Params []string
	// Payloads are the payload values the detection's own evidence shows: a
	// redirect target (response Location), an out-of-band interaction URL.
	Payloads []string
	// ExtraOASTHosts are configured interactsh servers.
	ExtraOASTHosts []string
}

// Point computes the injection point. A payload is removed from the path
// only when the path contains exactly that value, as whole segments, and its
// host is a known out-of-band domain: both conditions, so a segment that
// merely looks like a payload host stays.
func Point(in PointInput) (InjectionPoint, bool) {
	u, err := url.Parse(strings.TrimSpace(in.MatchedURL))
	if err != nil || u.Host == "" {
		return InjectionPoint{}, false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return InjectionPoint{}, false
	}
	host := strings.ToLower(u.Hostname())
	origin := scheme + "://" + host
	if port := u.Port(); port != "" && !(scheme == "http" && port == "80") && !(scheme == "https" && port == "443") {
		origin += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	p := InjectionPoint{Origin: origin, Path: path, Method: strings.ToUpper(strings.TrimSpace(in.Method))}
	if p.Method == "" || p.Method == "ANY" {
		p.Method = "GET"
	}
	for _, raw := range in.Payloads {
		if stripped, rest, ok := stripPayload(p.Path, raw, in.ExtraOASTHosts); ok {
			p.Path, p.Stripped = rest, stripped
			break
		}
	}
	params := map[string]bool{}
	for name := range u.Query() {
		params["query:"+name] = true
	}
	for _, x := range in.Params {
		if x = strings.TrimSpace(x); x != "" {
			params[x] = true
		}
	}
	for k := range params {
		p.Params = append(p.Params, k)
	}
	sort.Strings(p.Params)
	return p, true
}

// stripPayload removes payload from path when path ends with it as whole
// segments ("/a/oast.me" or "//interact.sh/en") and its host is out-of-band.
func stripPayload(path, payload string, extra []string) (string, string, bool) {
	v := strings.TrimSpace(payload)
	if i := strings.Index(v, "://"); i >= 0 {
		v = v[i+3:]
	}
	v = strings.Trim(v, "/")
	if v == "" {
		return "", "", false
	}
	host := v
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if j := strings.LastIndex(host, ":"); j > 0 {
		host = host[:j]
	}
	if !IsOASTHost(host, extra...) {
		return "", "", false
	}
	trimmed := strings.TrimRight(path, "/")
	if !strings.HasSuffix(trimmed, "/"+v) {
		return "", "", false
	}
	rest := strings.TrimRight(strings.TrimSuffix(trimmed, "/"+v), "/")
	if rest == "" {
		rest = "/"
	}
	return v, rest, true
}
