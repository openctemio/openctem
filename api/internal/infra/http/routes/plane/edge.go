package plane

import (
	"fmt"
	"sort"
	"strings"
)

// Edge is how the public gateway (api/deploy/gateway) treats a path.
type Edge string

const (
	// EdgeAPI: the gateway proxies the path straight to the API.
	EdgeAPI Edge = "api"
	// EdgeWeb: a browser plane. Cookie-session calls go through the web app's
	// BFF (its /api/v1 and /api/v1/admin proxies), which authenticates the
	// session and calls the API. Token clients (oct_ keys, bearer tokens
	// without a session cookie) reach the API by the gateway's credential
	// rules, which only ever see browser-plane paths.
	EdgeWeb Edge = "web"
	// EdgeInternal: never public; the gateway answers 404.
	EdgeInternal Edge = "internal"
)

// PlaneEdges is the edge treatment of each plane. The gateway configuration
// (api/deploy/gateway/planes.caddy) is generated from this table and Rules,
// so the edge and the route table cannot drift.
var PlaneEdges = map[Plane]Edge{
	User:    EdgeWeb,
	Self:    EdgeWeb,
	Auth:    EdgeWeb,
	Admin:   EdgeWeb,
	Sensor:  EdgeAPI,
	Inbound: EdgeAPI,
	SCIM:    EdgeAPI,
	MCP:     EdgeAPI,
	Ops:     EdgeAPI,
}

// EdgeOverride is a path whose edge treatment differs from its plane's.
type EdgeOverride struct {
	Prefix string
	Edge   Edge
	Why    string
}

// EdgeOverrides lists those paths. Each prefix must lie in a plane.
var EdgeOverrides = []EdgeOverride{
	{Prefix: "/metrics", Edge: EdgeInternal, Why: "Prometheus metrics"},
	{Prefix: "/ready", Edge: EdgeInternal, Why: "readiness detail"},
	{Prefix: "/api/v1/auth/saml", Edge: EdgeAPI, Why: "SAML metadata, login redirect and the IdP's form POST to the ACS"},
	{Prefix: "/api/v1/auth/backchannel-logout", Edge: EdgeAPI, Why: "OIDC back-channel logout, called by the IdP"},
	{Prefix: "/api/v1/ws", Edge: EdgeAPI, Why: "browser WebSocket (same origin, session cookie); the web BFF does not proxy upgrades"},
}

// EdgeOf returns the edge treatment of path: its override, else its plane's.
func EdgeOf(path string) (Edge, bool) {
	best := ""
	edge := Edge("")
	for _, o := range EdgeOverrides {
		if hasPathPrefix(path, o.Prefix) && len(o.Prefix) > len(best) {
			best, edge = o.Prefix, o.Edge
		}
	}
	r, ok := Of(path)
	if !ok {
		return "", false
	}
	if best != "" && len(best) >= len(r.Prefix) {
		return edge, true
	}
	return PlaneEdges[r.Plane], true
}

// edgeEntry is one prefix of the generated configuration.
type edgeEntry struct {
	prefix string
	why    string
}

// GatewayPlanesFile renders api/deploy/gateway/planes.caddy: one Caddy
// matcher per plane that the gateway sends straight to the API, and one for
// the paths it never serves. Everything else is a browser plane and falls
// through to the Caddyfile's credential rules and the web app.
func GatewayPlanesFile() (string, error) {
	internal := []edgeEntry{}
	api := map[Plane][]edgeEntry{}

	add := func(prefix, why string, pl Plane) error {
		e, ok := EdgeOf(prefix)
		if !ok {
			return fmt.Errorf("prefix %s lies in no plane", prefix)
		}
		switch e {
		case EdgeInternal:
			internal = append(internal, edgeEntry{prefix, why})
		case EdgeAPI:
			api[pl] = append(api[pl], edgeEntry{prefix, why})
		case EdgeWeb:
		default:
			return fmt.Errorf("prefix %s: plane %s has no edge treatment", prefix, pl)
		}
		return nil
	}
	for _, r := range Rules {
		if _, ok := PlaneEdges[r.Plane]; !ok {
			return "", fmt.Errorf("plane %s has no entry in PlaneEdges", r.Plane)
		}
		why := ""
		if r.Closed {
			why = "deprecated, successor " + r.Successor
		}
		for _, o := range EdgeOverrides {
			if o.Prefix == r.Prefix {
				why = o.Why
			}
		}
		if err := add(r.Prefix, why, r.Plane); err != nil {
			return "", err
		}
	}
	for _, o := range EdgeOverrides {
		r, ok := Of(o.Prefix)
		if !ok {
			return "", fmt.Errorf("edge override %s lies in no plane", o.Prefix)
		}
		if o.Edge == PlaneEdges[r.Plane] && o.Prefix != r.Prefix {
			return "", fmt.Errorf("edge override %s repeats its plane's treatment", o.Prefix)
		}
		if o.Prefix == r.Prefix {
			continue // already emitted from Rules, with the override applied
		}
		if err := add(o.Prefix, o.Why, r.Plane); err != nil {
			return "", err
		}
	}

	var b strings.Builder
	b.WriteString(`# Code generated from api/internal/infra/http/routes/plane (plane.go, edge.go).
# DO NOT EDIT. Regenerate with:
#   cd api && UPDATE_GATEWAY_PLANES=1 go test ./internal/infra/http/routes/plane/ -run TestGatewayPlanesFile
# CI fails when this file and the plane table disagree (RFC-041,
# api/docs/rfcs/RFC-041-api-path-design.md).
#
# The gateway routes by plane, from the same table the route-style lint checks
# every route against. Each plane the gateway sends straight to the API has its
# own matcher, so a per-plane policy (body limit, rate limit, IP allowlist) is
# one block. Browser planes (user, self, auth, admin) are not listed: they fall
# through to the Caddyfile's credential rules and the web app.

(planes) {
`)
	writeBlock := func(name, comment string, entries []edgeEntry, body string) {
		fmt.Fprintf(&b, "\t# %s\n", comment)
		for _, e := range entries {
			if e.why != "" {
				fmt.Fprintf(&b, "\t#   %s: %s\n", e.prefix, e.why)
			}
		}
		fmt.Fprintf(&b, "\t@%s path", name)
		for _, e := range entries {
			p := caddyPath(e.prefix)
			fmt.Fprintf(&b, " %s %s/*", p, p)
		}
		fmt.Fprintf(&b, "\n\thandle @%s {\n\t\t%s\n\t}\n\n", name, body)
	}
	if len(internal) > 0 {
		writeBlock("edge_internal", "Never public.", internal, "respond 404")
	}
	planes := make([]string, 0, len(api))
	for pl := range api {
		planes = append(planes, string(pl))
	}
	sort.Strings(planes)
	for _, pl := range planes {
		writeBlock("plane_"+pl, fmt.Sprintf("Plane %s: straight to the API.", pl), api[Plane(pl)], "import to_api")
	}
	out := strings.TrimRight(b.String(), "\n") + "\n}\n"
	return out, nil
}

// caddyPath turns a plane prefix into a Caddy path pattern: a path parameter
// matches one segment.
func caddyPath(prefix string) string {
	segs := strings.Split(prefix, "/")
	for i, s := range segs {
		if isParam(s) {
			segs[i] = "*"
		}
	}
	return strings.Join(segs, "/")
}
