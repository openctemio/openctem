//go:build authzmatrix

package authzmatrix

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/authzdoc"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
)

// route is one registered route with its gate and data-scope class, as
// internal/authzdoc reads them from the router source.
type route struct {
	Method, Path, RawPath string
	Feature               string
	Gate                  authzdoc.Gate
	Class                 string // data-scope class (scoped, partial, gap, separate, config, system)
	Ungated               string // why the route carries no gate (allowlist reason)
}

func (r route) key() string { return r.Method + " " + r.Path }

func (r route) console() bool { return strings.HasPrefix(r.Path, authzdoc.ConsolePathPrefix) }

func loadRoutes(t testing.TB) []route {
	t.Helper()
	root := apiRoot()
	raw, err := authzdoc.ParseRoutes(root)
	if err != nil {
		t.Fatalf("parse routes: %v", err)
	}
	ref, err := authzdoc.Build(root)
	if err != nil {
		t.Fatalf("authz reference: %v", err)
	}
	type doc struct {
		feature string
		rd      authzdoc.RouteDoc
	}
	docs := map[string]doc{}
	for _, f := range ref.Features {
		for _, rd := range f.Routes {
			docs[rd.Method+" "+rd.Path] = doc{f.ID, rd}
		}
	}
	seen := map[string]bool{}
	out := make([]route, 0, len(raw))
	for _, r := range raw {
		if seen[r.Method+" "+r.RawPath] {
			continue
		}
		seen[r.Method+" "+r.RawPath] = true
		d := docs[r.Key()]
		out = append(out, route{Method: r.Method, Path: r.Path, RawPath: r.RawPath, Feature: d.feature,
			Gate: r.Gate, Class: d.rd.DataSurface.Class, Ungated: d.rd.Ungated})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// verdict is what a principal should get from a route.
type verdict string

const (
	vAllow verdict = "allow" // passes the gate: anything but 401/403
	vDeny  verdict = "deny"  // refused: 401, 403 or 404
	vAny   verdict = "any"   // not decided by a route gate (public, token-bound, another access model)
)

// Path families decided outside the tenant permission gates.
var (
	// Credentials of their own: the route answers only to that credential.
	ownCredentialPrefixes = []string{
		"/api/v2/sensor/", "/scim/v2/", "/api/v1/ci/runs/", "/hooks/", "/api/v1/hooks/",
		"/oauth/", "/.well-known/", "/api/v1/invitations", "/api/v1/mcp",
	}
	// Public or sign-in endpoints.
	publicPaths = map[string]bool{
		"/health": true, "/ready": true, "/docs": true, "/openapi.yaml": true, "/metrics": true,
		"/api/v1/brand": true, "/api/v1/brand/images/{kind}": true, "/api/v1/legal": true,
		"/api/v1/client-errors": true, "/api/v1/sensors/install/seccomp-profile": true,
		"/api/v1/ci/oidc/exchange": true, "/api/v1/validation/evidence": true,
	}
)

func hasPrefix(p string, prefixes []string) bool {
	for _, x := range prefixes {
		if strings.HasPrefix(p, x) || p == strings.TrimSuffix(x, "/") {
			return true
		}
	}
	return false
}

// sessionOnly routes take a signed-in session and no API key (their chain
// has no oct_ authenticator; the route source says so).
var sessionOnly = map[string]bool{
	"/api/v1/announcements": true, "/api/v1/version": true, "/api/v1/module-presets": true,
}

// handlerGates are checks a handler adds after the route gate, which the
// route source does not show: the extra condition a principal must meet.
var handlerGates = map[string]struct {
	why string
	ok  func(p *principal) bool
}{
	// Organization-wide figures: dashboards:org:view or full data access.
	"GET /api/v1/ctem-cycles/metrics/trend": {"organization-wide figures", orgWide},
	"GET /api/v1/ctem-cycles/{id}/metrics":  {"organization-wide figures", orgWide},
	"GET /api/v1/dashboard/program-metrics": {"organization-wide figures", orgWide},
}

func orgWide(p *principal) bool { return p.adminBypass || p.fullData || p.perms["dashboards:org:view"] }

// passes decides a permission / team-role gate for a principal.
func passes(p *principal, g authzdoc.Gate, bypass bool) bool {
	if g.MinRole != "" {
		if p.Kind != kindUser {
			return false
		}
		switch g.MinRole {
		case teamOwner:
			if p.teamRole != teamOwner {
				return false
			}
		case teamAdmin:
			if p.teamRole != teamOwner && p.teamRole != teamAdmin {
				return false
			}
		}
	}
	if bypass {
		return true
	}
	for _, perm := range g.Permissions {
		if !p.perms[perm] {
			return false
		}
	}
	for _, grp := range g.AnyOf {
		ok := false
		for _, perm := range grp {
			ok = ok || p.perms[perm]
		}
		if !ok {
			return false
		}
	}
	return true
}

// expected is the verdict for one route and principal, with the rule that
// decided it.
func expected(r route, p *principal) (verdict, string) { //nolint:cyclop // one decision table, read top to bottom
	switch {
	case strings.HasPrefix(r.Path, "/api/v1/admin/auth/"):
		return vAny, "console sign-in endpoints (public by design)"
	case r.console():
		if p.Kind == kindNoTenant {
			return vAny, "console route: platform administrator (separate console session)"
		}
		return vDeny, "console route: no tenant credential reaches the platform console"
	case strings.HasPrefix(r.Path, "/api/v2/sensor/pairings"):
		return vAny, "sensor pairing: the pairing code is the credential"
	case strings.HasPrefix(r.Path, "/api/v2/sensor/"):
		if p.Kind == kindSensor {
			return vAny, "sensor protocol"
		}
		return vDeny, "sensor protocol: only a sensor credential"
	case hasPrefix(r.Path, ownCredentialPrefixes) || publicPaths[r.Path] || strings.HasPrefix(r.Path, "/api/v1/auth/"):
		return vAny, "own credential or public: " + firstLine(r.Ungated)
	}

	gated := r.Gate.Gated()
	if !gated && r.Ungated == "" {
		return vAny, "ungated without an allowlist reason"
	}
	if len(r.Gate.Other) > 0 && len(r.Gate.Permissions)+len(r.Gate.AnyOf) == 0 && r.Gate.MinRole == "" {
		return vAny, "decided by another gate: " + strings.Join(r.Gate.Other, ",")
	}

	switch p.Kind {
	case kindUnauth:
		return vDeny, "no credential"
	case kindRevoked:
		return vDeny, "credential of a suspended or removed member"
	case kindSensor:
		return vDeny, "sensor credential on a user route"
	case kindNoTenant:
		return vDeny, "account in no organization"
	case kindAPIKey:
		if middleware.APIKeyRouteDenied(r.RawPath) || sessionOnly[r.Path] {
			return vDeny, "API keys refused on this prefix"
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			return vDeny, "API keys are read-only"
		}
		if r.Gate.MinRole != "" {
			return vDeny, "API keys never carry a team role"
		}
		if r.Gate.StepUp {
			return vDeny, "API keys cannot step up"
		}
		if !gated {
			return vAllow, "signed-in route"
		}
		if passes(p, r.Gate, false) {
			return vAllow, "key scopes (narrowed to the owner) pass the gate"
		}
		return vDeny, "key scopes miss the gate"
	}
	// Signed-in member.
	if !gated {
		return vAllow, "signed-in route: " + firstLine(r.Ungated)
	}
	if len(r.Gate.Other) > 0 {
		// A permission gate plus another named gate (campaign role, self):
		// the permission part must still refuse.
		if !passes(p, r.Gate, p.adminBypass) {
			return vDeny, "permission part of a combined gate"
		}
		return vAny, "decided by another gate: " + strings.Join(r.Gate.Other, ",")
	}
	if passes(p, r.Gate, p.adminBypass) {
		if hg, ok := handlerGates[r.key()]; ok && !hg.ok(p) {
			return vDeny, "handler check: " + hg.why
		}
		return vAllow, "role passes the gate"
	}
	return vDeny, "role misses the gate"
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\n:("); i > 0 {
		s = s[:i]
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}
