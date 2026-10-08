package unit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// Fail-closed by construction: every HTTP route must EITHER carry a permission
// gate (middleware.Require*/RequireTeam*/RequireOwner…) OR be explicitly listed
// as public/self-scoped/machine-authenticated in routeAuthzAllowlist below.
// A new data route shipped without a gate — the exact bug that compiles, lints
// and unit-tests clean then exposes tenant data — fails HERE instead.
//
// See docs/authz-audit.md AUTHZ-02. This parses the route source (AST) rather
// than walking the built router because the source names WHICH gate is applied;
// the chi middleware chain at runtime only exposes opaque closures.

// gateFuncs are the middleware constructors that constitute an authorization
// gate. Any of these appearing in a route's middleware args (directly, inside
// an append(...), or inside a middleware-slice variable spread into the call)
// marks the route as gated.
var gateFuncs = map[string]bool{
	"Require": true, "RequireAny": true, "RequireAll": true,
	"RequireAdmin": true, "RequireOwner": true,
	"RequireTeamAdmin": true, "RequireTeamOwner": true, "RequireTeamRole": true,
	"RequireMinTeamRole": true, "RequireRole": true, "RequirePermission": true,
	"RequireTenantRole": true, "RequireMinTenantRole": true, "RequirePlatformAdmin": true,
	// RequirePermissionOrSelf: the permission, or the path names the caller.
	"RequirePermissionOrSelf": true,
}

// routeAuthzAllowlist enumerates routes that are legitimately NOT permission-
// gated, each with the reason. Keys are "METHOD /path" (path as written in the
// source, with {param} placeholders). Adding a route here is a SECURITY-
// sensitive change — it declares a route public/self/machine-scoped.
var routeAuthzAllowlist = map[string]string{
	"POST /api/v1/client-errors": "public on purpose: the web console reports an error kind (fixed set, nothing else accepted or stored) for operator alerting, also before sign-in; per-address and overall rate limits",
	"GET /api/v1/version":        "any signed-in user (authMiddleware): build identity for Help > About; no tenant data, and kept off the public /health",
	// CI runner identity (RFC-051): machine credentials, not permissions.
	"POST /api/v1/ci/oidc/exchange":           "public: a CI provider's signed OIDC token is the credential, verified against the tenant's trust configurations; per-IP rate limit; every refusal is the same 401",
	"POST /api/v1/ci/runs/{id}/results":       "CI run token (AuthenticateRun): 15-minute token bound to one run on one repository asset; tenant from the token",
	"POST /api/v1/ci/runs/{id}/baseline-diff": "CI run token (AuthenticateRun): the run's repository only",
	"POST /api/v1/ci/runs/{id}/evaluate":      "CI run token (AuthenticateRun): the run's own verdict",
}

// allowlistPrefixes: groups of routes authenticated by a non-permission gate
// (public auth flow, sensor API-key, SCIM/MCP bearer, webhooks HMAC, or
// self-scoped /me + /users/me where the handler scopes to the caller).
var allowlistPrefixes = []struct{ prefix, reason string }{
	{"/api/v1/auth", "public auth flow / self-scoped (login, register, oauth, sso, saml, logout)"},
	{"/api/v1/users/me", "self-scoped: acts only on the authenticated user"},
	{"/api/v1/me/", "self-scoped: /me/* reads the caller's own perms/modules/roles"},
	{"/api/v1/notifications", "tenant+user-scoped in handler"},
	{"/api/v1/invitations/", "invitation token IS the authorization"},
	{"/api/v2/sensor", "sensor protocol v2 (RFC-026): only the sensor authenticator (SensorResultsV2Handler.Authenticate); tenant from the key, user JWT/cookie/oct_ refused"},
	{"/api/v1/platform/", "platform sensor API-key / self-scoped stats"},
	{"/api/v1/admin", "platform-admin realm: AdminAuthMiddleware (X-Admin-API-Key or console session cookie, RFC-022) + RequireRole; /admin/auth/login|mfa|logout are the public console login steps (rate-limited); not tenant-permission-gated"},
	{"/scim/v2", "SCIM per-tenant bearer token auth (routes live at /scim/v2, not /api/v1)"},
	{"/api/v1/scim", "SCIM per-tenant bearer token auth"},
	{"/api/v1/mcp", "MCP oct_ API-key auth"},
	{"/api/v1/webhooks/incoming", "inbound webhook HMAC per-tenant"},
	{"/api/v1/tenants", "base-auth + RequireMembership/RequireTeam* (role-gated, not permission-gated)"},
	{"/api/v1/module-presets", "auth-only catalog read (public preset list)"},
	{"/api/v1/validation/evidence", "sensor API-key auth"},
	{"/health", "public liveness"},
	{"/ready", "public readiness"},
	{"/metrics", "MetricsAuth bearer (fail-closed 404)"},
	{"/openapi.yaml", "public API spec"},
	{"/docs", "public API docs"},
	{"/api/v1/ws", "session (cookie or Bearer, no API keys) through the tenant chain: SSO enforcement, IP allowlist, RequireTenant, active membership (realtimeMiddlewares, RFC-045); socket bound to the session and closed on revocation or expiry; channels authorized per subscription by Hub.defaultAuthorize"},
}

// routePathArg resolves a route path argument: a string literal, or one of the
// protov2 path constants the sensor protocol mounts are named by.
func routePathArg(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		p, err := strconv.Unquote(v.Value)
		return p, err == nil
	case *ast.SelectorExpr:
		if pkg, ok := v.X.(*ast.Ident); ok && pkg.Name == "protov2" {
			p, ok := protov2.Paths[v.Sel.Name]
			return p, ok
		}
	}
	return "", false
}

type routeRec struct {
	method, path, pos string
	gated             bool
	// stepUp: requireStepUp() is in the route's or an enclosing group's
	// middleware arguments.
	stepUp bool
	// handlerType and handlerMethod name the handler argument, e.g.
	// TenantHandler and OffboardMember for tenantH.OffboardMember. The type
	// is resolved from the registering function's parameters; it is "" when
	// the receiver is a local variable.
	handlerType, handlerMethod string
}

// exprContainsCall reports whether e calls a function or method named name.
func exprContainsCall(e ast.Expr, name string) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if ce, ok := n.(*ast.CallExpr); ok {
			switch f := ce.Fun.(type) {
			case *ast.Ident:
				found = found || f.Name == name
			case *ast.SelectorExpr:
				found = found || f.Sel.Name == name
			}
		}
		return !found
	})
	return found
}

// paramTypes maps each parameter of fn to its type name without package or
// pointer: h *handler.TenantHandler gives "h": "TenantHandler".
func paramTypes(fn *ast.FuncDecl) map[string]string {
	out := map[string]string{}
	if fn.Type.Params == nil {
		return out
	}
	for _, field := range fn.Type.Params.List {
		t := field.Type
		if st, ok := t.(*ast.StarExpr); ok {
			t = st.X
		}
		var name string
		switch v := t.(type) {
		case *ast.Ident:
			name = v.Name
		case *ast.SelectorExpr:
			name = v.Sel.Name
		}
		for _, n := range field.Names {
			out[n.Name] = name
		}
	}
	return out
}

func exprContainsGate(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if ce, ok := n.(*ast.CallExpr); ok {
			if sel, ok := ce.Fun.(*ast.SelectorExpr); ok {
				// middleware.RequireX(...) — match on the method name; the
				// package qualifier is elided so a rename of the import alias
				// doesn't silently disable the check.
				if gateFuncs[sel.Sel.Name] {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// parseRoutes reads every route registered in internal/infra/http/routes from
// the source: method, full path (chi groups resolved), whether a permission
// gate applies, and where it is registered. Shared by the authz coverage gate
// and the data-surface classification gate.
//
//nolint:cyclop,gocognit // the AST walk, moved unchanged out of TestEveryRouteIsGatedOrAllowlisted
func parseRoutes(t *testing.T) []routeRec {
	t.Helper()
	root := repoRoot(t)
	routesDir := filepath.Join(root, "internal", "infra", "http", "routes")
	entries, err := os.ReadDir(routesDir)
	if err != nil {
		t.Fatalf("read routes dir: %v", err)
	}

	var routes []routeRec
	fset := token.NewFileSet()

	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".go") || strings.HasSuffix(ent.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(routesDir, ent.Name())
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", ent.Name(), perr)
		}

		// argGates reports whether any middleware arg (after the path+handler)
		// is/contains a gate, or spreads a known-gated middleware-slice var.
		argGates := func(args []ast.Expr, gatedVars map[string]bool) bool {
			for _, a := range args {
				if exprContainsGate(a) {
					return true
				}
				if id, ok := a.(*ast.Ident); ok && gatedVars[id.Name] {
					return true
				}
			}
			return false
		}

		// collectGatedVars gathers, for a block, the middleware-slice vars whose
		// assigned RHS contains a gate (so spreading them gates a route).
		collectGatedVars := func(block *ast.BlockStmt, parent map[string]bool) map[string]bool {
			gv := map[string]bool{}
			for k := range parent {
				gv[k] = true
			}
			ast.Inspect(block, func(m ast.Node) bool {
				if as, ok := m.(*ast.AssignStmt); ok {
					for i, lhs := range as.Lhs {
						if id, ok := lhs.(*ast.Ident); ok && i < len(as.Rhs) && exprContainsGate(as.Rhs[i]) {
							gv[id.Name] = true
						}
					}
				}
				return true
			})
			return gv
		}

		fileName := ent.Name()

		// process walks a block, resolving chi .Group(prefix, fn, mws...) nesting
		// so a route's recorded path is the FULL path and it inherits any gate
		// applied at the group level.
		stepUpArgs := func(args []ast.Expr) bool {
			for _, a := range args {
				if exprContainsCall(a, "requireStepUp") {
					return true
				}
			}
			return false
		}
		var params map[string]string // the enclosing FuncDecl's parameter types

		var process func(block *ast.BlockStmt, prefix string, inheritedGated, inheritedStepUp bool, gatedVars map[string]bool)
		process = func(block *ast.BlockStmt, prefix string, inheritedGated, inheritedStepUp bool, gatedVars map[string]bool) {
			gv := collectGatedVars(block, gatedVars)
			ast.Inspect(block, func(m ast.Node) bool {
				ce, ok := m.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				recv, ok := sel.X.(*ast.Ident)
				if !ok || (recv.Name != "r" && recv.Name != "router") {
					return true
				}

				// Nested group: X.Group("/prefix", func(r Router){...}, mws...)
				if sel.Sel.Name == "Group" && len(ce.Args) >= 2 {
					gp, ok := routePathArg(ce.Args[0])
					if !ok {
						return true
					}
					var body *ast.BlockStmt
					for _, a := range ce.Args[1:] {
						if fl, ok := a.(*ast.FuncLit); ok {
							body = fl.Body
							break
						}
					}
					groupGated := inheritedGated || argGates(ce.Args[2:], gv)
					groupStepUp := inheritedStepUp || stepUpArgs(ce.Args[2:])
					if body != nil {
						process(body, prefix+gp, groupGated, groupStepUp, gv)
					}
					return false // children handled by the recursive call
				}

				switch sel.Sel.Name {
				case "GET", "POST", "PUT", "PATCH", "DELETE":
				default:
					return true
				}
				if len(ce.Args) == 0 {
					return true
				}
				p, ok := routePathArg(ce.Args[0])
				if !ok {
					return true
				}
				rec := routeRec{
					method: sel.Sel.Name,
					path:   prefix + p,
					gated:  inheritedGated || argGates(ce.Args[1:], gv),
					stepUp: inheritedStepUp || stepUpArgs(ce.Args[1:]),
					pos:    fileName + ":" + itoa(fset.Position(ce.Pos()).Line),
				}
				if len(ce.Args) > 1 {
					if hs, ok := ce.Args[1].(*ast.SelectorExpr); ok {
						rec.handlerMethod = hs.Sel.Name
						if id, ok := hs.X.(*ast.Ident); ok {
							rec.handlerType = params[id.Name]
						}
					}
				}
				routes = append(routes, rec)
				return true
			})
		}

		ast.Inspect(f, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok && fn.Body != nil {
				params = paramTypes(fn)
				process(fn.Body, "", false, false, map[string]bool{})
			}
			return true
		})
	}

	if len(routes) < 100 {
		t.Fatalf("parsed only %d routes — the AST matcher is broken, not the code", len(routes))
	}
	return routes
}

func TestEveryRouteIsGatedOrAllowlisted(t *testing.T) {
	routes := parseRoutes(t)

	allowed := func(p string) bool {
		for _, ap := range allowlistPrefixes {
			if strings.HasPrefix(p, ap.prefix) {
				return true
			}
		}
		return false
	}

	var ungated []string
	gatedN := 0
	for _, r := range routes {
		if r.gated {
			gatedN++
			continue
		}
		if allowed(r.path) {
			continue
		}
		if _, ok := routeAuthzAllowlist[r.method+" "+r.path]; ok {
			continue
		}
		ungated = append(ungated, r.method+" "+r.path+"  ("+r.pos+")")
	}
	sort.Strings(ungated)

	t.Logf("routes parsed=%d gated=%d ungated-unallowlisted=%d", len(routes), gatedN, len(ungated))
	if len(ungated) > 0 {
		t.Errorf("routes with NO permission gate and NOT on the public/self/machine allowlist "+
			"— add a middleware.Require*, or (if intentionally public) add it to allowlistPrefixes/routeAuthzAllowlist with a reason:\n  %s",
			strings.Join(ungated, "\n  "))
	}
}
