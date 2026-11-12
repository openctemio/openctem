package extensionhost

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/openctemio/openctem/server/pkg/domain/limits"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	ext "github.com/openctemio/openctem/server/pkg/extension"
)

// Route is an extension route the core accepted, ready to mount at
// /api/v1<Path> behind the organization chain, the permission and the
// grant.
type Route struct {
	Method     string
	Path       string
	Permission permission.Permission
	Grant      limits.GrantKey
	Handler    http.Handler
}

var (
	routePath = regexp.MustCompile(`^(/([a-z0-9][a-z0-9-]*|\{[a-z][a-zA-Z0-9_]*\}))+$`)
	grantKey  = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)
	methods   = map[string]bool{http.MethodGet: true, http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true}
	// reservedPrefixes are path roots an extension may not use: the core's
	// own planes, authentication and credential surfaces, and the roots the
	// API-key policy treats as a person's own (middleware.APIKeyDeniedPrefixes).
	reservedPrefixes = []string{
		"/admin", "/auth", "/internal", "/sensor", "/scim", "/health", "/version", "/me", "/users",
		"/platform", "/tenants", "/invitations", "/oauth", "/mcp", "/mcp-access", "/ci", "/ws",
		"/api-keys", "/scim-tokens", "/service-accounts", "/notifications",
	}
)

// router collects and validates an extension's routes.
type router struct {
	known  map[string]bool
	seen   map[string]bool
	routes []Route
}

func (r *router) Handle(rt ext.Route) error {
	switch {
	case !methods[rt.Method]:
		return fmt.Errorf("route %s %s: method not allowed", rt.Method, rt.Path)
	case !routePath.MatchString(rt.Path) || strings.Contains(rt.Path, "//"):
		return fmt.Errorf("route %s %q: invalid path", rt.Method, rt.Path)
	case rt.Permission == "":
		return fmt.Errorf("route %s %s: a permission is required", rt.Method, rt.Path)
	case !r.known[rt.Permission]:
		return fmt.Errorf("route %s %s: %q is not a core permission", rt.Method, rt.Path, rt.Permission)
	case rt.Grant == "" || !grantKey.MatchString(string(rt.Grant)):
		return fmt.Errorf("route %s %s: a valid grant key is required", rt.Method, rt.Path)
	case rt.Handler == nil:
		return fmt.Errorf("route %s %s: no handler", rt.Method, rt.Path)
	}
	for _, p := range reservedPrefixes {
		if rt.Path == p || strings.HasPrefix(rt.Path, p+"/") {
			return fmt.Errorf("route %s %s: %s is reserved for the core", rt.Method, rt.Path, p)
		}
	}
	k := rt.Method + " " + rt.Path
	if r.seen[k] {
		return fmt.Errorf("route %s: registered twice", k)
	}
	r.seen[k] = true
	r.routes = append(r.routes, Route{Method: rt.Method, Path: rt.Path, Permission: permission.Permission(rt.Permission), Grant: rt.Grant, Handler: rt.Handler})
	return nil
}
