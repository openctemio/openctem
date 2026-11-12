package extension

import (
	"context"
	"net/http"

	"github.com/openctemio/openctem/server/pkg/domain/limits"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Route is one HTTP route of an extension. The core mounts it at
// /api/v1<Path> behind the same chain as a core organization route:
// authentication (session or API key), the caller's organization from the
// credential (never from the request), active membership, CSRF, the
// permission check and the grant check. A route cannot exist without a
// permission and a grant key.
type Route struct {
	// Method is GET, POST, PUT, PATCH or DELETE.
	Method string
	// Path is below /api/v1: lower-case segments, digits, dashes and
	// {param} placeholders, starting with "/" (e.g. "/org-trusts/{id}").
	Path string
	// Permission is a core permission id (pkg/domain/permission) the
	// caller must hold.
	Permission string
	// Grant is the grant key that must be on for the caller's organization.
	Grant limits.GrantKey
	// Handler serves the request. The caller is in the request context
	// (CallerFrom).
	Handler http.Handler
}

// Router registers routes. Handle returns an error for a route the core
// refuses (missing permission or grant, unknown permission, invalid method
// or path, a path registered twice).
type Router interface {
	Handle(r Route) error
}

// Caller is the authenticated principal of an extension route.
type Caller struct {
	// TenantID is the caller's organization, from the credential.
	TenantID shared.ID
	// UserID is the signed-in user (zero for an API key with no user).
	UserID shared.ID
}

type callerKey struct{}

// WithCaller returns ctx carrying c. The core sets it for every extension
// route; tests of an extension use it to build requests.
func WithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerFrom returns the caller of an extension route, or false outside
// one. A handler that gets false answers 401 and does nothing else.
func CallerFrom(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(Caller)
	if !ok || c.TenantID.IsZero() {
		return Caller{}, false
	}
	return c, true
}
