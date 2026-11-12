package routes

// Routes of a build's extension (pkg/extension, docs/development/editions.md).
// Each one runs behind the same chain as a core
// organization route, then the route's core permission, then its grant;
// only then does the extension's handler see the request, with the caller
// from the credential in its context.

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/openctemio/openctem/server/internal/extensionhost"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/limits"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	ext "github.com/openctemio/openctem/server/pkg/extension"
)

// GrantChecker answers whether a grant is on for an organization
// (entitlement.Service).
type GrantChecker interface {
	RequireAddon(ctx context.Context, tenantID shared.ID, key limits.GrantKey) error
}

// registerExtensionRoutes mounts the extension's routes at /api/v1<path>.
// A route that would replace a core route, or with no grant checker to
// enforce its grant, stops the start.
// chain is the organization chain (buildTokenTenantMiddlewares).
func registerExtensionRoutes(router Router, rs []extensionhost.Route, grants GrantChecker, chain []Middleware) {
	if len(rs) == 0 {
		return
	}
	if grants == nil {
		panic("extension routes: no grant checker; a grant-gated route cannot be served")
	}
	existing := map[string]bool{}
	_ = router.Walk(func(method, path string, _ http.Handler) error {
		existing[method+" "+path] = true
		return nil
	})
	for _, rt := range rs {
		full := "/api/v1" + rt.Path
		if existing[rt.Method+" "+full] {
			panic(fmt.Sprintf("extension route %s %s replaces a core route", rt.Method, full))
		}
		mws := append(append([]Middleware(nil), chain...), middleware.Require(rt.Permission), requireGrant(grants, rt.Grant))
		h := withCaller(rt.Handler).ServeHTTP
		switch rt.Method {
		case http.MethodGet:
			router.GET(full, h, mws...)
		case http.MethodPost:
			router.POST(full, h, mws...)
		case http.MethodPut:
			router.PUT(full, h, mws...)
		case http.MethodPatch:
			router.PATCH(full, h, mws...)
		case http.MethodDelete:
			router.DELETE(full, h, mws...)
		}
	}
}

// requireGrant refuses the request unless grant key is on for the caller's
// organization (fail closed: a provider error refuses too).
func requireGrant(g GrantChecker, key limits.GrantKey) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenantID, ok := middleware.GetTenantIDFromContext(r.Context())
			if !ok {
				apierror.Unauthorized("Sign in to continue.").WriteJSON(w)
				return
			}
			if err := g.RequireAddon(r.Context(), tenantID, key); err != nil {
				code := limits.CodeAddonNotLicensed
				var gr *limits.ErrGrantRequired
				if errors.As(err, &gr) {
					code = gr.Code()
				}
				apierror.New(http.StatusForbidden, apierror.Code(code), "This feature is not available for your organization.").WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// withCaller hands the extension handler the authenticated caller.
func withCaller(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := middleware.GetTenantIDFromContext(r.Context())
		if !ok {
			apierror.Unauthorized("Sign in to continue.").WriteJSON(w)
			return
		}
		c := ext.Caller{TenantID: tenantID, UserID: middleware.GetLocalUserID(r.Context())}
		next.ServeHTTP(w, r.WithContext(ext.WithCaller(r.Context(), c)))
	})
}
