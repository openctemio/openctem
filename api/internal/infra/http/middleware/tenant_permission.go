package middleware

import (
	"context"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// TenantPermissionChecker answers whether a user holds a permission in a
// tenant, from their roles in that tenant. PermissionCacheService satisfies it.
type TenantPermissionChecker interface {
	HasPermission(ctx context.Context, tenantID, userID, permission string) (bool, error)
}

// RequireTenantPermission gates a /api/v1/tenants/{tenant}/... route on a
// permission held in the tenant named by the path.
//
// Require reads the permissions resolved for the credential's tenant, which on
// these routes may be a different tenant than the one in the path, so it must
// not be used here. This middleware resolves the caller's permissions in the
// path tenant instead (TenantContext and RequireMembership must run first).
//
// The tenant owner passes, as with Require's owner bypass: the owner role
// holds every permission. Everyone else needs the permission from their roles
// in that tenant. A lookup error refuses the request.
//
// A nil checker skips the check, leaving the route's other gates (membership,
// RequireTeamAdmin/Owner) in force; the server always wires one.
func RequireTenantPermission(checker TenantPermissionChecker, permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if checker == nil {
				next.ServeHTTP(w, r)
				return
			}
			ctx := r.Context()
			tenantID := GetTeamID(ctx)
			role := GetTeamRole(ctx)
			if tenantID.IsZero() || role == "" {
				apierror.Forbidden("Membership required").WriteJSON(w)
				return
			}
			if role == tenant.RoleOwner {
				next.ServeHTTP(w, r)
				return
			}
			userID := GetLocalUserID(ctx)
			if userID.IsZero() {
				apierror.Forbidden("Membership required").WriteJSON(w)
				return
			}
			ok, err := checker.HasPermission(ctx, tenantID.String(), userID.String(), permission)
			if err != nil {
				apierror.InternalServerError("Permission check failed").WriteJSON(w)
				return
			}
			if !ok {
				apierror.Forbidden("Insufficient permissions").WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
