package middleware

import (
	"net/http"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// RequirePermissionOrSelf requires perm, except when the path parameter param
// names the signed-in user themselves. It is for "my own X" reads that sit on
// an admin-only resource, such as GET /audit-logs/user/{id}: the organization
// audit log is owner/admin only, but everyone may read their own activity
// (the /account/activity page).
//
// The self branch is for a user session only. An `oct_` API key request is
// bounded by the key's scopes like any other, so it needs perm.
func RequirePermissionOrSelf(perm permission.Permission, param string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if HasPermission(ctx, perm.String()) {
				next.ServeHTTP(w, r)
				return
			}
			target := r.PathValue(param)
			if target != "" && GetAPIKeyID(ctx) == "" {
				self := GetLocalUserID(ctx)
				if (!self.IsZero() && self.String() == target) || (self.IsZero() && GetUserID(ctx) == target) {
					next.ServeHTTP(w, r)
					return
				}
			}
			permissionDenied(perm.String()).WriteJSON(w)
		})
	}
}
