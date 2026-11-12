package middleware

import (
	"net/http"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PermissionCheckContext records the caller's permission check
// (HasPermission on this request's context) for the application layer
// (shared.CallerHasPermission), so a rule decided in a service, such as a
// lifecycle move that needs a permission, reads the same fresh permissions
// as the route gates. Mount it after the permission sync.
func PermissionCheckContext() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			next.ServeHTTP(w, r.WithContext(shared.WithPermissionCheck(ctx, func(p string) bool {
				return HasPermission(ctx, p)
			})))
		})
	}
}
