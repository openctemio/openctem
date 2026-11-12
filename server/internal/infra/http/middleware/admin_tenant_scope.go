package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AdminTenantParam is the path parameter naming the organization an admin route
// acts on. It is not "id" because the reused tenant handlers use "id" for their
// own resource (identity provider, verified domain).
const AdminTenantParam = "tenantId"

// AdminTenantScope lets a platform admin (already authenticated by
// AdminAuthMiddleware) run a tenant-scoped handler against the organization in
// the path, so the admin console reuses the tenant SSO handlers instead of
// duplicating them (RFC-022 Phase 2).
//
// It checks the organization exists, sets it as the request's tenant, and
// clears the user id: an admin is not a row in users, and the reused handlers
// write the context user id into columns that reference users(id) (e.g.
// tenant_identity_providers.created_by). The admin action is recorded in
// admin_audit_logs instead.
func AdminTenantScope(exists func(ctx context.Context, tenantID shared.ID) error) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := shared.IDFromString(r.PathValue(AdminTenantParam))
			if err != nil {
				apierror.BadRequest("invalid organization id").WriteJSON(w)
				return
			}
			if err := exists(r.Context(), id); err != nil {
				if errors.Is(err, shared.ErrNotFound) {
					apierror.NotFound("organization").WriteJSON(w)
					return
				}
				apierror.InternalError(err).WriteJSON(w)
				return
			}
			ctx := context.WithValue(r.Context(), TenantIDKey, id.String())
			ctx = context.WithValue(ctx, UserIDKey, "")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
