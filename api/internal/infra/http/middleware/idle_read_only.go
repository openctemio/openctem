package middleware

import (
	"context"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// IdleReadOnlyChecker says whether an organization is read-only because
// nobody signed in to it for 90 days (lifecycle.Service.ReadOnly).
type IdleReadOnlyChecker interface {
	ReadOnly(ctx context.Context, tenantID shared.ID) bool
}

// CodeWorkspaceReadOnly is the error code of a change refused because the
// idle Free organization is read-only.
const CodeWorkspaceReadOnly = "WORKSPACE_READ_ONLY"

// IdleReadOnly refuses changes (any method but GET, HEAD and OPTIONS) to an
// organization that is read-only after 90 days without a sign-in
// (docs/architecture/idle-workspaces.md). Reads keep working, and a sign-in
// by any member lifts it at once. Requests without a tenant in the token
// pass through.
func IdleReadOnly(checker IdleReadOnlyChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}
			tid, err := shared.IDFromString(GetTenantID(r.Context()))
			if err != nil || checker == nil || !checker.ReadOnly(r.Context(), tid) {
				next.ServeHTTP(w, r)
				return
			}
			apierror.New(http.StatusForbidden, CodeWorkspaceReadOnly,
				"This organization is read-only because nobody signed in to it for 90 days. Sign in again to make changes.").WriteJSON(w)
		})
	}
}
