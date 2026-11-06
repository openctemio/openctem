package middleware

// Organization suspension at the HTTP edge:
// docs/architecture/organization-suspension.md.

import (
	"errors"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// WriteOrganizationSuspended writes the refusal every credential path returns
// for a suspended organization: 403 ORGANIZATION_SUSPENDED with the member
// message (never the administrator's reason).
func WriteOrganizationSuspended(w http.ResponseWriter) {
	apierror.New(http.StatusForbidden, tenantdom.CodeOrganizationSuspended, tenantdom.MessageOrganizationSuspended).WriteJSON(w)
}

// WriteOrganizationGateError answers a request the access gate did not admit:
// the suspended refusal, or 503 when the status could not be read (the gate
// fails closed). A missing organization is a 401: the credential names an
// organization that no longer exists.
func WriteOrganizationGateError(w http.ResponseWriter, err error, log *logger.Logger) {
	switch {
	case errors.Is(err, tenantdom.ErrOrganizationSuspended):
		WriteOrganizationSuspended(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.Unauthorized("Authentication required").WriteJSON(w)
	default:
		if log != nil {
			log.Error("organization access gate", "error", err)
		}
		apierror.ServiceUnavailable("Please try again shortly").WriteJSON(w)
	}
}

// RequireActiveOrganization refuses a request whose organization (the tenant
// of its credential: a session token, an API key, an MCP token) is suspended.
// Requests without an organization pass: they reach nothing of one. It runs
// right after authentication on every chain that carries a tenant, before
// any route logic.
func RequireActiveOrganization(gate tenantdom.AccessGate, log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := GetTenantID(r.Context())
			if raw == "" {
				next.ServeHTTP(w, r)
				return
			}
			tid, err := shared.IDFromString(raw)
			if err != nil {
				apierror.Unauthorized("Authentication required").WriteJSON(w)
				return
			}
			if err := gate.CheckAccess(r.Context(), tid); err != nil {
				WriteOrganizationGateError(w, err, log)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireActiveOrganizationParam is RequireActiveOrganization for routes that
// name the organization in the path (/api/v1/tenants/{tenant}/...). resolve
// turns the path value (an id or a slug) into the organization id; it runs
// after the membership check, so only members learn the status.
func RequireActiveOrganizationParam(gate tenantdom.AccessGate, resolve func(r *http.Request) (shared.ID, bool), log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tid, ok := resolve(r)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			if err := gate.CheckAccess(r.Context(), tid); err != nil {
				WriteOrganizationGateError(w, err, log)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
