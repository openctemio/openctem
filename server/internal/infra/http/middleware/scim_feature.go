package middleware

import (
	"context"
	"net/http"
	"path"

	"github.com/openctemio/openctem/server/pkg/domain/limits"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// SCIMFeatureUsage is the feature check of SCIM provisioning.
type SCIMFeatureUsage interface {
	Usable(ctx context.Context, tenantID shared.ID, feature string) (bool, error)
}

type scimLeaveOnlyKey struct{}

// SCIMLeaveOnly reports whether the request passed the feature gate only
// because it removes access: the organization may not use SCIM now (or its
// limits could not be read), so a handler must refuse any change that grants
// or restores access (an active:true) and may only deactivate.
func SCIMLeaveOnly(ctx context.Context) bool {
	v, _ := ctx.Value(scimLeaveOnlyKey{}).(bool)
	return v
}

// scimLeaverRequest reports whether r targets one user (DELETE, PUT or PATCH
// on /Users/{id}): the requests an identity provider uses to deprovision.
func scimLeaverRequest(r *http.Request) bool {
	switch r.Method {
	case http.MethodDelete, http.MethodPut, http.MethodPatch:
	default:
		return false
	}
	users := path.Dir(r.URL.Path)
	return path.Base(users) == "Users" && path.Base(path.Dir(users)) == "v2"
}

// SCIMFeatureGate refuses the SCIM requests of an organization that may no
// longer use SCIM once its read-only grace ended (403), and fails closed
// when its limits cannot be read (503). It runs after SCIMAuth, which put the
// token's tenant in the context. A nil gate lets every request through.
//
// Deprovisioning is never gated: a disabled feature or an unreadable limit
// must not keep a leaver's access. A user DELETE, PUT or PATCH passes with
// SCIMLeaveOnly set, and the handler allows only the deactivating outcome.
func SCIMFeatureGate(gate SCIMFeatureUsage) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if gate == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tid, ok := SCIMTenantID(r.Context())
			if !ok {
				writeSCIMError(w, http.StatusUnauthorized, "invalid or revoked token")
				return
			}
			usable, err := gate.Usable(r.Context(), tid, limits.FeatureSCIM)
			if (err != nil || !usable) && scimLeaverRequest(r) {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), scimLeaveOnlyKey{}, true)))
				return
			}
			if err != nil {
				writeSCIMError(w, http.StatusServiceUnavailable, "the organization's limits could not be checked; try again later")
				return
			}
			if !usable {
				writeSCIMError(w, http.StatusForbidden, "SCIM provisioning is not available for this organization")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SCIMAuthWithFeature authenticates the SCIM token, then applies the feature
// check of SCIM provisioning.
func SCIMAuthWithFeature(authn SCIMTokenAuthenticator, gate SCIMFeatureUsage) func(http.Handler) http.Handler {
	auth, feature := SCIMAuth(authn), SCIMFeatureGate(gate)
	return func(next http.Handler) http.Handler { return auth(feature(next)) }
}
