package middleware

import (
	"context"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SCIMFeatureUsage is the feature check of SCIM provisioning.
type SCIMFeatureUsage interface {
	Usable(ctx context.Context, tenantID shared.ID, feature string) (bool, error)
}

// SCIMFeatureGate refuses the SCIM requests of an organization that may no
// longer use SCIM once its read-only grace ended (403), and fails closed
// when its limits cannot be read (503). It runs after SCIMAuth, which put the
// token's tenant in the context. A nil gate lets every request through.
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
