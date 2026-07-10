package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/openctemio/api/pkg/apierror"
	apikeydom "github.com/openctemio/api/pkg/domain/apikey"
	"github.com/openctemio/api/pkg/logger"
)

// APIKeyAuthenticator is the slice of the apikey service the middleware needs.
// Declared here (not imported from the app package) so the middleware depends
// only on the domain type. Satisfied by *apikey.Service.
type APIKeyAuthenticator interface {
	Authenticate(ctx context.Context, rawKey, ip string) (*apikeydom.APIKey, error)
}

// APIKeyAuth authenticates a request by a tenant-scoped `oct_` API key presented
// as `Authorization: Bearer oct_…` (or `X-API-Key: oct_…`). On success it seeds
// the same context keys the JWT path uses — tenant, optional user, scopes as
// permissions, and IsAdmin=false — so downstream handlers and the Require*
// permission gates work unchanged. Any failure is a generic 401 (the real reason
// is logged server-side only, to avoid key enumeration).
//
// It is the sole authenticator on the routes it guards: a request without a
// valid `oct_` key — including one bearing a JWT — is rejected with 401 rather
// than passed through, so a JWT is never mistakenly treated as an API key.
func APIKeyAuth(auth APIKeyAuthenticator, log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := extractAPIKeyToken(r)
			if raw == "" {
				apierror.Unauthorized("Invalid credentials").WriteJSON(w)
				return
			}

			key, err := auth.Authenticate(r.Context(), raw, getClientIP(r))
			if err != nil {
				log.Debug("api key auth failed", "reason", err.Error())
				apierror.Unauthorized("Invalid credentials").WriteJSON(w)
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, TenantIDKey, key.TenantID().String())
			if uid := key.UserID(); uid != nil {
				ctx = context.WithValue(ctx, UserIDKey, uid.String())
			}
			// Scopes act as the permission set; an API key is never an admin —
			// it is bounded to exactly the scopes it was minted with.
			ctx = context.WithValue(ctx, PermissionsKey, key.Scopes())
			ctx = context.WithValue(ctx, IsAdminKey, false)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractAPIKeyToken pulls an `oct_` key from the Authorization: Bearer header or
// the X-API-Key header. It deliberately never reads a query parameter (keys in
// URLs get logged by proxies) and returns "" for any non-`oct_` token so JWT
// bearer tokens fall through untouched.
func extractAPIKeyToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if rest, ok := strings.CutPrefix(h, "Bearer "); ok {
			tok := strings.TrimSpace(rest)
			if strings.HasPrefix(tok, "oct_") {
				return tok
			}
		}
	}
	if k := strings.TrimSpace(r.Header.Get("X-API-Key")); strings.HasPrefix(k, "oct_") {
		return k
	}
	return ""
}
