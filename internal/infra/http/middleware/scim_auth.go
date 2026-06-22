package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/openctemio/api/pkg/domain/scimtoken"
	"github.com/openctemio/api/pkg/domain/shared"
)

type scimCtxKey string

const scimTenantCtxKey scimCtxKey = "scim_tenant_id"

// SCIMTokenAuthenticator validates a presented SCIM bearer token. Implemented by
// scim.TokenService.
type SCIMTokenAuthenticator interface {
	Authenticate(ctx context.Context, plaintext string) (*scimtoken.ScimToken, error)
}

// SCIMAuth authenticates SCIM requests via a per-tenant bearer token and puts
// the resolved tenant id in the request context. One token = one tenant, so all
// downstream SCIM handlers are tenant-isolated by construction.
func SCIMAuth(authn SCIMTokenAuthenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearer(r)
			if token == "" {
				writeSCIMError(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			tok, err := authn.Authenticate(r.Context(), token)
			if err != nil {
				writeSCIMError(w, http.StatusUnauthorized, "invalid or revoked token")
				return
			}
			ctx := context.WithValue(r.Context(), scimTenantCtxKey, tok.TenantID())
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SCIMTenantID returns the tenant id resolved by SCIMAuth.
func SCIMTenantID(ctx context.Context) (shared.ID, bool) {
	id, ok := ctx.Value(scimTenantCtxKey).(shared.ID)
	return id, ok
}

func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	parts := strings.SplitN(h, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

// writeSCIMError emits a minimal RFC-7644 §3.12 error envelope. Kept here (not
// the handler package) to avoid an import cycle; the handler has a richer one.
func writeSCIMError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"` +
		itoa(status) + `","detail":"` + jsonEscape(detail) + `"}`))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func jsonEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}
