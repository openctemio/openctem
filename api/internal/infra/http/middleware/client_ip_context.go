package middleware

import (
	"net/http"

	"github.com/openctemio/openctem/api/pkg/httpsec"
)

// ClientIPContext stores the request's client IP (pkg/httpsec: the TCP peer,
// or the forwarded address only when the peer is a trusted proxy) on the
// request context, for services that record where an action came from
// without a request in hand (sign-up events).
func ClientIPContext() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(httpsec.WithClientIP(r.Context(), getClientIP(r))))
		})
	}
}
