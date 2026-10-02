package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/logger"
)

// F-8: Middleware that authenticates WebSocket upgrade requests via a
// single-use opaque ticket instead of a short-lived JWT in the URL.
//
// The handler at /auth/ws-token issues the ticket. The client immediately
// passes it as ?ticket=<64hex> on the WebSocket upgrade. This middleware
// atomically redeems the ticket via Redis (GETDEL) and, on success, sets
// the standard user/tenant context keys so downstream WS logic works
// unchanged.
//
// Unlike UnifiedAuth, this middleware MUST NOT fall back to JWT query-param
// auth — the whole point is to eliminate replay risk. If the ticket is
// missing, malformed, or already consumed, the request is rejected.

// WSTicketRedeemer is the minimal surface needed from the ticket service.
type WSTicketRedeemer interface {
	RedeemTicket(ctx context.Context, ticket string) (*app.WSTicketClaims, error)
}

// WSTicketAuth returns middleware enforcing single-use ticket auth.
func WSTicketAuth(svc WSTicketRedeemer, log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ticket := r.URL.Query().Get("ticket")
			if ticket == "" {
				log.Warn("ws upgrade rejected: missing ticket", "remote_ip", r.RemoteAddr)
				apierror.Unauthorized("missing ticket").WriteJSON(w)
				return
			}

			claims, err := svc.RedeemTicket(r.Context(), ticket)
			if err != nil {
				// Always return the same error on all failure modes — do
				// not distinguish "not found" vs "malformed" to the client.
				if !errors.Is(err, app.ErrTicketNotFound) {
					log.Warn("ws ticket redeem failed", "error", err, "remote_ip", r.RemoteAddr)
				}
				apierror.Unauthorized("invalid or expired ticket").WriteJSON(w)
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, UserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, TenantIDKey, claims.TenantID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
