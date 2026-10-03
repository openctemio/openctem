package websocket

import (
	"context"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// maxConnectionLifetime caps how long one socket stays open whatever its
// credential's expiry. Gates that publish no revocation event (the
// organization IP allowlist, SSO enforcement, data-scope and group changes
// behind per-channel checks) are re-applied at least this often, because the
// client reconnects through the full upgrade chain. Up to
// maxLifetimeJitter is taken off per connection so sockets opened together
// (after a deploy) do not all reconnect in the same second.
const (
	maxConnectionLifetime = 15 * time.Minute
	maxLifetimeJitter     = time.Minute
)

// revocationCheckTimeout bounds the post-registration session check.
const revocationCheckTimeout = 3 * time.Second

// SessionRevocationChecker answers whether a session was signed out. It is
// the same store the HTTP auth middleware consults (RFC-045).
type SessionRevocationChecker interface {
	IsSessionRevoked(ctx context.Context, sessionID string) (bool, error)
}

// Handler handles WebSocket connections.
type Handler struct {
	hub      *Hub
	logger   *logger.Logger
	upgrader websocket.Upgrader
	sessions SessionRevocationChecker
	now      func() time.Time
}

// SetSessionRevocationChecker enables the post-registration session check,
// which closes a socket whose session was revoked while its upgrade was in
// flight (after the auth middleware passed it, before the hub registered it,
// so the revocation broadcast could not see it).
func (h *Handler) SetSessionRevocationChecker(c SessionRevocationChecker) {
	h.sessions = c
}

// NewHandler creates a new WebSocket handler.
//
// allowedOrigins is the CORS allow-list (cfg.CORS.AllowedOrigins); appEnv is
// cfg.App.Env. CheckOrigin rejects browser upgrades whose Origin is not in the
// list — without this, a permissive CheckOrigin combined with the cookie-auth
// fallback allows Cross-Site WebSocket Hijacking (a malicious page opening an
// authenticated socket as the victim).
func NewHandler(hub *Hub, log *logger.Logger, allowedOrigins []string, appEnv string) *Handler {
	allowed := make(map[string]bool, len(allowedOrigins))
	allowAll := false
	for _, o := range allowedOrigins {
		if o == "*" {
			// Never honour a wildcard in production (defense-in-depth;
			// config validation already rejects it there).
			if appEnv == config.EnvProduction {
				continue
			}
			allowAll = true
		}
		allowed[o] = true
	}

	return &Handler{
		hub:    hub,
		logger: log,
		now:    time.Now,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				// Non-browser clients (CLI/SDK) send no Origin and
				// authenticate via API key / single-use ticket, not
				// cookies, so they are not a CSWSH vector.
				if origin == "" {
					return true
				}
				if allowAll || allowed[origin] {
					return true
				}
				metrics.WSUpgradeRejectionsTotal.WithLabelValues("origin").Inc()
				log.Warn("websocket upgrade rejected: origin not allowed",
					"origin", origin, "remote_addr", r.RemoteAddr)
				return false
			},
		},
	}
}

// connectionDeadline is when a socket opened now must close: the credential's
// expiry, capped by the (jittered) maximum connection lifetime.
func (h *Handler) connectionDeadline(credentialExpiry time.Time) time.Time {
	now := h.now()
	jitter := time.Duration(rand.Int64N(int64(maxLifetimeJitter))) //nolint:gosec // spreads reconnects, not a secret
	deadline := now.Add(maxConnectionLifetime - jitter)
	if !credentialExpiry.IsZero() && credentialExpiry.Before(deadline) {
		deadline = credentialExpiry
	}
	return deadline
}

// ServeWS handles WebSocket upgrade requests (GET /api/v1/ws). The auth
// middleware in front of it has already authenticated the request and put
// the user, tenant, session and credential expiry in the context.
func (h *Handler) ServeWS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := middleware.GetUserID(ctx)
	tenantID := middleware.GetTenantID(ctx)

	if userID == "" || tenantID == "" {
		h.logger.Warn("websocket connection attempt without auth",
			"remote_addr", r.RemoteAddr,
		)
		metrics.WSUpgradeRejectionsTotal.WithLabelValues("no_identity").Inc()
		apierror.Unauthorized("authentication required").WriteJSON(w)
		return
	}

	identity := Identity{
		UserID:    userID,
		TenantID:  tenantID,
		SessionID: middleware.GetSessionID(ctx),
		ExpiresAt: h.connectionDeadline(middleware.GetCredentialExpiry(ctx)),
	}
	if !identity.ExpiresAt.After(h.now()) {
		// The credential expired between the middleware and here.
		apierror.Unauthorized("session expired").WriteJSON(w)
		return
	}

	// Upgrade to WebSocket
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("websocket upgrade failed",
			"user_id", userID,
			"error", err,
		)
		return
	}

	client := NewClient(h.hub, conn, identity, h.logger)

	// Register with the hub and wait until it has handled the request: the
	// checks below must see the client registered, so that a revocation
	// published from here on reaches it.
	h.hub.RegisterClient(client)
	<-client.registered
	if client.isDone() {
		return // refused (per-user connection cap) or hub stopped
	}

	metrics.WSConnectsTotal.Inc()
	h.logger.Info("websocket client connected",
		"client_id", client.ID,
		"user_id", userID,
		"tenant_id", tenantID,
		"session_id", identity.SessionID,
		"expires_at", identity.ExpiresAt,
		"remote_addr", r.RemoteAddr,
	)

	go client.WritePump()
	go client.ReadPump()

	// A session revoked after the auth middleware checked it but before the
	// registration above was missed by the revocation broadcast; the store
	// was written before the broadcast, so reading it now closes that gap.
	if h.sessions != nil && identity.SessionID != "" {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revocationCheckTimeout)
		revoked, err := h.sessions.IsSessionRevoked(cctx, identity.SessionID)
		cancel()
		switch {
		case err != nil:
			h.logger.Warn("websocket session revocation check failed; socket still ends at its deadline",
				"client_id", client.ID, "error", err)
		case revoked:
			client.closeWith(CloseUnauthorized, "session revoked", RevocationSessionRevoked)
			return
		}
	}

	client.armExpiry(h.now())
}

// GetHub returns the hub instance.
func (h *Handler) GetHub() *Hub {
	return h.hub
}
