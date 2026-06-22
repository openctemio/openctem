package websocket

import (
	"net/http"

	"github.com/gorilla/websocket"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/logger"
)

// Handler handles WebSocket connections.
type Handler struct {
	hub      *Hub
	logger   *logger.Logger
	upgrader websocket.Upgrader
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
				return allowAll || allowed[origin]
			},
		},
	}
}

// ServeWS handles WebSocket upgrade requests.
// GET /api/v1/ws?token=xxx
func (h *Handler) ServeWS(w http.ResponseWriter, r *http.Request) {
	// Get user and tenant from context (set by auth middleware)
	ctx := r.Context()
	userID := middleware.GetUserID(ctx)
	tenantID := middleware.GetTenantID(ctx)

	if userID == "" || tenantID == "" {
		h.logger.Warn("websocket connection attempt without auth",
			"remote_addr", r.RemoteAddr,
		)
		apierror.Unauthorized("authentication required").WriteJSON(w)
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

	// Create client
	client := NewClient(h.hub, conn, userID, tenantID, h.logger)

	// Register with hub
	h.hub.RegisterClient(client)

	h.logger.Info("websocket client connected",
		"client_id", client.ID,
		"user_id", userID,
		"tenant_id", tenantID,
		"remote_addr", r.RemoteAddr,
	)

	// Start read/write pumps
	go client.WritePump()
	go client.ReadPump()
}

// GetHub returns the hub instance.
func (h *Handler) GetHub() *Hub {
	return h.hub
}
