package websocket

import (
	"net/http"

	"github.com/gorilla/websocket"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/logger"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// In production, check origin against allowed domains
		// For now, allow all origins
		return true
	},
}

// Handler handles WebSocket connections.
type Handler struct {
	hub    *Hub
	logger *logger.Logger
}

// NewHandler creates a new WebSocket handler.
func NewHandler(hub *Hub, log *logger.Logger) *Handler {
	return &Handler{
		hub:    hub,
		logger: log,
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
	conn, err := upgrader.Upgrade(w, r, nil)
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
