package websocket

import (
	"context"
	"strings"
	"sync"

	"github.com/openctemio/api/pkg/logger"
)

// Hub configuration constants
const (
	// Max connections per user for rate limiting
	maxConnectionsPerUser = 10

	// Broadcast buffer size
	broadcastBufferSize = 256
)

// Hub maintains the set of active clients and broadcasts messages to them.
type Hub struct {
	// Registered clients
	clients map[*Client]bool

	// User connection counts for rate limiting
	userConnCounts map[string]int

	// Channel subscriptions: channel -> set of clients
	channels map[string]map[*Client]bool

	// Inbound messages for broadcast
	broadcast chan *BroadcastMessage

	// Register requests from clients
	register chan *Client

	// Unregister requests from clients
	unregister chan *Client

	// Logger
	logger *logger.Logger

	// Authorization function
	authorizeFn AuthorizeFunc

	// Mutex for concurrent access
	mu sync.RWMutex
}

// BroadcastMessage represents a message to broadcast to a channel.
type BroadcastMessage struct {
	Channel  string
	Message  *Message
	TenantID string // If set, only clients in this tenant receive the message
}

// AuthorizeFunc is a function that checks if a client can subscribe to a channel.
// Returns true if authorized, false otherwise.
type AuthorizeFunc func(client *Client, channel string) bool

// NewHub creates a new Hub.
func NewHub(log *logger.Logger) *Hub {
	return &Hub{
		clients:        make(map[*Client]bool),
		userConnCounts: make(map[string]int),
		channels:       make(map[string]map[*Client]bool),
		broadcast:      make(chan *BroadcastMessage, broadcastBufferSize),
		register:       make(chan *Client),
		unregister:     make(chan *Client),
		logger:         log,
		authorizeFn:    defaultAuthorize,
	}
}

// defaultAuthorize is the default authorization function.
// It checks tenant isolation for channel subscriptions.
func defaultAuthorize(client *Client, channel string) bool {
	channelType, id := ParseChannel(channel)

	switch channelType {
	case ChannelTypeFinding:
		// Finding channel requires access to the finding
		// For now, allow any authenticated user in the same tenant
		// In production, should check if user has access to this finding
		return client.TenantID != "" && id != ""

	case ChannelTypeScan:
		// Scan channel requires tenant access
		return client.TenantID != "" && id != ""

	case ChannelTypeTriage:
		// Triage channel requires tenant access (id = finding_id)
		return client.TenantID != "" && id != ""

	case ChannelTypeTenant:
		// Tenant channel: client must be in the tenant
		return client.TenantID == id

	case ChannelTypeNotification:
		// Notification channel: client must be in the tenant
		return client.TenantID == id

	default:
		// Unknown channel type, deny by default
		return false
	}
}

// SetAuthorizeFunc sets a custom authorization function.
func (h *Hub) SetAuthorizeFunc(fn AuthorizeFunc) {
	h.authorizeFn = fn
}

// Run starts the hub's main loop.
func (h *Hub) Run(ctx context.Context) {
	h.logger.Info("websocket hub started")

	for {
		select {
		case <-ctx.Done():
			h.logger.Info("websocket hub stopping")
			h.closeAllClients()
			return

		case client := <-h.register:
			h.mu.Lock()
			// Rate limit: check connections per user
			if client.UserID != "" {
				count := h.userConnCounts[client.UserID]
				if count >= maxConnectionsPerUser {
					h.mu.Unlock()
					h.logger.Warn("connection limit exceeded",
						"user_id", client.UserID,
						"current", count,
						"max", maxConnectionsPerUser,
					)
					client.Close()
					continue
				}
				h.userConnCounts[client.UserID] = count + 1
			}
			h.clients[client] = true
			h.mu.Unlock()

			h.logger.Debug("client registered",
				"client_id", client.ID,
				"user_id", client.UserID,
				"tenant_id", client.TenantID,
			)

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				h.removeClientFromAllChannels(client)
				// Decrement user connection count
				if client.UserID != "" {
					if count := h.userConnCounts[client.UserID]; count > 0 {
						h.userConnCounts[client.UserID] = count - 1
						if h.userConnCounts[client.UserID] == 0 {
							delete(h.userConnCounts, client.UserID)
						}
					}
				}
			}
			h.mu.Unlock()

			h.logger.Debug("client unregistered",
				"client_id", client.ID,
				"user_id", client.UserID,
			)

		case msg := <-h.broadcast:
			h.broadcastToChannel(msg)
		}
	}
}

// RegisterClient registers a new client.
func (h *Hub) RegisterClient(client *Client) {
	h.register <- client
}

// UnregisterClient unregisters a client.
func (h *Hub) UnregisterClient(client *Client) {
	h.unregister <- client
}

// Broadcast sends a message to all clients subscribed to a channel.
func (h *Hub) Broadcast(channel string, msg *Message, tenantID string) {
	h.broadcast <- &BroadcastMessage{
		Channel:  channel,
		Message:  msg,
		TenantID: tenantID,
	}
}

// BroadcastEvent is a convenience method to broadcast an event to a channel.
func (h *Hub) BroadcastEvent(channel string, data any, tenantID string) {
	msg := NewMessage(MessageTypeEvent).
		WithChannel(channel).
		WithData(data)
	h.Broadcast(channel, msg, tenantID)
}

// subscribeToChannel adds a client to a channel (internal use).
func (h *Hub) subscribeToChannel(client *Client, channel string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.channels[channel] == nil {
		h.channels[channel] = make(map[*Client]bool)
	}
	h.channels[channel][client] = true
}

// unsubscribeFromChannel removes a client from a channel (internal use).
func (h *Hub) unsubscribeFromChannel(client *Client, channel string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if clients, ok := h.channels[channel]; ok {
		delete(clients, client)
		if len(clients) == 0 {
			delete(h.channels, channel)
		}
	}
}

// authorizeSubscription checks if a client can subscribe to a channel.
func (h *Hub) authorizeSubscription(client *Client, channel string) bool {
	if h.authorizeFn == nil {
		return true
	}
	return h.authorizeFn(client, channel)
}

// broadcastToChannel sends a message to all clients subscribed to a channel.
func (h *Hub) broadcastToChannel(msg *BroadcastMessage) {
	h.mu.RLock()
	clients, ok := h.channels[msg.Channel]
	if !ok || len(clients) == 0 {
		h.mu.RUnlock()
		return
	}

	// Copy client list to avoid holding lock during send
	clientList := make([]*Client, 0, len(clients))
	for client := range clients {
		// Filter by tenant if specified
		if msg.TenantID != "" && client.TenantID != msg.TenantID {
			continue
		}
		clientList = append(clientList, client)
	}
	h.mu.RUnlock()

	// Send to all clients
	for _, client := range clientList {
		if err := client.SendMessage(msg.Message); err != nil {
			h.logger.Debug("failed to send message to client",
				"client_id", client.ID,
				"channel", msg.Channel,
				"error", err,
			)
		}
	}

	h.logger.Debug("broadcast message",
		"channel", msg.Channel,
		"recipients", len(clientList),
	)
}

// removeClientFromAllChannels removes a client from all channel subscriptions.
func (h *Hub) removeClientFromAllChannels(client *Client) {
	for channel, clients := range h.channels {
		delete(clients, client)
		if len(clients) == 0 {
			delete(h.channels, channel)
		}
	}
}

// closeAllClients closes all client connections.
func (h *Hub) closeAllClients() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for client := range h.clients {
		client.Close()
		delete(h.clients, client)
	}
	h.channels = make(map[string]map[*Client]bool)
}

// GetStats returns hub statistics.
func (h *Hub) GetStats() HubStats {
	h.mu.RLock()
	defer h.mu.RUnlock()

	channelStats := make(map[string]int)
	for channel, clients := range h.channels {
		channelStats[channel] = len(clients)
	}

	return HubStats{
		TotalClients:   len(h.clients),
		TotalChannels:  len(h.channels),
		ChannelClients: channelStats,
	}
}

// HubStats contains hub statistics.
type HubStats struct {
	TotalClients   int            `json:"total_clients"`
	TotalChannels  int            `json:"total_channels"`
	ChannelClients map[string]int `json:"channel_clients"`
}

// GetClientsByTenant returns all clients for a tenant.
func (h *Hub) GetClientsByTenant(tenantID string) []*Client {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var clients []*Client
	for client := range h.clients {
		if client.TenantID == tenantID {
			clients = append(clients, client)
		}
	}
	return clients
}

// BroadcastToTenant sends a message to all clients in a tenant.
func (h *Hub) BroadcastToTenant(tenantID string, msg *Message) {
	clients := h.GetClientsByTenant(tenantID)
	for _, client := range clients {
		_ = client.SendMessage(msg)
	}
}

// GetChannelsByPrefix returns all channels matching a prefix.
func (h *Hub) GetChannelsByPrefix(prefix string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var channels []string
	for channel := range h.channels {
		if strings.HasPrefix(channel, prefix) {
			channels = append(channels, channel)
		}
	}
	return channels
}
