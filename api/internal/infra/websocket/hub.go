package websocket

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/internal/metrics"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
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

	// Permission/membership resolver for permission-scoped channels.
	access ChannelAccessChecker

	// Mutex for concurrent access
	mu sync.RWMutex

	// F-7: Cross-pod publisher. When set, Broadcast publishes through
	// this sink (Redis pubsub) instead of delivering only in-process.
	// The fan-in subscriber on each pod receives the payload and pushes
	// it to h.broadcast for local delivery.
	publisher BroadcastPublisher

	// Cross-pod revocation bus (RFC-045). When set, RevokeSession and
	// RevokeAccess publish through it so every pod closes its own matching
	// sockets; otherwise they apply to this pod only.
	revocations RevocationPublisher

	// done is closed when Run exits. Every send onto the hub's channels selects
	// on it so callers (HTTP handlers broadcasting, ReadPump/WritePump defers
	// unregistering) cannot block forever once the hub stopped — an unguarded
	// send after shutdown would stall graceful server shutdown.
	done chan struct{}
}

// BroadcastPublisher is the minimum surface a cross-pod transport must
// provide. The redis-pubsub implementation lives in bridge.go.
type BroadcastPublisher interface {
	Publish(ctx context.Context, msg *BroadcastMessage) error
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

// ChannelAccessChecker answers the permission and membership questions that
// decide who may watch a permission-scoped channel. The server wires it to the
// RBAC and group services; without one, those channels are refused.
type ChannelAccessChecker interface {
	HasPermission(ctx context.Context, tenantID, userID, permission string) (bool, error)
	IsGroupMember(ctx context.Context, tenantID, groupID, userID string) (bool, error)
	// CanSeeFinding reports whether the finding exists in the tenant and is
	// inside the user's Layer 2 data scope (admins and unrestricted members
	// see every finding of their tenant).
	CanSeeFinding(ctx context.Context, tenantID, userID, findingID string) (bool, error)
}

// channelAccessTimeout bounds the permission lookup made on a subscribe.
const channelAccessTimeout = 5 * time.Second

// NewHub creates a new Hub.
func NewHub(log *logger.Logger) *Hub {
	h := &Hub{
		clients:        make(map[*Client]bool),
		userConnCounts: make(map[string]int),
		channels:       make(map[string]map[*Client]bool),
		broadcast:      make(chan *BroadcastMessage, broadcastBufferSize),
		register:       make(chan *Client),
		unregister:     make(chan *Client),
		logger:         log,
		done:           make(chan struct{}),
	}
	h.authorizeFn = h.defaultAuthorize
	return h
}

// SetChannelAccessChecker attaches the permission/membership resolver used to
// authorize finding, triage, scan and group channels. Must be called before
// clients connect.
func (h *Hub) SetChannelAccessChecker(c ChannelAccessChecker) {
	h.access = c
}

// defaultAuthorize decides whether a client may subscribe to a channel. The
// client names the channel, so every rule here is checked against the
// identity the connection authenticated as, never against the channel text
// alone. Unknown channel types are refused.
func (h *Hub) defaultAuthorize(client *Client, channel string) bool {
	if client.TenantID == "" || client.UserID == "" {
		return false
	}
	channelType, id := ParseChannel(channel)
	if id == "" {
		return false
	}

	switch channelType {
	case ChannelTypeUser:
		// A user's own notifications: user:{tenant}:{user}. Exactly the
		// authenticated user in the authenticated tenant, nobody else.
		return channel == notificationdom.UserChannel(client.TenantID, client.UserID)

	case ChannelTypeTenant:
		// Tenant-wide events meant for every member (module toggles).
		return client.TenantID == id

	case ChannelTypeFinding, ChannelTypeTriage:
		// Finding activity (actor, changes) and AI triage progress: the same
		// permission the finding endpoints require, and the finding must be
		// in the user's data scope (GET /findings/{id} would 404 otherwise).
		return h.hasPermission(client, permission.FindingsRead) && h.canSeeFinding(client, id)

	case ChannelTypeScan:
		return h.hasPermission(client, permission.ScansRead)

	case ChannelTypeGroup:
		// Scope-rule changes of one group: its members, or anyone allowed to
		// read groups.
		return h.isGroupMember(client, id) || h.hasPermission(client, permission.GroupsRead)

	default:
		// Unknown channel type (including the retired notification:{id}),
		// deny by default.
		return false
	}
}

func (h *Hub) hasPermission(client *Client, perm permission.Permission) bool {
	if h.access == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), channelAccessTimeout)
	defer cancel()
	ok, err := h.access.HasPermission(ctx, client.TenantID, client.UserID, perm.String())
	if err != nil {
		h.logger.Warn("ws channel permission check failed", "user_id", client.UserID, "permission", perm.String(), "error", err)
		return false
	}
	return ok
}

func (h *Hub) canSeeFinding(client *Client, findingID string) bool {
	if h.access == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), channelAccessTimeout)
	defer cancel()
	ok, err := h.access.CanSeeFinding(ctx, client.TenantID, client.UserID, findingID)
	if err != nil {
		h.logger.Debug("ws finding scope check failed", "user_id", client.UserID, "finding_id", findingID, "error", err)
		return false
	}
	return ok
}

func (h *Hub) isGroupMember(client *Client, groupID string) bool {
	if h.access == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), channelAccessTimeout)
	defer cancel()
	ok, err := h.access.IsGroupMember(ctx, client.TenantID, groupID, client.UserID)
	if err != nil {
		h.logger.Debug("ws group membership check failed", "user_id", client.UserID, "group_id", groupID, "error", err)
		return false
	}
	return ok
}

// SetAuthorizeFunc sets a custom authorization function.
func (h *Hub) SetAuthorizeFunc(fn AuthorizeFunc) {
	h.authorizeFn = fn
}

// Run starts the hub's main loop.
func (h *Hub) Run(ctx context.Context) {
	h.logger.Info("websocket hub started")

	// Signal all channel senders (Broadcast/Register/Unregister/DeliverLocal)
	// that the loop is gone, so their selects fall through instead of blocking
	// forever on channels nobody reads.
	defer close(h.done)

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
					metrics.WSUpgradeRejectionsTotal.WithLabelValues("too_many").Inc()
					// A close code, not a silent drop: the client backs off
					// instead of reconnecting in a tight loop.
					client.closeWith(CloseTooManyConnections, "too many connections", "")
					client.markRegistered()
					continue
				}
				h.userConnCounts[client.UserID] = count + 1
			}
			h.clients[client] = true
			h.mu.Unlock()
			metrics.WSConnections.Inc()
			client.markRegistered()

			h.logger.Debug("client registered",
				"client_id", client.ID,
				"user_id", client.UserID,
				"tenant_id", client.TenantID,
			)

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				metrics.WSConnections.Dec()
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

// RegisterClient registers a new client. No-op after the hub stopped (the
// select on done prevents a permanent block on a channel nobody reads).
func (h *Hub) RegisterClient(client *Client) {
	select {
	case h.register <- client:
	case <-h.done:
		client.Close()
		client.markRegistered()
	}
}

// Revocation reasons. They label openctem_ws_forced_closes_total and are the
// only values ApplyRevocation accepts from the cross-instance bus.
const (
	RevocationSessionRevoked = "session_revoked"
	RevocationAccessChanged  = "access_changed"
)

// Revocation names the connections that must be closed because the
// credential or access they were opened with no longer holds: every
// connection of one session, or every connection of one user in one tenant.
type Revocation struct {
	Reason    string `json:"reason"`
	SessionID string `json:"session_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
	UserID    string `json:"user_id,omitempty"`
}

// RevocationPublisher fans a revocation out to every API instance (the Redis
// bridge). Each instance, this one included, applies it via ApplyRevocation.
type RevocationPublisher interface {
	PublishRevocation(ctx context.Context, r Revocation) error
}

// SetRevocationPublisher attaches the cross-instance revocation bus.
func (h *Hub) SetRevocationPublisher(p RevocationPublisher) {
	h.revocations = p
}

// RevokeSession closes every connection opened with sessionID, on every API
// instance. Called when the session is signed out or revoked.
func (h *Hub) RevokeSession(ctx context.Context, sessionID string) {
	if sessionID == "" {
		return
	}
	h.revoke(ctx, Revocation{Reason: RevocationSessionRevoked, SessionID: sessionID})
}

// RevokeAccess closes every connection of userID in tenantID, on every API
// instance. Called when the user's membership or role in the tenant changes;
// the client reconnects and the upgrade re-runs every tenant gate.
func (h *Hub) RevokeAccess(ctx context.Context, tenantID, userID string) {
	if tenantID == "" || userID == "" {
		return
	}
	h.revoke(ctx, Revocation{Reason: RevocationAccessChanged, TenantID: tenantID, UserID: userID})
}

func (h *Hub) revoke(ctx context.Context, r Revocation) {
	if h.revocations != nil {
		err := h.revocations.PublishRevocation(ctx, r)
		if err == nil {
			return
		}
		// Other instances miss this one; their sockets still end at the
		// credential expiry. This instance closes its own now.
		h.logger.Error("ws revocation publish failed, closing local connections only",
			"reason", r.Reason, "error", err)
	}
	h.ApplyRevocation(r)
}

// ApplyRevocation closes the matching connections on this instance and
// returns how many it closed. A revocation that names neither a session nor
// a user+tenant, or carries an unknown reason, closes nothing: a malformed
// bus message must never fan out to every socket.
func (h *Hub) ApplyRevocation(r Revocation) int {
	var text string
	switch r.Reason {
	case RevocationSessionRevoked:
		text = "session revoked"
	case RevocationAccessChanged:
		text = "access changed"
	default:
		return 0
	}
	bySession := r.SessionID != ""
	if !bySession && (r.TenantID == "" || r.UserID == "") {
		return 0
	}

	h.mu.RLock()
	var targets []*Client
	for c := range h.clients {
		if bySession {
			if c.SessionID == r.SessionID {
				targets = append(targets, c)
			}
		} else if c.TenantID == r.TenantID && c.UserID == r.UserID {
			targets = append(targets, c)
		}
	}
	h.mu.RUnlock()

	for _, c := range targets {
		c.closeWith(CloseUnauthorized, text, r.Reason)
	}
	if len(targets) > 0 {
		h.logger.Info("websocket connections revoked",
			"reason", r.Reason,
			"session_id", r.SessionID,
			"tenant_id", r.TenantID,
			"user_id", r.UserID,
			"closed", len(targets),
		)
	}
	return len(targets)
}

// UnregisterClient unregisters a client. No-op after the hub stopped.
func (h *Hub) UnregisterClient(client *Client) {
	select {
	case h.unregister <- client:
	case <-h.done:
	}
}

// Broadcast sends a message to all clients subscribed to a channel.
//
// F-7: when a cross-pod publisher is configured (Redis pubsub bridge),
// the message is handed to it instead of being placed directly on the
// local broadcast channel. The bridge round-trips it through Redis and
// every subscribing pod (including this one) receives it via
// DeliverLocal, ensuring a single source of fan-out and correct delivery
// in multi-replica deployments.
func (h *Hub) Broadcast(channel string, msg *Message, tenantID string) {
	if h.publisher != nil {
		bm := &BroadcastMessage{Channel: channel, Message: msg, TenantID: tenantID}
		if err := h.publisher.Publish(context.Background(), bm); err != nil {
			h.logger.Error("ws broadcast publish failed, falling back to local only",
				"channel", channel, "error", err)
			h.deliver(bm)
		}
		return
	}
	h.deliver(&BroadcastMessage{
		Channel:  channel,
		Message:  msg,
		TenantID: tenantID,
	})
}

// DeliverLocal pushes a BroadcastMessage onto the local broadcast channel
// WITHOUT re-publishing it through the cross-pod publisher. This is the
// entry point used by the Redis subscriber to inject incoming messages
// into this pod's in-memory fan-out. External callers should use
// Broadcast instead.
func (h *Hub) DeliverLocal(msg *BroadcastMessage) {
	h.deliver(msg)
}

// deliver places a message on the broadcast channel unless the hub has
// stopped — after Run exits nothing reads h.broadcast, and an unguarded send
// would block the caller (an HTTP handler or the Redis subscriber) forever,
// stalling graceful shutdown.
func (h *Hub) deliver(msg *BroadcastMessage) {
	select {
	case h.broadcast <- msg:
	case <-h.done:
		h.logger.Debug("ws broadcast dropped: hub stopped", "channel", msg.Channel)
	}
}

// SetPublisher attaches a cross-pod publisher (F-7). Must be called
// before Run so Broadcast observes it.
func (h *Hub) SetPublisher(p BroadcastPublisher) {
	h.publisher = p
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
	// SECURITY: Reject broadcasts without tenant context to prevent
	// cross-tenant data leakage. All broadcasts must be explicitly tenant-scoped.
	if msg.TenantID == "" {
		h.logger.Error("refusing broadcast without tenant_id",
			"channel", msg.Channel,
		)
		return
	}

	userChannel := strings.HasPrefix(msg.Channel, notificationdom.UserChannelPrefix)

	h.mu.RLock()
	clients, ok := h.channels[msg.Channel]
	if !ok || len(clients) == 0 {
		h.mu.RUnlock()
		return
	}

	// Copy client list to avoid holding lock during send
	clientList := make([]*Client, 0, len(clients))
	for client := range clients {
		// SECURITY: Strict tenant isolation — client must belong to the same tenant
		if client.TenantID != msg.TenantID {
			continue
		}
		// SECURITY: a user channel is delivered only to that user's own
		// connections, even if a subscription slipped past authorization.
		if userChannel && msg.Channel != notificationdom.UserChannel(client.TenantID, client.UserID) {
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
		metrics.WSConnections.Dec()
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
