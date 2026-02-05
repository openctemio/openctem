package websocket

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/openctemio/api/pkg/logger"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer.
	maxMessageSize = 4096

	// Rate limiting: max subscriptions per client
	maxSubscriptionsPerClient = 50
)

// Client represents a single WebSocket connection.
type Client struct {
	hub    *Hub
	conn   *websocket.Conn
	send   chan []byte
	logger *logger.Logger

	// Identity
	ID       string
	UserID   string
	TenantID string

	// Subscriptions (channel -> true)
	subscriptions map[string]bool
	subMu         sync.RWMutex

	// State
	closed bool
	mu     sync.Mutex
}

// NewClient creates a new WebSocket client.
func NewClient(hub *Hub, conn *websocket.Conn, userID, tenantID string, log *logger.Logger) *Client {
	return &Client{
		hub:           hub,
		conn:          conn,
		send:          make(chan []byte, 256),
		logger:        log,
		ID:            generateClientID(),
		UserID:        userID,
		TenantID:      tenantID,
		subscriptions: make(map[string]bool),
	}
}

// generateClientID creates a unique client ID.
func generateClientID() string {
	// Simple unique ID for our purposes
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Nanosecond()%10000)
}

// Subscribe adds a channel subscription.
// Returns false if already subscribed or rate limit exceeded.
func (c *Client) Subscribe(channel string) bool {
	c.subMu.Lock()
	defer c.subMu.Unlock()

	if c.subscriptions[channel] {
		return false // Already subscribed
	}

	// Rate limit: max subscriptions per client
	if len(c.subscriptions) >= maxSubscriptionsPerClient {
		c.logger.Warn("subscription limit exceeded",
			"client_id", c.ID,
			"user_id", c.UserID,
			"current", len(c.subscriptions),
			"max", maxSubscriptionsPerClient,
		)
		return false
	}

	c.subscriptions[channel] = true
	return true
}

// Unsubscribe removes a channel subscription.
func (c *Client) Unsubscribe(channel string) bool {
	c.subMu.Lock()
	defer c.subMu.Unlock()

	if !c.subscriptions[channel] {
		return false // Not subscribed
	}

	delete(c.subscriptions, channel)
	return true
}

// IsSubscribed checks if client is subscribed to a channel.
func (c *Client) IsSubscribed(channel string) bool {
	c.subMu.RLock()
	defer c.subMu.RUnlock()
	return c.subscriptions[channel]
}

// GetSubscriptions returns all subscribed channels.
func (c *Client) GetSubscriptions() []string {
	c.subMu.RLock()
	defer c.subMu.RUnlock()

	channels := make([]string, 0, len(c.subscriptions))
	for ch := range c.subscriptions {
		channels = append(channels, ch)
	}
	return channels
}

// SendMessage sends a message to the client.
func (c *Client) SendMessage(msg *Message) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	select {
	case c.send <- data:
		return nil
	default:
		// Buffer full, client is slow
		c.logger.Warn("client send buffer full, dropping message",
			"client_id", c.ID,
			"user_id", c.UserID,
		)
		return nil
	}
}

// Close closes the client connection.
func (c *Client) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()

	close(c.send)
	c.conn.Close()
}

// ReadPump pumps messages from the WebSocket connection to the hub.
func (c *Client) ReadPump() {
	defer func() {
		c.hub.unregister <- c
		c.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.logger.Debug("websocket read error",
					"client_id", c.ID,
					"error", err,
				)
			}
			break
		}

		// Parse message
		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			c.logger.Debug("invalid websocket message",
				"client_id", c.ID,
				"error", err,
			)
			c.sendError("INVALID_MESSAGE", "Invalid message format")
			continue
		}

		// Handle message
		c.handleMessage(&msg)
	}
}

// WritePump pumps messages from the hub to the WebSocket connection.
func (c *Client) WritePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// Hub closed the channel
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			// Send message in its own frame (don't batch to avoid JSON parse issues on client)
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleMessage processes incoming messages from client.
func (c *Client) handleMessage(msg *Message) {
	switch msg.Type {
	case MessageTypeSubscribe:
		c.handleSubscribe(msg)
	case MessageTypeUnsubscribe:
		c.handleUnsubscribe(msg)
	case MessageTypePing:
		c.handlePing(msg)
	default:
		c.sendError("UNKNOWN_MESSAGE_TYPE", "Unknown message type: "+string(msg.Type))
	}
}

// handleSubscribe processes subscribe requests.
func (c *Client) handleSubscribe(msg *Message) {
	var req SubscribeRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		// Try to get channel from message directly
		req.Channel = msg.Channel
		req.RequestID = msg.RequestID
	}

	if req.Channel == "" {
		c.sendErrorWithRequestID("INVALID_CHANNEL", "Channel is required", req.RequestID)
		return
	}

	// Check authorization
	if !c.hub.authorizeSubscription(c, req.Channel) {
		c.sendErrorWithRequestID("FORBIDDEN", "Access denied to channel", req.RequestID)
		return
	}

	// Subscribe
	if c.Subscribe(req.Channel) {
		c.hub.subscribeToChannel(c, req.Channel)
		c.logger.Debug("client subscribed",
			"client_id", c.ID,
			"channel", req.Channel,
		)
	}

	// Send confirmation
	response := NewMessage(MessageTypeSubscribed).
		WithChannel(req.Channel).
		WithRequestID(req.RequestID)
	c.SendMessage(response)
}

// handleUnsubscribe processes unsubscribe requests.
func (c *Client) handleUnsubscribe(msg *Message) {
	var req UnsubscribeRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		req.Channel = msg.Channel
		req.RequestID = msg.RequestID
	}

	if req.Channel == "" {
		c.sendErrorWithRequestID("INVALID_CHANNEL", "Channel is required", req.RequestID)
		return
	}

	// Unsubscribe
	if c.Unsubscribe(req.Channel) {
		c.hub.unsubscribeFromChannel(c, req.Channel)
		c.logger.Debug("client unsubscribed",
			"client_id", c.ID,
			"channel", req.Channel,
		)
	}

	// Send confirmation
	response := NewMessage(MessageTypeUnsubscribed).
		WithChannel(req.Channel).
		WithRequestID(req.RequestID)
	c.SendMessage(response)
}

// handlePing processes ping messages.
func (c *Client) handlePing(msg *Message) {
	response := NewMessage(MessageTypePong)
	c.SendMessage(response)
}

// sendError sends an error message to the client.
func (c *Client) sendError(code, message string) {
	c.sendErrorWithRequestID(code, message, "")
}

// sendErrorWithRequestID sends an error message with request ID.
func (c *Client) sendErrorWithRequestID(code, message, requestID string) {
	errMsg := NewMessage(MessageTypeError).
		WithData(ErrorData{Code: code, Message: message}).
		WithRequestID(requestID)
	c.SendMessage(errMsg)
}
