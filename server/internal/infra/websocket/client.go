package websocket

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10

	// After the server sends a close frame it waits this long for the peer's
	// answering close before dropping the TCP connection. Dropping it at once
	// can reset the connection while the peer is still sending, and the reset
	// discards the close frame (and its code) on the peer's side.
	closeGrace = 2 * time.Second

	// Maximum message size allowed from peer.
	maxMessageSize = 4096

	// Rate limiting: max subscriptions per client
	maxSubscriptionsPerClient = 50

	// Client message rate limit (subscribe/unsubscribe/ping). Every subscribe
	// costs a permission lookup, so an unthrottled socket could turn into a
	// database amplifier. The burst covers a reconnect that re-subscribes the
	// maximum number of channels at once.
	messagesPerSecond = 10
	messageBurst      = maxSubscriptionsPerClient + 10

	// A client that keeps sending past the limit is closed (1008) after this
	// many dropped messages instead of being answered forever.
	maxThrottledMessages = 50
)

// Identity is who a connection authenticated as, and until when it may stay
// open. It is fixed for the life of the connection: a change of session,
// membership or role closes the socket (Hub.RevokeSession/RevokeAccess)
// rather than mutating it.
type Identity struct {
	UserID   string
	TenantID string
	// SessionID is the server-side session the credential belongs to. Empty
	// for credentials that carry none (OIDC access tokens); such sockets end
	// at ExpiresAt or on a user/tenant revocation only.
	SessionID string
	// ExpiresAt is when the connection is closed with CloseUnauthorized. The
	// handler sets it to the credential's expiry, capped by the maximum
	// connection lifetime.
	ExpiresAt time.Time
}

// Client represents a single WebSocket connection.
type Client struct {
	hub    *Hub
	conn   *websocket.Conn
	send   chan []byte
	logger *logger.Logger

	// Identity
	ID        string
	UserID    string
	TenantID  string
	SessionID string
	ExpiresAt time.Time

	// expiry closes the connection at ExpiresAt.
	expiry *time.Timer

	// Per-connection message rate limit; throttled is touched only by
	// ReadPump's goroutine.
	limiter   *rate.Limiter
	throttled int

	// registered is closed once the hub has accepted (or refused) the
	// client, so the handler can run checks that must observe it registered.
	registered chan struct{}
	regOnce    sync.Once

	// Subscriptions (channel -> true)
	subscriptions map[string]bool
	subMu         sync.RWMutex

	// State. closing is set when the server has sent a close frame: from
	// then on nothing is delivered to the client or processed from it, and
	// closed follows once the peer answers or closeGrace passes.
	closed  bool
	closing bool
	mu      sync.Mutex
}

// NewClient creates a new WebSocket client.
func NewClient(hub *Hub, conn *websocket.Conn, id Identity, log *logger.Logger) *Client {
	return &Client{
		hub:           hub,
		conn:          conn,
		send:          make(chan []byte, 256),
		logger:        log,
		ID:            generateClientID(),
		UserID:        id.UserID,
		TenantID:      id.TenantID,
		SessionID:     id.SessionID,
		ExpiresAt:     id.ExpiresAt,
		limiter:       rate.NewLimiter(rate.Limit(messagesPerSecond), messageBurst),
		subscriptions: make(map[string]bool),
		registered:    make(chan struct{}),
	}
}

// generateClientID creates a random connection id for logs.
func generateClientID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().Format("150405.000000000")
	}
	return hex.EncodeToString(b[:])
}

// markRegistered signals that the hub has handled the register request.
func (c *Client) markRegistered() {
	if c.registered == nil {
		return
	}
	c.regOnce.Do(func() { close(c.registered) })
}

// armExpiry closes the connection with CloseUnauthorized at ExpiresAt. A
// deadline already in the past closes it at once. Zero ExpiresAt arms nothing
// (the handler never registers a client without one).
func (c *Client) armExpiry(now time.Time) {
	if c.ExpiresAt.IsZero() {
		return
	}
	d := c.ExpiresAt.Sub(now)
	if d <= 0 {
		c.closeWith(CloseUnauthorized, "session expired", "session_expired")
		return
	}
	t := time.AfterFunc(d, func() {
		c.closeWith(CloseUnauthorized, "session expired", "session_expired")
	})
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		t.Stop()
		return
	}
	c.expiry = t
	c.mu.Unlock()
}

// closeWith sends a close frame with code and reason, then closes the
// connection. metricReason labels openctem_ws_forced_closes_total. Safe to call
// from any goroutine and more than once: gorilla allows WriteControl
// concurrently with the write pump, and Close is idempotent.
func (c *Client) closeWith(code int, reason, metricReason string) {
	c.mu.Lock()
	if c.closed || c.closing {
		c.mu.Unlock()
		return
	}
	c.closing = true
	c.mu.Unlock()

	if c.conn == nil {
		c.Close()
	} else {
		_ = c.conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(code, reason), time.Now().Add(writeWait))
		// ReadPump returns when the peer answers the close (or at the
		// deadline) and closes the connection; the timer is the backstop.
		_ = c.conn.SetReadDeadline(time.Now().Add(closeGrace))
		time.AfterFunc(closeGrace, c.Close)
	}
	if metricReason != "" {
		metrics.WSForcedClosesTotal.WithLabelValues(metricReason).Inc()
	}
	c.logger.Info("websocket connection closed by server",
		"client_id", c.ID,
		"user_id", c.UserID,
		"tenant_id", c.TenantID,
		"code", code,
		"reason", reason,
	)
}

// allowMessage applies the per-connection rate limit to one client message.
// It reports whether the message may be processed; false with a closed
// connection means the client kept flooding and was disconnected.
func (c *Client) allowMessage() bool {
	if c.limiter == nil || c.limiter.Allow() {
		return true
	}
	c.throttled++
	metrics.WSMessagesThrottledTotal.Inc()
	if c.throttled >= maxThrottledMessages {
		c.closeWith(websocket.ClosePolicyViolation, "rate limit exceeded", "rate_limited")
		return false
	}
	c.sendError("RATE_LIMITED", "Too many messages")
	return false
}

// isDone reports whether the connection is closed or being closed by the
// server; such a client gets no more messages and has none processed.
func (c *Client) isDone() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed || c.closing
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
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	// Hold the mutex across BOTH the closed-check and the channel send, and
	// have Close() close c.send under the same mutex. The previous code
	// released the lock between the check and the send, leaving a window where
	// a concurrent Close could close the channel first — a send on a closed
	// channel panics and crashes the whole process on a routine websocket
	// disconnect under load. The send is non-blocking (select/default), so
	// holding the lock here cannot deadlock against Close.
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.closing {
		return nil
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
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true

	if c.expiry != nil {
		c.expiry.Stop()
	}

	// close(c.send) happens under c.mu so it can never race a send in
	// SendMessage (which also holds c.mu across its send) — see comment there.
	close(c.send)
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

// ReadPump pumps messages from the WebSocket connection to the hub.
func (c *Client) ReadPump() {
	defer func() {
		c.hub.UnregisterClient(c)
		c.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
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

		// Once the server has sent its close frame, keep reading (and
		// discarding) until the peer answers it.
		if c.isDone() {
			continue
		}
		if !c.allowMessage() {
			continue
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
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// Hub closed the channel
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if c.isDone() {
				// Queued before the server closed the connection: never
				// delivered after a revocation or expiry.
				continue
			}

			// Send message in its own frame (don't batch to avoid JSON parse issues on client)
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			if c.isDone() {
				continue
			}
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
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
		metrics.WSSubscribeDeniedTotal.Inc()
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
	_ = c.SendMessage(response)
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
	_ = c.SendMessage(response)
}

// handlePing processes ping messages.
func (c *Client) handlePing(msg *Message) {
	response := NewMessage(MessageTypePong)
	_ = c.SendMessage(response)
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
	_ = c.SendMessage(errMsg)
}
