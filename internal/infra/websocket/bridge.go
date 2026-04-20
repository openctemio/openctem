package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	redislib "github.com/redis/go-redis/v9"

	"github.com/openctemio/api/pkg/logger"
)

// F-7: Cross-pod WebSocket fan-out via Redis pubsub.
//
// Problem: the Hub is in-memory, so in a multi-replica deployment a
// BroadcastEvent on Pod-A never reaches a client connected to Pod-B.
// Silent data-quality issue — the UI just looks quiet.
//
// Design: on every pod, run a single subscriber on the `ws:broadcast`
// Redis channel. When a service calls hub.Broadcast(...), the Hub's
// publisher publishes the serialized BroadcastMessage to that channel
// instead of delivering only locally. All pods (including the publishing
// one) then receive the message via the subscriber and fan it out to
// their local clients, with the same tenant-isolation check that local
// broadcasts already enforce in broadcastToChannel.
//
// Intentional properties:
//   - A single Redis channel for all WS broadcasts keeps connection
//     overhead constant with tenant count.
//   - Tenant isolation is re-applied on the receiving pod — a
//     compromised Redis instance that injects crafted messages is still
//     constrained by the local Hub's authorization check.
//   - The publisher falls back to local-only delivery on Redis errors
//     so a Redis outage degrades to single-pod behaviour instead of
//     dropping notifications.

// redisBroadcastChannel is the pubsub channel used for all WS fan-out.
// Chosen as a single channel (not per-tenant) so the subscriber count
// stays O(1) per pod regardless of tenant count. Tenant isolation is
// enforced on receive.
const redisBroadcastChannel = "ws:broadcast"

// BridgeConfig configures the Redis bridge.
type BridgeConfig struct {
	// Channel overrides the default pubsub channel. Leave empty to use
	// the standard value.
	Channel string
	// Logger for bridge diagnostics.
	Logger *logger.Logger
}

// RedisBridge publishes local broadcasts to Redis and fans incoming
// Redis messages back into the local Hub.
type RedisBridge struct {
	rc      *redislib.Client
	hub     *Hub
	channel string
	logger  *logger.Logger
}

// NewRedisBridge constructs a bridge. The caller is expected to call
// Start in a goroutine and Stop on shutdown.
func NewRedisBridge(rc *redislib.Client, hub *Hub, cfg *BridgeConfig) *RedisBridge {
	if cfg == nil {
		cfg = &BridgeConfig{}
	}
	if cfg.Channel == "" {
		cfg.Channel = redisBroadcastChannel
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.NewNop()
	}
	b := &RedisBridge{
		rc:      rc,
		hub:     hub,
		channel: cfg.Channel,
		logger:  cfg.Logger.With("component", "ws-bridge"),
	}
	hub.SetPublisher(b)
	return b
}

// wirePayload is the JSON shape pushed over Redis. We transport the
// already-serialized Message so the receiving pod does not need the
// originating process's type information.
type wirePayload struct {
	Channel  string          `json:"channel"`
	TenantID string          `json:"tenant_id"`
	Message  json.RawMessage `json:"message"`
}

// Publish implements BroadcastPublisher. Serialises the BroadcastMessage
// and pushes to the configured Redis pubsub channel.
func (b *RedisBridge) Publish(ctx context.Context, msg *BroadcastMessage) error {
	if msg == nil || msg.Message == nil {
		return fmt.Errorf("ws bridge: nil broadcast")
	}
	raw, err := json.Marshal(msg.Message)
	if err != nil {
		return fmt.Errorf("marshal ws message: %w", err)
	}
	payload, err := json.Marshal(&wirePayload{
		Channel:  msg.Channel,
		TenantID: msg.TenantID,
		Message:  raw,
	})
	if err != nil {
		return fmt.Errorf("marshal ws envelope: %w", err)
	}
	if err := b.rc.Publish(ctx, b.channel, payload).Err(); err != nil {
		return fmt.Errorf("redis publish: %w", err)
	}
	return nil
}

// Start subscribes to the Redis channel and fans incoming messages into
// the local Hub's broadcast queue. Returns when ctx is cancelled.
//
// Reconnection is handled by the underlying go-redis client for
// transient failures. For non-transient errors (pubsub closed) we log
// and return so the caller can restart us.
func (b *RedisBridge) Start(ctx context.Context) error {
	sub := b.rc.Subscribe(ctx, b.channel)
	defer func() { _ = sub.Close() }()

	// Wait for subscription confirmation so we know we are actually
	// receiving before we log "bridge ready".
	if _, err := sub.Receive(ctx); err != nil {
		return fmt.Errorf("ws bridge subscribe: %w", err)
	}
	b.logger.Info("ws redis bridge subscribed", "channel", b.channel)

	ch := sub.Channel(
		redislib.WithChannelSize(256),
		redislib.WithChannelHealthCheckInterval(30*time.Second),
	)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case rm, ok := <-ch:
			if !ok {
				return fmt.Errorf("ws bridge channel closed")
			}
			b.handleIncoming(rm.Payload)
		}
	}
}

// handleIncoming decodes a Redis payload and delivers it to the local
// Hub. Tenant isolation is re-applied by broadcastToChannel.
func (b *RedisBridge) handleIncoming(payload string) {
	var env wirePayload
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		b.logger.Warn("ws bridge received malformed payload", "error", err)
		return
	}
	var m Message
	if err := json.Unmarshal(env.Message, &m); err != nil {
		b.logger.Warn("ws bridge received malformed message", "error", err)
		return
	}
	b.hub.DeliverLocal(&BroadcastMessage{
		Channel:  env.Channel,
		Message:  &m,
		TenantID: env.TenantID,
	})
}
