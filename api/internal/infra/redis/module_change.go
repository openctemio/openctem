package redis

// Cross-replica fan-out of module toggles. A tenant's module change is saved
// on one API replica; every replica caches the tenant's module state for the
// route gate. The bus drops the local cache at once and tells the other
// replicas to drop theirs. The message carries only the tenant id: each
// replica re-reads the database, the only source of truth. A lost message
// costs at most the gate's TTL of staleness.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	redislib "github.com/redis/go-redis/v9"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ModuleChangeChannel is the pub/sub channel of module toggles.
const ModuleChangeChannel = "modules:changed"

// moduleChangeQueue bounds the changes waiting to be published; beyond it a
// change is dropped (the gate's TTL still expires the cache).
const moduleChangeQueue = 256

// ModuleCacheInvalidator is the local cache the bus drops entries from
// (*middleware.ModuleGate).
type ModuleCacheInvalidator interface {
	Invalidate(tenantID string)
	InvalidateAll()
}

type moduleChange struct {
	// Origin is the publishing replica; it already dropped its own cache.
	Origin   string `json:"o"`
	TenantID string `json:"t,omitempty"`
	// All drops every tenant (a plan to module mapping change).
	All bool `json:"all,omitempty"`
}

// ModuleChangeBus invalidates the local module cache and every other
// replica's through Redis.
type ModuleChangeBus struct {
	rc     redislib.UniversalClient
	local  ModuleCacheInvalidator
	log    *logger.Logger
	origin string
	queue  chan moduleChange
}

// NewModuleChangeBus builds the bus. Start must run for remote delivery.
func NewModuleChangeBus(client *Client, local ModuleCacheInvalidator, log *logger.Logger) *ModuleChangeBus {
	return newModuleChangeBus(client.Client(), local, log)
}

func newModuleChangeBus(rc redislib.UniversalClient, local ModuleCacheInvalidator, log *logger.Logger) *ModuleChangeBus {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return &ModuleChangeBus{
		rc: rc, local: local, log: log.With("component", "module-change-bus"),
		origin: hex.EncodeToString(b[:]), queue: make(chan moduleChange, moduleChangeQueue),
	}
}

// Invalidate drops the tenant's cached module state here and on every other
// replica. It never blocks.
func (b *ModuleChangeBus) Invalidate(tenantID string) {
	b.local.Invalidate(tenantID)
	select {
	case b.queue <- moduleChange{Origin: b.origin, TenantID: tenantID}:
	default:
		b.log.Debug("module change dropped: publish queue full")
	}
}

// InvalidateAll drops every tenant's cached module state here and on every
// other replica (a plan to module mapping change). It never blocks.
func (b *ModuleChangeBus) InvalidateAll() {
	b.local.InvalidateAll()
	select {
	case b.queue <- moduleChange{Origin: b.origin, All: true}:
	default:
		b.log.Debug("module change dropped: publish queue full")
	}
}

// Start publishes queued changes and applies other replicas' changes until
// ctx ends.
func (b *ModuleChangeBus) Start(ctx context.Context) error {
	sub := b.rc.Subscribe(ctx, ModuleChangeChannel)
	if _, err := sub.Receive(ctx); err != nil {
		_ = sub.Close()
		return err
	}
	go b.publishLoop(ctx)
	go func() {
		defer func() { _ = sub.Close() }()
		ch := sub.Channel(redislib.WithChannelSize(64), redislib.WithChannelHealthCheckInterval(30*time.Second))
		for {
			select {
			case <-ctx.Done():
				return
			case m, ok := <-ch:
				if !ok {
					b.log.Warn("module change subscription closed")
					return
				}
				b.deliver(m.Payload)
			}
		}
	}()
	b.log.Info("module change bus subscribed", "channel", ModuleChangeChannel)
	return nil
}

func (b *ModuleChangeBus) publishLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-b.queue:
			raw, err := json.Marshal(c)
			if err != nil {
				continue
			}
			pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			if err := b.rc.Publish(pctx, ModuleChangeChannel, raw).Err(); err != nil {
				b.log.Debug("module change not published", "error", err)
			}
			cancel()
		}
	}
}

// deliver applies a remote change. Redis is trusted with no more than a
// hint: a malformed or oversized message, or a tenant id that is not a UUID,
// is dropped, and a change only ever drops a cache entry.
func (b *ModuleChangeBus) deliver(payload string) {
	if len(payload) > 256 {
		return
	}
	var c moduleChange
	if json.Unmarshal([]byte(payload), &c) != nil || c.Origin == b.origin {
		return
	}
	if c.All {
		b.local.InvalidateAll()
		return
	}
	if _, err := shared.IDFromString(c.TenantID); err != nil {
		return
	}
	b.local.Invalidate(c.TenantID)
}
