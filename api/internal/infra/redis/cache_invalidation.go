package redis

// Cross-replica fan-out of per-tenant cache drops (module toggles, IP
// allowlist changes). A change is saved on one API replica while every
// replica caches the tenant's state for a request gate. The bus drops the
// local cache at once and tells the other replicas to drop theirs. The
// message carries only the origin replica and a tenant id (no tenant data):
// each replica re-reads the database, the only source of truth. A lost
// message costs at most the gate's TTL of staleness.

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

const (
	// ModuleChangeChannel is the pub/sub channel of module toggles.
	ModuleChangeChannel = "modules:changed"
	// IPAllowlistChangeChannel is the pub/sub channel of IP allowlist changes.
	IPAllowlistChangeChannel = "ip_allowlist:changed"
)

// cacheChangeQueue bounds the changes waiting to be published; beyond it a
// change is dropped (the gate's TTL still expires the cache).
const cacheChangeQueue = 256

// CacheInvalidator is the local cache the bus drops entries from
// (*middleware.ModuleGate, *middleware.IPAllowlistGate).
type CacheInvalidator interface {
	Invalidate(tenantID string)
	InvalidateAll()
}

// ModuleCacheInvalidator is the module gate's CacheInvalidator.
type ModuleCacheInvalidator = CacheInvalidator

type cacheChange struct {
	// Origin is the publishing replica; it already dropped its own cache.
	Origin   string `json:"o"`
	TenantID string `json:"t,omitempty"`
	// All drops every tenant (a plan to module mapping change).
	All bool `json:"all,omitempty"`
}

// CacheInvalidationBus invalidates a local per-tenant cache and every other
// replica's through one Redis channel.
type CacheInvalidationBus struct {
	rc      redislib.UniversalClient
	local   CacheInvalidator
	log     *logger.Logger
	channel string
	origin  string
	queue   chan cacheChange
}

// ModuleChangeBus is the bus on the module toggle channel.
type ModuleChangeBus = CacheInvalidationBus

// NewCacheInvalidationBus builds a bus on channel. Start must run for remote
// delivery.
func NewCacheInvalidationBus(client *Client, channel string, local CacheInvalidator, log *logger.Logger) *CacheInvalidationBus {
	return newCacheInvalidationBus(client.Client(), channel, local, log)
}

// NewModuleChangeBus builds the module toggle bus.
func NewModuleChangeBus(client *Client, local CacheInvalidator, log *logger.Logger) *ModuleChangeBus {
	return NewCacheInvalidationBus(client, ModuleChangeChannel, local, log)
}

// NewIPAllowlistChangeBus builds the IP allowlist change bus.
func NewIPAllowlistChangeBus(client *Client, local CacheInvalidator, log *logger.Logger) *CacheInvalidationBus {
	return NewCacheInvalidationBus(client, IPAllowlistChangeChannel, local, log)
}

func newModuleChangeBus(rc redislib.UniversalClient, local CacheInvalidator, log *logger.Logger) *ModuleChangeBus {
	return newCacheInvalidationBus(rc, ModuleChangeChannel, local, log)
}

func newCacheInvalidationBus(rc redislib.UniversalClient, channel string, local CacheInvalidator, log *logger.Logger) *CacheInvalidationBus {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return &CacheInvalidationBus{
		rc: rc, local: local, channel: channel,
		log:    log.With("component", "cache-invalidation-bus", "channel", channel),
		origin: hex.EncodeToString(b[:]), queue: make(chan cacheChange, cacheChangeQueue),
	}
}

// Invalidate drops the tenant's cached state here and on every other
// replica. It never blocks.
func (b *CacheInvalidationBus) Invalidate(tenantID string) {
	b.local.Invalidate(tenantID)
	select {
	case b.queue <- cacheChange{Origin: b.origin, TenantID: tenantID}:
	default:
		b.log.Debug("cache invalidation dropped: publish queue full")
	}
}

// InvalidateAll drops every tenant's cached module state here and on every
// other replica (a plan to module mapping change). It never blocks.
func (b *CacheInvalidationBus) InvalidateAll() {
	b.local.InvalidateAll()
	select {
	case b.queue <- cacheChange{Origin: b.origin, All: true}:
	default:
		b.log.Debug("cache invalidation dropped: publish queue full")
	}
}

// Start publishes queued changes and applies other replicas' changes until
// ctx ends.
func (b *CacheInvalidationBus) Start(ctx context.Context) error {
	sub := b.rc.Subscribe(ctx, b.channel)
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
					b.log.Warn("cache invalidation subscription closed")
					return
				}
				b.deliver(m.Payload)
			}
		}
	}()
	b.log.Info("cache invalidation bus subscribed")
	return nil
}

func (b *CacheInvalidationBus) publishLoop(ctx context.Context) {
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
			if err := b.rc.Publish(pctx, b.channel, raw).Err(); err != nil {
				b.log.Debug("cache invalidation not published", "error", err)
			}
			cancel()
		}
	}
}

// deliver applies a remote change. Redis is trusted with no more than a
// hint: a malformed or oversized message, or a tenant id that is not a UUID,
// is dropped, and a change only ever drops a cache entry.
func (b *CacheInvalidationBus) deliver(payload string) {
	if len(payload) > 256 {
		return
	}
	var c cacheChange
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
