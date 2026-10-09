package redis

// Cross-replica fan-out of sensor control-stream wakes
// (docs/rfcs/RFC-059-sensor-transport-v3.md T12). A command change or a
// sensor status change on one API replica must reach the control streams
// held by every replica. The wake carries no data, only which tenant (and
// optionally which sensor) to re-check: each replica re-reads the doorbell
// from the database, which stays the only source of truth. A lost wake costs
// latency, never a job.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	redislib "github.com/redis/go-redis/v9"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/coalesce"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SensorWakeChannel is the pub/sub channel of control-stream wakes.
const SensorWakeChannel = "sensor:v3:wake"

// sensorWakeQueue bounds the wakes waiting to be published; beyond it a
// wake is dropped (the periodic re-check still delivers it).
const sensorWakeQueue = 1024

// sensorWakeTenantQuota is one tenant's share of the publish queue
// (research/84 RE-12): the queue is shared by every tenant, so a tenant
// flooding wakes must not push out the others'. A tenant at its quota has
// its further wakes folded into one tenant-wide wake, queued as soon as one
// of its queued wakes is published.
const sensorWakeTenantQuota = 32

// allTenants is the quota key of WakeAll.
const allTenants = "*"

// SensorWaker is the local hub the bus delivers wakes to.
type SensorWaker interface {
	Wake(tenantID, sensorID string)
	WakeAll()
}

type sensorWake struct {
	// Origin is the publishing replica; it already woke its own streams.
	Origin   string `json:"o"`
	TenantID string `json:"t,omitempty"`
	SensorID string `json:"s,omitempty"`
	All      bool   `json:"all,omitempty"`
}

// SensorWakeBus wakes the local hub at once and every other replica's
// through Redis.
type SensorWakeBus struct {
	rc     redislib.UniversalClient
	local  SensorWaker
	log    *logger.Logger
	origin string
	queue  chan sensorWake
	// publish coalesces the publishes of one tenant (sensor, WakeAll) to
	// one per sensortransport.WakeCoalesce, like the hubs deliver them.
	publish *coalesce.Throttle

	mu sync.Mutex
	// queued counts each tenant's wakes in queue; owed marks a tenant whose
	// wakes beyond its quota were folded into a tenant-wide wake still to
	// be queued.
	queued map[string]int
	owed   map[string]bool
}

// sensorWakeCoalesce matches sensortransport.WakeCoalesce (the redis
// package does not import the transport).
const sensorWakeCoalesce = 500 * time.Millisecond

// NewSensorWakeBus builds the bus. Start must run for remote delivery.
func NewSensorWakeBus(client *Client, local SensorWaker, log *logger.Logger) *SensorWakeBus {
	return newSensorWakeBus(client.Client(), local, log)
}

func newSensorWakeBus(rc redislib.UniversalClient, local SensorWaker, log *logger.Logger) *SensorWakeBus {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return &SensorWakeBus{
		rc: rc, local: local, log: log.With("component", "sensor-wake-bus"),
		origin: hex.EncodeToString(b[:]), queue: make(chan sensorWake, sensorWakeQueue),
		publish: coalesce.New(sensorWakeCoalesce), queued: map[string]int{}, owed: map[string]bool{},
	}
}

// Wake implements the command and sensor change notifiers. It never blocks.
func (b *SensorWakeBus) Wake(tenantID, sensorID string) {
	b.local.Wake(tenantID, sensorID)
	key := "t:" + tenantID
	if sensorID != "" {
		key = "s:" + tenantID + "/" + sensorID
	}
	b.publish.Do(key, func() { b.enqueue(sensorWake{Origin: b.origin, TenantID: tenantID, SensorID: sensorID}) })
}

// WakeAll wakes every stream on every replica.
func (b *SensorWakeBus) WakeAll() {
	b.local.WakeAll()
	b.publish.Do(allTenants, func() { b.enqueue(sensorWake{Origin: b.origin, All: true}) })
}

func quotaKey(w sensorWake) string {
	if w.All {
		return allTenants
	}
	return w.TenantID
}

// enqueue queues w unless its tenant holds its quota of the queue (then the
// wake is folded into a tenant-wide one, owed) or the queue is full.
func (b *SensorWakeBus) enqueue(w sensorWake) {
	key := quotaKey(w)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.queued[key] >= sensorWakeTenantQuota {
		b.owed[key] = true
		metrics.SensorWakesCoalescedTotal.WithLabelValues("tenant_quota").Inc()
		return
	}
	select {
	case b.queue <- w:
		b.queued[key]++
	default:
		metrics.SensorWakesCoalescedTotal.WithLabelValues("queue_full").Inc()
		b.log.Debug("sensor wake dropped: publish queue full")
	}
}

// dequeued releases w's quota slot and queues the tenant's owed tenant-wide
// wake, if any, in its place.
func (b *SensorWakeBus) dequeued(w sensorWake) {
	key := quotaKey(w)
	b.mu.Lock()
	if b.queued[key]--; b.queued[key] <= 0 {
		delete(b.queued, key)
	}
	owed := b.owed[key]
	delete(b.owed, key)
	b.mu.Unlock()
	if owed {
		b.enqueue(sensorWake{Origin: b.origin, TenantID: w.TenantID, All: w.All})
	}
}

// Start publishes queued wakes and delivers other replicas' wakes to the
// local hub until ctx ends.
func (b *SensorWakeBus) Start(ctx context.Context) error {
	sub := b.rc.Subscribe(ctx, SensorWakeChannel)
	if _, err := sub.Receive(ctx); err != nil {
		_ = sub.Close()
		return err
	}
	go b.publishLoop(ctx)
	go func() {
		defer func() { _ = sub.Close() }()
		ch := sub.Channel(redislib.WithChannelSize(256), redislib.WithChannelHealthCheckInterval(30*time.Second))
		for {
			select {
			case <-ctx.Done():
				return
			case m, ok := <-ch:
				if !ok {
					b.log.Warn("sensor wake subscription closed")
					return
				}
				b.deliver(m.Payload)
			}
		}
	}()
	b.log.Info("sensor wake bus subscribed", "channel", SensorWakeChannel)
	return nil
}

func (b *SensorWakeBus) publishLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case w := <-b.queue:
			b.dequeued(w)
			raw, err := json.Marshal(w)
			if err != nil {
				continue
			}
			pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			if err := b.rc.Publish(pctx, SensorWakeChannel, raw).Err(); err != nil {
				b.log.Debug("sensor wake not published", "error", err)
			}
			cancel()
		}
	}
}

// deliver hands a remote wake to the local hub. Redis is not trusted with
// more than a hint: a malformed or oversized message, or ids that are not
// UUIDs, are dropped; a wake only ever triggers a database re-check.
func (b *SensorWakeBus) deliver(payload string) {
	if len(payload) > 512 {
		return
	}
	var w sensorWake
	if json.Unmarshal([]byte(payload), &w) != nil || w.Origin == b.origin {
		return
	}
	if w.All {
		b.local.WakeAll()
		return
	}
	if _, err := shared.IDFromString(w.TenantID); err != nil {
		return
	}
	if w.SensorID != "" {
		if _, err := shared.IDFromString(w.SensorID); err != nil {
			return
		}
	}
	b.local.Wake(w.TenantID, w.SensorID)
}
