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
	"time"

	redislib "github.com/redis/go-redis/v9"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SensorWakeChannel is the pub/sub channel of control-stream wakes.
const SensorWakeChannel = "sensor:v3:wake"

// sensorWakeQueue bounds the wakes waiting to be published; beyond it a
// wake is dropped (the periodic re-check still delivers it).
const sensorWakeQueue = 1024

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
}

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
	}
}

// Wake implements the command and sensor change notifiers. It never blocks.
func (b *SensorWakeBus) Wake(tenantID, sensorID string) {
	b.local.Wake(tenantID, sensorID)
	b.enqueue(sensorWake{Origin: b.origin, TenantID: tenantID, SensorID: sensorID})
}

// WakeAll wakes every stream on every replica.
func (b *SensorWakeBus) WakeAll() {
	b.local.WakeAll()
	b.enqueue(sensorWake{Origin: b.origin, All: true})
}

func (b *SensorWakeBus) enqueue(w sensorWake) {
	select {
	case b.queue <- w:
	default:
		b.log.Debug("sensor wake dropped: publish queue full")
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
