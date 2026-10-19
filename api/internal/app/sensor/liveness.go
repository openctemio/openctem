package sensor

// Heartbeat soft state (docs/architecture/sensors.md, "Heartbeat soft
// state"; research/191 §4A): where a heartbeat's writes go.
//
//   - postgres: every heartbeat updates the sensors row (the behavior before
//     the liveness store).
//   - shadow: as postgres, and the liveness store records every heartbeat
//     too, so the health controller can compare the two verdicts.
//   - redis: the liveness store records every heartbeat. Postgres gets the
//     heartbeat only when it changes something (the state digest), brings
//     the sensor back online, or follows a health-controller verdict; a
//     steady sensor reaches Postgres through the batched checkpoint, every
//     LivenessCheckpointPeriod. When the store cannot be reached, heartbeats
//     fall back to Postgres under a limit (livenessFallback).

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/openctemio/openctem/api/internal/metrics"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Liveness plane bounds.
const (
	// livenessFlushEvery and livenessFlushRows: the checkpoint batch is
	// written every few seconds, or at once when it holds this many rows.
	livenessFlushEvery = 5 * time.Second
	livenessFlushRows  = 500
	// livenessHistoryFlushEvery: the heartbeat history aggregates are
	// written this often (and when their bucket closes).
	livenessHistoryFlushEvery = 5 * time.Minute
	// livenessFallbackPerSecond and livenessFallbackPerSensor bound the
	// Postgres writes of heartbeats while the store is unreachable: per API
	// replica, and per sensor.
	livenessFallbackPerSecond = 50
	livenessFallbackPerSensor = time.Minute
	// livenessStoreTimeout bounds one store call on the heartbeat path.
	livenessStoreTimeout = 300 * time.Millisecond
	// maxPendingCheckpoints bounds the checkpoint batch; beyond it the
	// oldest rows are dropped (the next checkpoint repeats them).
	maxPendingCheckpoints = 20_000
)

// Heartbeat write kinds (metrics label values).
const (
	hbWriteFull       = "full"
	hbWriteCheckpoint = "checkpoint"
	hbWriteNone       = "none"
	hbWriteFallback   = "fallback"
	hbWriteDropped    = "dropped"
)

type histKey struct {
	sensor shared.ID
	bucket time.Time
}

// livenessPlane is the SensorService's liveness store wiring.
type livenessPlane struct {
	mode  sensordom.LivenessMode
	store sensordom.LivenessStore
	ckpt  sensordom.LivenessCheckpointer
	hist  sensordom.HeartbeatBatchRecorder
	log   *logger.Logger

	mu        sync.Mutex
	pending   map[shared.ID]sensordom.LivenessCheckpoint
	aggs      map[histKey]*sensordom.HeartbeatAggregate
	histFlush time.Time
	kick      chan struct{}

	fallbackAll  *rate.Limiter
	fallbackLast keyUseDebouncer
	// keyRows debounces the per-key-row usage writes (sensor_api_keys) in
	// redis mode: once per checkpoint period per sensor and address.
	keyRows keyUseDebouncer

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// SetLiveness wires the liveness store (SENSOR_LIVENESS_STORE). store is
// required for shadow and redis; ckpt and hist are used in redis mode (nil:
// checkpoints, or history, are not written). It starts the batch writer;
// FlushLiveness stops it after a last flush.
func (s *SensorService) SetLiveness(mode sensordom.LivenessMode, store sensordom.LivenessStore,
	ckpt sensordom.LivenessCheckpointer, hist sensordom.HeartbeatBatchRecorder) {
	if mode == sensordom.LivenessPostgres || store == nil {
		s.live = nil
		return
	}
	p := &livenessPlane{
		mode: mode, store: store, ckpt: ckpt, hist: hist,
		log:          s.logger.With("component", "sensor_liveness"),
		pending:      map[shared.ID]sensordom.LivenessCheckpoint{},
		aggs:         map[histKey]*sensordom.HeartbeatAggregate{},
		histFlush:    s.now(),
		kick:         make(chan struct{}, 1),
		fallbackAll:  rate.NewLimiter(rate.Limit(livenessFallbackPerSecond), livenessFallbackPerSecond),
		fallbackLast: keyUseDebouncer{window: livenessFallbackPerSensor},
		keyRows:      keyUseDebouncer{window: sensordom.LivenessCheckpointPeriod},
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
	}
	s.live = p
	go p.run(s.now)
}

// LivenessMode is the configured mode (postgres when no store is wired).
func (s *SensorService) LivenessMode() sensordom.LivenessMode {
	if s.live == nil {
		return sensordom.LivenessPostgres
	}
	return s.live.mode
}

// LivenessStore is the wired store; nil in postgres mode.
func (s *SensorService) LivenessStore() sensordom.LivenessStore {
	if s.live == nil {
		return nil
	}
	return s.live.store
}

// FlushLiveness writes what is pending and stops the batch writer (server
// shutdown). Safe to call more than once and without a store.
func (s *SensorService) FlushLiveness(ctx context.Context) {
	p := s.live
	if p == nil {
		return
	}
	p.stopOnce.Do(func() { close(p.stop) })
	select {
	case <-p.done:
	case <-ctx.Done():
	}
}

func (p *livenessPlane) redis() bool { return p != nil && p.mode == sensordom.LivenessRedis }

func (p *livenessPlane) run(now func() time.Time) {
	defer close(p.done)
	t := time.NewTicker(livenessFlushEvery)
	defer t.Stop()
	for {
		select {
		case <-p.stop:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			p.flushCheckpoints(ctx)
			p.flushHistory(ctx, now(), true)
			cancel()
			return
		case <-t.C:
		case <-p.kick:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		p.flushCheckpoints(ctx)
		p.flushHistory(ctx, now(), false)
		cancel()
	}
}

// enqueueCheckpoint adds a checkpoint row (the latest per sensor wins).
func (p *livenessPlane) enqueueCheckpoint(c sensordom.LivenessCheckpoint) {
	p.mu.Lock()
	if len(p.pending) >= maxPendingCheckpoints {
		for k := range p.pending {
			delete(p.pending, k)
			break
		}
	}
	p.pending[c.SensorID] = c
	full := len(p.pending) >= livenessFlushRows
	p.mu.Unlock()
	if full {
		select {
		case p.kick <- struct{}{}:
		default:
		}
	}
}

func (p *livenessPlane) flushCheckpoints(ctx context.Context) {
	p.mu.Lock()
	if len(p.pending) == 0 || p.ckpt == nil {
		clear(p.pending)
		p.mu.Unlock()
		return
	}
	rows := make([]sensordom.LivenessCheckpoint, 0, len(p.pending))
	for _, c := range p.pending {
		rows = append(rows, c)
	}
	clear(p.pending)
	p.mu.Unlock()
	if _, err := p.ckpt.CheckpointLiveness(ctx, rows); err != nil {
		metrics.SensorLivenessStoreErrorsTotal.WithLabelValues("checkpoint").Inc()
		p.log.Warn("sensor liveness checkpoint not written; the next one repeats it", "rows", len(rows), "error", err)
	}
}

// addHistory folds one heartbeat into the in-memory history aggregates.
func (p *livenessPlane) addHistory(sample sensordom.HeartbeatSample) {
	k := histKey{sensor: sample.SensorID, bucket: sensordom.HeartbeatBucketStart(sample.At)}
	p.mu.Lock()
	a := p.aggs[k]
	if a == nil {
		a = &sensordom.HeartbeatAggregate{TenantID: sample.TenantID, SensorID: sample.SensorID, BucketStart: k.bucket}
		p.aggs[k] = a
	}
	a.Add(sample)
	p.mu.Unlock()
}

// flushHistory writes the aggregates of closed buckets, and all of them
// every livenessHistoryFlushEvery (or when all is set).
func (p *livenessPlane) flushHistory(ctx context.Context, now time.Time, all bool) {
	current := sensordom.HeartbeatBucketStart(now)
	p.mu.Lock()
	if now.Sub(p.histFlush) >= livenessHistoryFlushEvery {
		all = true
	}
	var rows []sensordom.HeartbeatAggregate
	for k, a := range p.aggs {
		if all || k.bucket.Before(current) {
			rows = append(rows, *a)
			delete(p.aggs, k)
		}
	}
	if all {
		p.histFlush = now
	}
	p.mu.Unlock()
	if len(rows) == 0 || p.hist == nil {
		return
	}
	if err := p.hist.RecordHeartbeatBatch(ctx, rows); err != nil {
		p.log.Warn("heartbeat history batch not recorded", "rows", len(rows), "error", err)
	}
}

// allowFallback reports whether a heartbeat of a may be written to Postgres
// while the store is unreachable: at most once per sensor per
// livenessFallbackPerSensor, and within the replica's budget unless the
// sensor would otherwise reach stale before its next allowed write.
//
// The budget alone is not fail safe: the controller may still read the
// store (another replica, or reads succeed while writes fail) and judges by
// the later of the store's and Postgres's deadlines, so a sensor whose beats
// are all dropped here would be walked to stale and offline, its jobs
// released and re-run elsewhere. The per-sensor bound keeps the bypass below
// the Postgres-mode write rate.
func (p *livenessPlane) allowFallback(a *sensordom.Sensor, now time.Time) bool {
	if !p.fallbackLast.due(a.ID.String(), now) {
		return false
	}
	return p.fallbackAll.AllowN(now, 1) || fallbackUrgent(a, now)
}

// fallbackUrgent reports whether a, as last read (Postgres row with the
// store's entry overlaid when it could be read), reaches stale before its
// next allowed fallback write.
func fallbackUrgent(a *sensordom.Sensor, now time.Time) bool {
	pos := sensordom.Ladder(now, a.HeartbeatDeadline())
	if pos.State != sensordom.SensorHealthOnline && pos.State != sensordom.SensorHealthLate {
		return true
	}
	return !now.Add(livenessFallbackPerSensor + sensordom.LadderGraceFloor).Before(pos.StaleAt)
}

// checkpointEvery is one heartbeat's checkpoint period: ±10 % jitter so a
// fleet that started together does not checkpoint together.
func checkpointEvery() time.Duration {
	base := float64(sensordom.LivenessCheckpointPeriod)
	return time.Duration(base * (0.9 + 0.2*rand.Float64())) //nolint:gosec // jitter, not security
}

// heartbeatWrite is the decision for one heartbeat.
type heartbeatWrite struct {
	// full: write the heartbeat to Postgres (repo.UpdateHeartbeat).
	full bool
	kind string
	key  sensordom.LivenessKey
}

// planHeartbeatWrite records the heartbeat in the store (shadow, redis) and
// decides what Postgres gets. a is the row read for this heartbeat (with
// the store's entry overlaid in redis mode).
func (s *SensorService) planHeartbeatWrite(ctx context.Context, a *sensordom.Sensor, hb sensordom.HeartbeatUpdate, now time.Time) heartbeatWrite {
	p := s.live
	w := heartbeatWrite{full: true, kind: hbWriteFull, key: sensordom.LivenessKeyOf(a.TenantID, a.ID)}
	if p == nil {
		return w
	}
	ip := ""
	if hb.IPAddress != nil {
		ip = hb.IPAddress.String()
	}
	sctx, cancel := context.WithTimeout(ctx, livenessStoreTimeout)
	res, err := p.store.Beat(sctx, sensordom.LivenessBeat{
		Key: w.key, Interval: hb.Interval, Digest: sensordom.HeartbeatStateDigest(hb), IP: ip,
		CheckpointEvery: checkpointEvery(),
	})
	cancel()
	if err != nil {
		metrics.SensorLivenessStoreErrorsTotal.WithLabelValues("beat").Inc()
	}
	if !p.redis() {
		return w // shadow: Postgres decides, every heartbeat is written
	}
	if err != nil {
		if p.allowFallback(a, now) {
			w.kind = hbWriteFallback
			return w
		}
		return heartbeatWrite{kind: hbWriteDropped, key: w.key}
	}
	if res.Changed || a.Health != sensordom.SensorHealthOnline {
		return w
	}
	w.full = false
	w.kind = hbWriteNone
	if res.Checkpoint {
		w.kind = hbWriteCheckpoint
		p.enqueueCheckpoint(sensordom.LivenessCheckpoint{
			TenantID: a.TenantID, SensorID: a.ID,
			SeenAt: res.Now, DueAt: res.Now.Add(sensordom.ClampHeartbeatInterval(hb.Interval)),
			Interval: hb.Interval, KeyUsedAt: res.Prev.KeyUsedAt,
			Load: sensordom.LivenessLoad{
				CPUPercent: hb.CPUPercent, MemoryPercent: hb.MemoryPercent,
				DiskReadMBPS: hb.DiskReadMBPS, DiskWriteMBPS: hb.DiskWriteMBPS,
				NetworkRxMBPS: hb.NetworkRxMBPS, NetworkTxMBPS: hb.NetworkTxMBPS,
				LoadScore: hb.LoadScore, Load: hb.Load, Outbox: hb.Outbox, Control: hb.Control,
			},
		})
	}
	return w
}

// heartbeatWriteFailed undoes the store's record of the digest after a
// failed Postgres write, so the next heartbeat writes again.
func (s *SensorService) heartbeatWriteFailed(ctx context.Context, w heartbeatWrite) {
	if !s.live.redis() {
		return
	}
	sctx, cancel := context.WithTimeout(ctx, livenessStoreTimeout)
	defer cancel()
	_ = s.live.store.Invalidate(sctx, w.key)
}

// touchLiveness records a key use in the store (redis mode). It reports
// whether Postgres must record it too: no entry yet, a new address (the
// key_ip_changed event), or the store unreachable.
func (s *SensorService) touchLiveness(a *sensordom.Sensor, ip string) bool {
	if s.live == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), livenessStoreTimeout)
	defer cancel()
	exists, prev, err := s.live.store.Touch(ctx, sensordom.LivenessKeyOf(a.TenantID, a.ID), ip)
	if err != nil {
		metrics.SensorLivenessStoreErrorsTotal.WithLabelValues("touch").Inc()
		return true
	}
	if !s.live.redis() {
		return true // shadow: Postgres records every key use, as before
	}
	return !exists || (ip != "" && prev != ip)
}

// TouchPresence records that a sensor's control stream is open (a
// keepalive): proof of life without a heartbeat body (redis and shadow
// modes; nothing otherwise). Only an existing entry is touched.
func (s *SensorService) TouchPresence(ctx context.Context, tenantID *shared.ID, sensorID shared.ID) {
	if s.live == nil {
		return
	}
	sctx, cancel := context.WithTimeout(ctx, livenessStoreTimeout)
	defer cancel()
	if _, _, err := s.live.store.Touch(sctx, sensordom.LivenessKeyOf(tenantID, sensorID), ""); err != nil {
		metrics.SensorLivenessStoreErrorsTotal.WithLabelValues("touch").Inc()
	}
}
