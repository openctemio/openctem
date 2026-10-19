package sensor

// Heartbeat doorbell (docs/rfcs/RFC-023-scan-zones-and-scanners.md §9.2a).
//
// The heartbeat tells a sensor that something is waiting for it and how soon
// to ring again; it never carries the work itself. Jobs are fetched and
// claimed through GET /api/v2/sensor/commands, so authorization,
// the zone claim predicate and claim semantics stay in one place.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/rand/v2"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// PendingWorkSource reads the doorbell's facts for one sensor in a single
// query. Implemented by postgres.CommandRepository.
type PendingWorkSource interface {
	PendingWorkForSensor(ctx context.Context, tenantID, sensorID shared.ID, capabilities []string, limit int) (sensordom.PendingWork, error)
}

// DoorbellConfig bounds what the doorbell advises. Durations, sent to sensors
// as whole seconds.
type DoorbellConfig struct {
	// IdleInterval is the advised interval when nothing is waiting.
	IdleInterval time.Duration
	// BusyInterval is the advised interval while work is waiting, so the
	// sensor hears about the next job soon after claiming the current ones.
	BusyInterval time.Duration
	// MinInterval and MaxInterval clamp every advised interval. Normalized
	// caps MaxInterval at the derived bound (MaxIntervalBound).
	MinInterval time.Duration
	MaxInterval time.Duration
	// SlowQuery is the doorbell query latency that counts as "under load":
	// the doorbell then advises MaxInterval, the longest safe interval.
	SlowQuery time.Duration
	// QueryTimeout caps the doorbell query; on timeout the heartbeat
	// succeeds without hints.
	QueryTimeout time.Duration
	// KeyRenewBefore rings rotate_key once the presented key expires within
	// this window. Zero disables rotate_key.
	KeyRenewBefore time.Duration
	// PendingCap caps pending_jobs (and bounds the count query).
	PendingCap int
}

// DefaultDoorbellConfig is the configuration the server runs with when no
// SENSOR_HEARTBEAT_* variable is set.
func DefaultDoorbellConfig() DoorbellConfig {
	return DoorbellConfig{
		IdleInterval:   30 * time.Second,
		BusyInterval:   5 * time.Second,
		MinInterval:    5 * time.Second,
		MaxInterval:    300 * time.Second,
		SlowQuery:      250 * time.Millisecond,
		QueryTimeout:   time.Second,
		KeyRenewBefore: 24 * time.Hour,
		PendingCap:     100,
	}
}

// MaxIntervalBound is the longest interval the doorbell may ever advise,
// derived rather than configured: min(offlineAfter/2, lease/3).
//
//   - offlineAfter is the health checker's offline mark: an interval of half
//     of it or more would get a sensor that follows the advice marked offline
//     between two heartbeats.
//   - lease is the command lease, renewed by each heartbeat: at lease/3 a
//     sensor holding a command renews it at least twice before it runs out,
//     so one lost or late heartbeat never re-queues a running command (which
//     would run it twice).
//
// A zero argument skips its bound; with both zero there is no bound (0).
func MaxIntervalBound(offlineAfter, lease time.Duration) time.Duration {
	var bound time.Duration
	if offlineAfter > 0 {
		bound = offlineAfter / 2
	}
	if lease > 0 && (bound == 0 || lease/3 < bound) {
		bound = lease / 3
	}
	return bound
}

// Normalized returns c with every value inside safe bounds. No advised
// interval, MinInterval included, exceeds MaxIntervalBound(offlineAfter,
// lease), whatever the configured values.
func (c DoorbellConfig) Normalized(offlineAfter, lease time.Duration) DoorbellConfig {
	d := DefaultDoorbellConfig()
	if c.MinInterval < time.Second {
		c.MinInterval = d.MinInterval
	}
	if c.MaxInterval <= 0 {
		c.MaxInterval = d.MaxInterval
	}
	if bound := MaxIntervalBound(offlineAfter, lease); bound > 0 {
		c.MaxInterval = min(c.MaxInterval, bound)
		c.MinInterval = min(c.MinInterval, bound)
	}
	if c.MaxInterval < c.MinInterval {
		c.MaxInterval = c.MinInterval
	}
	// Unset intervals take the default; Ring clamps every one into [Min, Max].
	if c.IdleInterval <= 0 {
		c.IdleInterval = d.IdleInterval
	}
	if c.BusyInterval <= 0 {
		c.BusyInterval = d.BusyInterval
	}
	if c.SlowQuery <= 0 {
		c.SlowQuery = d.SlowQuery
	}
	if c.QueryTimeout <= 0 {
		c.QueryTimeout = d.QueryTimeout
	}
	if c.KeyRenewBefore < 0 {
		c.KeyRenewBefore = 0
	}
	if c.PendingCap <= 0 {
		c.PendingCap = d.PendingCap
	}
	return c
}

// Doorbell computes heartbeat hints.
type Doorbell struct {
	src    PendingWorkSource
	cfg    DoorbellConfig
	logger *logger.Logger
	now    func() time.Time
	grants GrantSource
	keyset func() string
	// fleet is the live fleet size (SetFleetSize); nil: unknown.
	fleet *fleetSize
	// jitter is the fraction ±jitter applied to every advised interval
	// (0: none).
	jitter float64
	rnd    func() float64
}

// heartbeatBudgetPerSecond is the heartbeats per second per API replica
// the platform plans for (RFC-074 D3): the idle interval stretches once the
// live fleet would exceed it.
const heartbeatBudgetPerSecond = 50

// fleetCacheTTL is how long a fleet count is reused.
const fleetCacheTTL = 30 * time.Second

// fleetSize caches the live fleet size and the replica count.
type fleetSize struct {
	count    func(ctx context.Context) (int64, error)
	replicas func() int
	mu       sync.Mutex
	n        int64
	at       time.Time
}

func (f *fleetSize) get(ctx context.Context, now time.Time) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.at.IsZero() && now.Sub(f.at) < fleetCacheTTL {
		return f.n
	}
	f.at = now
	cctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if n, err := f.count(cctx); err == nil {
		f.n = n
	}
	return f.n
}

// SetFleetSize makes the idle interval follow the fleet size: at least
// fleet / (heartbeatBudgetPerSecond × replicas) seconds, inside the safe
// bounds (the platform decides; RFC-074). count is the live fleet (the
// liveness store's due index); replicas the API replicas serving sensors
// (nil: one).
func (d *Doorbell) SetFleetSize(count func(ctx context.Context) (int64, error), replicas func() int) {
	if count == nil {
		d.fleet = nil
		return
	}
	d.fleet = &fleetSize{count: count, replicas: replicas}
}

// SetJitter spreads every advised interval by ±fraction (bounded to
// [0, 0.5]); the result still never exceeds MaxInterval.
func (d *Doorbell) SetJitter(fraction float64) {
	d.jitter = min(max(fraction, 0), 0.5)
	if d.rnd == nil {
		d.rnd = rand.Float64
	}
}

// idleInterval is the advised idle interval: the configured one, stretched
// when the fleet would exceed the heartbeat budget.
func (d *Doorbell) idleInterval(ctx context.Context) time.Duration {
	idle := d.cfg.IdleInterval
	if d.fleet == nil {
		return idle
	}
	replicas := 1
	if d.fleet.replicas != nil {
		replicas = max(d.fleet.replicas(), 1)
	}
	n := d.fleet.get(ctx, d.now())
	if n <= 0 {
		return idle
	}
	need := time.Duration(float64(n) / float64(heartbeatBudgetPerSecond*replicas) * float64(time.Second))
	return max(idle, need)
}

// GrantSource reads a sensor's grant: the doorbell rings a gated action
// (rotate_key, update, diagnostics) only when the grant lists it
// (RFC-052 §5.3). Narrowing actions (pause, drain, cancel) always ring.
type GrantSource interface {
	Get(ctx context.Context, tenantID, sensorID shared.ID) (*sensordom.Grant, error)
}

// SetGrants makes the doorbell drop gated actions the sensor's grant does
// not list. A grant that cannot be read drops them too (fail closed).
func (d *Doorbell) SetGrants(g GrantSource) { d.grants = g }

// SetKeySetVersion makes config_version change when the job signer's key
// set changes (RFC-040 §5.6), so a sensor re-reads hello and picks up a
// rotated or revoked signer key. v must not block.
func (d *Doorbell) SetKeySetVersion(v func() string) { d.keyset = v }

// mayRing reports whether action may go to the sensor.
func (d *Doorbell) mayRing(ctx context.Context, a *sensordom.Sensor, action sensordom.Action) bool {
	if d.grants == nil {
		return true
	}
	if a.TenantID == nil {
		return false
	}
	g, err := d.grants.Get(ctx, *a.TenantID, a.ID)
	if err != nil || g == nil {
		return false
	}
	return g.MayReceiveAction(string(action))
}

// NewDoorbell builds a doorbell over src. cfg should already be Normalized.
func NewDoorbell(src PendingWorkSource, cfg DoorbellConfig, log *logger.Logger) *Doorbell {
	return &Doorbell{src: src, cfg: cfg, logger: log.With("component", "heartbeat_doorbell"), now: time.Now}
}

// DoorbellRequest is one heartbeat as the doorbell sees it.
type DoorbellRequest struct {
	Identity SensorIdentity
	// Aware is true when the sensor announced the doorbell feature. Only an
	// aware sensor gets the hints that are present on every heartbeat
	// (config_version, the idle next_heartbeat_seconds) or that replace an
	// error (pause for a disabled sensor); a sensor that did not ask sees
	// exactly the v1 response unless there is news (work or an action).
	Aware bool
	// NoFreeSlots is true when the heartbeat's load report says every slot
	// is taken: waiting work is no reason to ring again soon.
	NoFreeSlots bool
	// Streaming is true when the heartbeat came over the gRPC binding,
	// whose control stream wakes the sensor when work arrives: waiting work
	// is no reason to poll faster.
	Streaming bool
}

// Ring returns the hints for one heartbeat. It never fails: when the query
// fails or times out the result simply carries no query-derived hints.
func (d *Doorbell) Ring(ctx context.Context, req DoorbellRequest) sensordom.HeartbeatHints {
	var h sensordom.HeartbeatHints
	a := req.Identity.Sensor
	if a == nil {
		return h
	}
	idle := d.seconds(d.idleInterval(ctx))

	if req.Identity.Paused {
		// Nothing else is computed for a paused sensor: it may take no work.
		h.Actions = []sensordom.Action{sensordom.ActionPause}
		h.NextHeartbeatSeconds = idle
		return h
	}
	if exp := req.Identity.KeyExpiresAt; exp != nil && d.cfg.KeyRenewBefore > 0 &&
		!d.now().Add(d.cfg.KeyRenewBefore).Before(*exp) && d.mayRing(ctx, a, sensordom.ActionRotateKey) {
		h.Actions = append(h.Actions, sensordom.ActionRotateKey)
	}

	interval := idle
	zones := ""
	if a.TenantID != nil && d.src != nil {
		qctx, cancel := context.WithTimeout(ctx, d.cfg.QueryTimeout)
		start := time.Now()
		work, err := d.src.PendingWorkForSensor(qctx, *a.TenantID, a.ID, a.EffectiveCapabilities(), d.cfg.PendingCap)
		elapsed := time.Since(start)
		cancel()
		if err != nil {
			// The heartbeat itself must not fail: answer without hints.
			d.logger.Warn("heartbeat doorbell query failed; answering without hints",
				"sensor_id", a.ID.String(), "error", sanitizeLogValue(err.Error()))
			return h
		}
		h.PendingJobs = work.Count
		zones = work.ZoneFingerprint
		switch {
		case work.RecentlyCanceled > 0,
			work.Count > 0 && !req.NoFreeSlots && !req.Streaming:
			// A command it claimed was canceled and it may still be
			// running it, or work is waiting that it has room for and no
			// stream would wake it for: ring again soon.
			interval = d.seconds(d.cfg.BusyInterval)
		case elapsed >= d.cfg.SlowQuery:
			// The platform is under load: back off as far as is safe.
			interval = d.seconds(d.cfg.MaxInterval)
		}
	}
	// Platform sensors (no tenant) do not use the tenant command poll, so
	// there is no pending count for them; the rest still applies.

	if req.Aware {
		keyset := ""
		if d.keyset != nil {
			keyset = d.keyset()
		}
		h.ConfigVersion = ConfigVersion(a, req.Identity.KeyExpiresAt, zones, keyset)
		h.NextHeartbeatSeconds = d.jittered(interval)
	} else if interval != idle {
		h.NextHeartbeatSeconds = d.jittered(interval)
	}
	return h
}

// jittered spreads an advised interval by ±jitter, inside [Min, Max].
func (d *Doorbell) jittered(seconds int) int {
	if d.jitter <= 0 || d.rnd == nil || seconds <= 0 {
		return seconds
	}
	f := float64(seconds) * (1 + d.jitter*(2*d.rnd()-1))
	return d.seconds(time.Duration(f * float64(time.Second)))
}

// seconds converts an interval to whole seconds inside [Min, Max].
func (d *Doorbell) seconds(v time.Duration) int {
	if v < d.cfg.MinInterval {
		v = d.cfg.MinInterval
	}
	if v > d.cfg.MaxInterval {
		v = d.cfg.MaxInterval
	}
	n := int(math.Round(v.Seconds()))
	if time.Duration(n)*time.Second > d.cfg.MaxInterval {
		// Rounding up must not cross the maximum (a lease/3 that is not a
		// whole number of seconds): round down instead.
		n = int(d.cfg.MaxInterval / time.Second)
	}
	return n
}

// ConfigVersion is an opaque, stable digest of what the platform governs
// about a sensor: capabilities, concurrency, execution mode, the
// operator-set config, the presented key's expiry, the assigned zones
// (each with its last change) and the job signer's key set (when one is
// served). It changes when any of those changes and only then; heartbeat
// metrics and last-seen times are not part of it.
func ConfigVersion(a *sensordom.Sensor, keyExpiresAt *time.Time, zoneFingerprint, keySetVersion string) string {
	caps := append([]string(nil), a.Capabilities...)
	sort.Strings(caps)
	cfg, _ := json.Marshal(a.Config) // map keys are emitted sorted
	exp := ""
	if keyExpiresAt != nil {
		exp = keyExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	var b strings.Builder
	for _, part := range []string{
		"caps=" + strings.Join(caps, ","),
		"max_jobs=" + strconv.Itoa(a.MaxConcurrentJobs),
		"mode=" + string(a.ExecutionMode),
		"config=" + string(cfg),
		"key_expires=" + exp,
		"zones=" + zoneFingerprint,
	} {
		b.WriteString(part)
		b.WriteByte('\n')
	}
	// Only present with a key set, so the value is unchanged without one.
	if keySetVersion != "" {
		b.WriteString("keyset=" + keySetVersion + "\n")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

// sanitizeLogValue strips line breaks before a value reaches the log.
func sanitizeLogValue(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "\r", " ")
}
