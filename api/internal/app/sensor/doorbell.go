package sensor

// Heartbeat doorbell (docs/rfcs/RFC-023-scan-zones-and-scanners.md §9.2a).
//
// The heartbeat tells a sensor that something is waiting for it and how soon
// to ring again; it never carries the work itself. Jobs are fetched and
// claimed through GET /api/v1/agent/commands as before, so authorization,
// the zone claim predicate and claim semantics stay in one place.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
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
	// LoadedInterval is advised when the doorbell query itself was slow
	// (SlowQuery or more): the platform is under load, back off.
	LoadedInterval time.Duration
	// MinInterval and MaxInterval clamp every advised interval.
	MinInterval time.Duration
	MaxInterval time.Duration
	// SlowQuery is the doorbell query latency that counts as "under load".
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
		LoadedInterval: 120 * time.Second,
		MinInterval:    5 * time.Second,
		MaxInterval:    300 * time.Second,
		SlowQuery:      250 * time.Millisecond,
		QueryTimeout:   time.Second,
		KeyRenewBefore: 24 * time.Hour,
		PendingCap:     100,
	}
}

// Normalized returns c with every value inside safe bounds. offlineAfter is
// the health checker's heartbeat timeout: no advised interval may reach half
// of it, or a sensor that follows the advice would be marked offline between
// two heartbeats. Zero offlineAfter skips that bound.
func (c DoorbellConfig) Normalized(offlineAfter time.Duration) DoorbellConfig {
	d := DefaultDoorbellConfig()
	if c.MinInterval < time.Second {
		c.MinInterval = d.MinInterval
	}
	if c.MaxInterval <= 0 {
		c.MaxInterval = d.MaxInterval
	}
	if offlineAfter > 0 && c.MaxInterval > offlineAfter/2 {
		c.MaxInterval = offlineAfter / 2
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
	if c.LoadedInterval <= 0 {
		c.LoadedInterval = d.LoadedInterval
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
}

// Ring returns the hints for one heartbeat. It never fails: when the query
// fails or times out the result simply carries no query-derived hints.
func (d *Doorbell) Ring(ctx context.Context, req DoorbellRequest) sensordom.HeartbeatHints {
	var h sensordom.HeartbeatHints
	a := req.Identity.Sensor
	if a == nil {
		return h
	}
	idle := d.seconds(d.cfg.IdleInterval)

	if req.Identity.Paused {
		// Nothing else is computed for a paused sensor: it may take no work.
		h.Actions = []sensordom.Action{sensordom.ActionPause}
		h.NextHeartbeatSeconds = idle
		return h
	}
	if exp := req.Identity.KeyExpiresAt; exp != nil && d.cfg.KeyRenewBefore > 0 &&
		!d.now().Add(d.cfg.KeyRenewBefore).Before(*exp) {
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
		case work.Count > 0, work.RecentlyCanceled > 0:
			// Work waiting, or a command it claimed was canceled and it may
			// still be running it: ring again soon.
			interval = d.seconds(d.cfg.BusyInterval)
		case elapsed >= d.cfg.SlowQuery:
			interval = d.seconds(d.cfg.LoadedInterval)
		}
	}
	// Platform sensors (no tenant) do not use the tenant command poll, so
	// there is no pending count for them; the rest still applies.

	if req.Aware {
		h.ConfigVersion = ConfigVersion(a, req.Identity.KeyExpiresAt, zones)
		h.NextHeartbeatSeconds = interval
	} else if interval != idle {
		h.NextHeartbeatSeconds = interval
	}
	return h
}

// seconds converts an interval to whole seconds inside [Min, Max].
func (d *Doorbell) seconds(v time.Duration) int {
	if v < d.cfg.MinInterval {
		v = d.cfg.MinInterval
	}
	if v > d.cfg.MaxInterval {
		v = d.cfg.MaxInterval
	}
	return int(math.Round(v.Seconds()))
}

// ConfigVersion is an opaque, stable digest of what the platform governs
// about a sensor: capabilities, tools, concurrency, execution mode, the
// operator-set config, the presented key's expiry and the assigned zones
// (each with its last change). It changes when any of those changes and only
// then; heartbeat metrics and last-seen times are not part of it.
func ConfigVersion(a *sensordom.Sensor, keyExpiresAt *time.Time, zoneFingerprint string) string {
	caps := append([]string(nil), a.Capabilities...)
	tools := append([]string(nil), a.Tools...)
	sort.Strings(caps)
	sort.Strings(tools)
	cfg, _ := json.Marshal(a.Config) // map keys are emitted sorted
	exp := ""
	if keyExpiresAt != nil {
		exp = keyExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	var b strings.Builder
	for _, part := range []string{
		"caps=" + strings.Join(caps, ","),
		"tools=" + strings.Join(tools, ","),
		"max_jobs=" + strconv.Itoa(a.MaxConcurrentJobs),
		"mode=" + string(a.ExecutionMode),
		"config=" + string(cfg),
		"key_expires=" + exp,
		"zones=" + zoneFingerprint,
	} {
		b.WriteString(part)
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

// sanitizeLogValue strips line breaks before a value reaches the log.
func sanitizeLogValue(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "\r", " ")
}
