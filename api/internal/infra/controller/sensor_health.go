package controller

// Sensor health: the heartbeat ladder
// (docs/rfcs/RFC-035-sensor-control-plane-under-load.md §5.6, owner decisions
// D1 and D3).

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/outbox"
	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// sensorAuditSystemActor is the actor recorded on sensor lifecycle audit events
// emitted by this background controller (no user request behind them). LogEvent
// treats an empty ActorID + non-empty email as a system action.
const sensorAuditSystemActor = "system"

// SensorHealthControllerConfig configures the SensorHealthController.
type SensorHealthControllerConfig struct {
	// Interval is how often to run the health check.
	// Default: 30 seconds.
	Interval time.Duration

	// StaleTimeout is no longer a conviction threshold: each sensor is judged
	// against its own heartbeat deadline (pkg/domain/sensor/liveness.go).
	// Kept for the configuration surface; it only appears in logs.
	StaleTimeout time.Duration

	// Logger for logging.
	Logger *logger.Logger
}

// SensorOfflineNotifier is the slice of the notification outbox the controller
// needs to announce a sensor going offline.
type SensorOfflineNotifier interface {
	Enqueue(ctx context.Context, params outbox.EnqueueParams) error
}

// sensorOfflineSeverity is the outbox severity of a sensor.offline event. It
// matches the event_types catalog default and clears the default
// critical+high integration filter: a scanner that stopped reporting means
// scans silently stop running.
const sensorOfflineSeverity = "high"

// SensorHealthController walks sensors down the heartbeat ladder each tick:
// online -> late -> stale -> offline, each step judged against the sensor's
// own stored deadline (sensor.Ladder). Only the offline step is announced
// (sensor.offline notification, audit and activity events), and it is held
// while the platform itself is degraded (PlatformHealth).
type SensorHealthController struct {
	sensorRepo   sensor.Repository
	liveness     sensor.LivenessRepository
	auditService *auditapp.AuditService
	notifier     SensorOfflineNotifier
	events       SensorOfflineRecorder
	platform     *sensorapp.PlatformHealth
	config       *SensorHealthControllerConfig
	logger       *logger.Logger
}

// NewSensorHealthController creates a new SensorHealthController.
//
// auditService is optional (nil-safe): when provided, each sensor that
// transitions to offline is recorded as a sensor.disconnected event in the
// tamper-evident audit_logs so the Sensor detail UI can show lifecycle history.
func NewSensorHealthController(
	sensorRepo sensor.Repository,
	auditService *auditapp.AuditService,
	config *SensorHealthControllerConfig,
) *SensorHealthController {
	if config == nil {
		config = &SensorHealthControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 30 * time.Second
	}
	if config.StaleTimeout == 0 {
		config.StaleTimeout = 90 * time.Second
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}

	liveness, _ := sensorRepo.(sensor.LivenessRepository)
	return &SensorHealthController{
		sensorRepo:   sensorRepo,
		liveness:     liveness,
		auditService: auditService,
		config:       config,
		logger:       config.Logger,
	}
}

// SetNotifier wires the notification outbox. Optional: without it the
// controller still marks sensors offline and writes the audit event.
func (c *SensorHealthController) SetNotifier(n SensorOfflineNotifier) {
	c.notifier = n
}

// SetPlatformHealth wires the platform-health guard: while it reports the
// platform degraded no sensor is moved to offline (RFC-035 D3). Optional:
// without it the controller convicts whenever the ladder says so.
func (c *SensorHealthController) SetPlatformHealth(p *sensorapp.PlatformHealth) {
	c.platform = p
}

// SensorOfflineRecorder records the offline transition on the sensor's
// activity timeline.
type SensorOfflineRecorder interface {
	RecordOffline(ctx context.Context, a *sensor.Sensor)
}

// SetEventRecorder wires the activity timeline. Optional.
func (c *SensorHealthController) SetEventRecorder(r SensorOfflineRecorder) {
	c.events = r
}

// Name returns the controller name.
func (c *SensorHealthController) Name() string {
	return "sensor-health"
}

// Interval returns the reconciliation interval.
func (c *SensorHealthController) Interval() time.Duration {
	return c.config.Interval
}

// errNoLivenessRepository: the repository cannot list deadlines, so the
// controller cannot judge anyone. Loud on purpose: a controller that silently
// does nothing leaves dead sensors online forever.
var errNoLivenessRepository = fmt.Errorf("sensor-health: the sensor repository does not implement sensor.LivenessRepository")

// Reconcile places every watched sensor (online, late or stale) on the
// ladder and stores the steps that changed. Moves to offline are held while
// the platform-health guard reports the platform degraded; such a sensor is
// moved to stale instead (or left there). Returns the number of sensors
// moved.
func (c *SensorHealthController) Reconcile(ctx context.Context) (int, error) {
	if c.liveness == nil {
		c.logger.Error("cannot check sensor heartbeats", "controller", "sensor-health", "error", errNoLivenessRepository)
		return 0, errNoLivenessRepository
	}
	hold := c.platform.HoldConvictions(c.config.Interval)

	now, candidates, err := c.liveness.ListLivenessCandidates(ctx)
	if err != nil {
		c.logger.Error("failed to list sensor heartbeat deadlines",
			"controller", "sensor-health",
			"error", err,
		)
		return 0, err
	}

	moves := map[sensor.SensorHealth][]sensor.LivenessCandidate{}
	held := 0
	for _, cand := range candidates {
		next := sensor.Ladder(now, cand.Deadline).State
		if next == sensor.SensorHealthOffline && hold != "" {
			held++
			next = sensor.SensorHealthStale
		}
		if next == cand.Health || next == sensor.SensorHealthOnline {
			// Only a request brings a sensor back online (it sets health
			// itself); the controller only moves sensors down the ladder.
			continue
		}
		moves[next] = append(moves[next], cand)
	}
	if held > 0 {
		c.logger.Warn("holding sensor offline convictions while the platform is degraded",
			"controller", "sensor-health",
			"sensors", held,
			"reason", hold,
		)
	}

	total := 0
	var firstErr error
	for _, step := range []sensor.SensorHealth{sensor.SensorHealthLate, sensor.SensorHealthStale, sensor.SensorHealthOffline} {
		ids, err := c.liveness.ApplyLiveness(ctx, step, moves[step])
		if err != nil {
			c.logger.Error("failed to move sensors down the heartbeat ladder",
				"controller", "sensor-health",
				"health", step,
				"error", err,
			)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		total += len(ids)
		if len(ids) == 0 {
			continue
		}
		c.logger.Info("sensors moved down the heartbeat ladder",
			"controller", "sensor-health",
			"health", step,
			"count", len(ids),
		)
		if step == sensor.SensorHealthOffline {
			for _, sensorID := range ids {
				c.onOffline(ctx, sensorID)
			}
		}
	}
	return total, firstErr
}

// onOffline records a sensor.disconnected audit event and enqueues a
// sensor.offline notification for a single sensor that this tick transitioned
// to offline. ApplyLiveness only returns sensors whose health WAS online, late
// or stale, so this is a genuine transition to offline — repeated reconciles
// never re-emit for an already-offline sensor, and a sensor that comes back
// and drops again is a new episode that notifies again.
//
// Tenant sensors only: platform sensors (TenantID == nil) are shared
// infrastructure with no owning tenant to scope the audit log or the
// notification to. Best-effort — a failure to resolve, log or enqueue must not
// abort the reconcile.
func (c *SensorHealthController) onOffline(ctx context.Context, sensorID shared.ID) {
	if c.auditService == nil && c.notifier == nil && c.events == nil {
		return
	}

	a, err := c.sensorRepo.GetByID(ctx, sensorID)
	if err != nil {
		c.logger.Warn("could not load sensor that went offline",
			"controller", "sensor-health",
			"sensor_id", sensorID,
			"error", err,
		)
		return
	}
	if a.TenantID == nil || a.IsPlatformSensor {
		// A platform sensor is shared infrastructure, not the sensor of the
		// tenant its row carries: no tenant audit row or notification.
		return
	}

	if c.auditService != nil {
		if err := c.auditService.LogSensorDisconnected(ctx, auditapp.AuditContext{
			TenantID:   a.TenantID.String(),
			ActorEmail: sensorAuditSystemActor,
		}, a.ID.String(), a.Name); err != nil {
			c.logger.Warn("failed to write sensor.disconnected audit event",
				"controller", "sensor-health", "sensor_id", a.ID, "error", err)
		}
	}

	if c.events != nil {
		c.events.RecordOffline(ctx, a)
	}

	if c.notifier != nil {
		c.notifyOffline(ctx, a)
	}
}

// notifyOffline enqueues the sensor.offline notification through the outbox,
// so delivery to the tenant's channels gets the outbox's retries.
func (c *SensorHealthController) notifyOffline(ctx context.Context, a *sensor.Sensor) {
	aggregateID, err := uuid.Parse(a.ID.String())
	if err != nil {
		return
	}

	lastSeen := "never"
	pos := sensor.Ladder(time.Now(), a.HeartbeatDeadline())
	silentFor := sensor.OfflineDistance(pos.Interval)
	metadata := map[string]any{
		"sensor_id":          a.ID.String(),
		"sensor_name":        a.Name,
		"heartbeat_interval": pos.Interval.String(),
		"offline_after":      silentFor.String(),
	}
	if a.LastSeenAt != nil {
		lastSeen = a.LastSeenAt.UTC().Format(time.RFC3339)
		metadata["last_seen_at"] = lastSeen
	}
	if a.Hostname != "" {
		metadata["hostname"] = a.Hostname
	}
	if a.IPAddress != nil {
		metadata["ip_address"] = a.IPAddress.String()
	}

	err = c.notifier.Enqueue(ctx, outbox.EnqueueParams{
		TenantID:      *a.TenantID,
		EventType:     string(integration.EventTypeSensorOffline),
		AggregateType: "sensor",
		AggregateID:   &aggregateID,
		Title:         fmt.Sprintf("Sensor offline: %s", a.Name),
		Body: fmt.Sprintf("Sensor '%s' has not sent a heartbeat for more than %s (it heartbeats every %s; last seen: %s). "+
			"Scans routed to it will not run until it reconnects.", a.Name, silentFor, pos.Interval, lastSeen),
		Severity: sensorOfflineSeverity,
		URL:      "/sensors",
		Metadata: metadata,
	})
	if err != nil {
		c.logger.Warn("failed to enqueue sensor.offline notification",
			"controller", "sensor-health",
			"sensor_id", a.ID,
			"error", err,
		)
	}
}
