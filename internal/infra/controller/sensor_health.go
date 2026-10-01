package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	auditapp "github.com/openctemio/api/internal/app/audit"
	"github.com/openctemio/api/internal/app/outbox"
	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
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

	// StaleTimeout is how long since last heartbeat before marking a sensor as offline.
	// Default: 90 seconds (1.5x the typical heartbeat interval of 60s).
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

// SensorHealthController periodically checks sensor health and marks stale sensors as offline.
// This is a K8s-style controller that reconciles the desired state (sensors with recent
// heartbeats are online, sensors without recent heartbeats are offline) with the actual state.
type SensorHealthController struct {
	sensorRepo   sensor.Repository
	auditService *auditapp.AuditService
	notifier     SensorOfflineNotifier
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

	return &SensorHealthController{
		sensorRepo:   sensorRepo,
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

// Name returns the controller name.
func (c *SensorHealthController) Name() string {
	return "sensor-health"
}

// Interval returns the reconciliation interval.
func (c *SensorHealthController) Interval() time.Duration {
	return c.config.Interval
}

// Reconcile checks sensor health and marks stale sensors as offline.
// Uses the MarkStaleSensorsOffline method which also updates last_offline_at timestamp.
func (c *SensorHealthController) Reconcile(ctx context.Context) (int, error) {
	// Mark stale sensors as offline (based on last_seen_at)
	// This also updates last_offline_at timestamp for historical queries
	offlineSensorIDs, err := c.sensorRepo.MarkStaleSensorsOffline(ctx, c.config.StaleTimeout)
	if err != nil {
		c.logger.Error("failed to mark stale sensors as offline",
			"controller", "sensor-health",
			"error", err,
		)
		return 0, err
	}

	if len(offlineSensorIDs) > 0 {
		c.logger.Info("marked stale sensors as offline",
			"controller", "sensor-health",
			"count", len(offlineSensorIDs),
			"stale_timeout", c.config.StaleTimeout,
		)
		for _, sensorID := range offlineSensorIDs {
			c.logger.Debug("sensor marked offline due to heartbeat timeout",
				"controller", "sensor-health",
				"sensor_id", sensorID,
				"stale_timeout", c.config.StaleTimeout,
			)
			c.onOffline(ctx, sensorID)
		}
	}

	return len(offlineSensorIDs), nil
}

// onOffline records a sensor.disconnected audit event and enqueues a
// sensor.offline notification for a single sensor that this tick transitioned
// to offline. MarkStaleSensorsOffline only returns sensors whose health WAS
// online (its WHERE clause), so this is a genuine online->offline transition —
// repeated reconciles never re-emit for an already-offline sensor, and a sensor
// that comes back and drops again is a new episode that notifies again.
//
// Tenant sensors only: platform sensors (TenantID == nil) are shared
// infrastructure with no owning tenant to scope the audit log or the
// notification to. Best-effort — a failure to resolve, log or enqueue must not
// abort the reconcile.
func (c *SensorHealthController) onOffline(ctx context.Context, sensorID shared.ID) {
	if c.auditService == nil && c.notifier == nil {
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
	if a.TenantID == nil {
		return // platform sensor — no tenant to scope the events to
	}

	if c.auditService != nil {
		_ = c.auditService.LogSensorDisconnected(ctx, auditapp.AuditContext{
			TenantID:   a.TenantID.String(),
			ActorEmail: sensorAuditSystemActor,
		}, a.ID.String(), a.Name)
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
	metadata := map[string]any{
		"sensor_id":     a.ID.String(),
		"sensor_name":   a.Name,
		"stale_timeout": c.config.StaleTimeout.String(),
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
		Body: fmt.Sprintf("Sensor '%s' has not sent a heartbeat for more than %s (last seen: %s). "+
			"Scans routed to it will not run until it reconnects.", a.Name, c.config.StaleTimeout, lastSeen),
		Severity: sensorOfflineSeverity,
		URL:      "/agents",
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
