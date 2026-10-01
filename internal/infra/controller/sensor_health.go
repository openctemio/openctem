package controller

import (
	"context"
	"time"

	auditapp "github.com/openctemio/api/internal/app/audit"
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

// SensorHealthController periodically checks sensor health and marks stale sensors as offline.
// This is a K8s-style controller that reconciles the desired state (sensors with recent
// heartbeats are online, sensors without recent heartbeats are offline) with the actual state.
type SensorHealthController struct {
	sensorRepo   sensor.Repository
	auditService *auditapp.AuditService
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
			c.auditDisconnect(ctx, sensorID)
		}
	}

	return len(offlineSensorIDs), nil
}

// auditDisconnect records a sensor.disconnected event for a single sensor that
// this tick transitioned to offline. MarkStaleSensorsOffline only returns sensors
// whose health WAS online (its WHERE clause), so this is a genuine online->offline
// transition — repeated reconciles never re-emit for an already-offline sensor.
//
// Tenant sensors only: platform sensors (TenantID == nil) are shared infrastructure
// with no owning tenant to scope the audit log to. Best-effort — a failure to
// resolve or log must not abort the reconcile.
func (c *SensorHealthController) auditDisconnect(ctx context.Context, sensorID shared.ID) {
	if c.auditService == nil {
		return
	}

	a, err := c.sensorRepo.GetByID(ctx, sensorID)
	if err != nil {
		c.logger.Warn("could not load sensor for disconnect audit",
			"controller", "sensor-health",
			"sensor_id", sensorID,
			"error", err,
		)
		return
	}
	if a.TenantID == nil {
		return // platform sensor — no tenant to scope the audit event to
	}

	_ = c.auditService.LogSensorDisconnected(ctx, auditapp.AuditContext{
		TenantID:   a.TenantID.String(),
		ActorEmail: sensorAuditSystemActor,
	}, a.ID.String(), a.Name)
}
