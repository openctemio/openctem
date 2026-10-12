package sensor

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/redis"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SensorAvailabilityResult represents sensor availability status.
type SensorAvailabilityResult struct {
	HasTenantSensor bool
	Available       bool
	Message         string
}

// SensorSelectionMode defines which sensors to consider.
type SensorSelectionMode string

const (
	// SelectTenantOnly only considers tenant's own sensors.
	SelectTenantOnly SensorSelectionMode = "tenant_only"
	// SelectAny selects from any available sensor.
	SelectAny SensorSelectionMode = "any"
)

var (
	// ErrNoSensorAvailable is returned when no suitable sensor is found.
	ErrNoSensorAvailable = errors.New("no suitable sensor available")
)

// metricsFreshness bounds how old a sensor's resource metrics may be before
// the selector stops trusting them. A crashed or wedged sensor keeps its last
// reported CPU/memory forever; without this guard one bad sample would
// permanently bias scheduling away from (or towards) that sensor. Sensors
// heartbeat far more often than this, so fresh sensors are unaffected.
const metricsFreshness = 5 * time.Minute

// SensorSelector handles intelligent sensor selection for job execution.
type SensorSelector struct {
	sensorRepo  sensordom.Repository
	commandRepo command.Repository
	sensorState *redis.SensorStateStore
	logger      *logger.Logger

	// weights drive selectLeastLoaded's scoring. Defaults to the compiled-in
	// weight set; SetLoadBalancingWeights installs the operator-configured
	// SENSOR_LB_* values at boot.
	weights sensordom.LoadBalancingWeights
}

// NewSensorSelector creates a new SensorSelector.
func NewSensorSelector(
	sensorRepo sensordom.Repository,
	commandRepo command.Repository,
	sensorState *redis.SensorStateStore,
	log *logger.Logger,
) *SensorSelector {
	return &SensorSelector{
		sensorRepo:  sensorRepo,
		commandRepo: commandRepo,
		sensorState: sensorState,
		logger:      log.With("service", "sensor_selector"),
		weights:     sensordom.DefaultLoadBalancingWeights(),
	}
}

// SetLoadBalancingWeights installs the operator-configured load-balancing
// weights (SENSOR_LB_*). Call once at boot, before the selector serves traffic.
// An all-zero weight set is ignored — it would score every sensor at 0 and make
// selection arbitrary.
func (s *SensorSelector) SetLoadBalancingWeights(w sensordom.LoadBalancingWeights) {
	if w.IsZero() {
		s.logger.Warn("ignoring all-zero sensor load-balancing weights; keeping defaults")
		return
	}
	s.weights = w
}

// SelectSensorRequest represents a request to select a sensor for a job.
type SelectSensorRequest struct {
	TenantID     shared.ID
	Capabilities []string
	Tool         string
	Region       string // Preferred region
	Mode         SensorSelectionMode
	AllowQueue   bool // If true, return queue info instead of error when no sensor available
}

// SelectSensorResult represents the result of sensor selection.
type SelectSensorResult struct {
	Sensor  *sensordom.Sensor
	Queued  bool
	Message string
	// TenantBusy is true when the tenant has online sensors that can run the
	// job but none has a free slot: the job waits for one of them (it is
	// never moved to shared sensors because the tenant's fleet is busy).
	TenantBusy bool
}

// SelectSensor selects the best sensor for a job based on the selection mode.
func (s *SensorSelector) SelectSensor(ctx context.Context, req SelectSensorRequest) (*SelectSensorResult, error) {
	return s.selectTenantSensor(ctx, req)
}

// selectTenantSensor selects from tenant's own sensors.
func (s *SensorSelector) selectTenantSensor(ctx context.Context, req SelectSensorRequest) (*SelectSensorResult, error) {
	// Find available tenant sensors with capacity
	sensors, err := s.sensorRepo.FindAvailableWithCapacity(ctx, req.TenantID, req.Capabilities, req.Tool)
	if err != nil {
		return nil, fmt.Errorf("failed to find tenant sensors: %w", err)
	}

	if len(sensors) == 0 {
		if req.AllowQueue {
			return &SelectSensorResult{
				Queued:  true,
				Message: "No tenant sensor available, job will be queued",
			}, nil
		}
		return nil, ErrNoSensorAvailable
	}

	// Select the best sensor (least loaded). Candidates are every capable
	// online sensor; one without a free slot is skipped.
	selected := s.selectLeastLoaded(sensors)
	if selected == nil {
		return &SelectSensorResult{
			Queued:     true,
			TenantBusy: true,
			Message:    "Tenant sensors are busy, job will be queued",
		}, nil
	}

	return &SelectSensorResult{
		Sensor:  selected,
		Message: "Tenant sensor assigned",
	}, nil
}

// selectLeastLoaded selects the sensor with the lowest weighted load score.
//
// The score is the same formula the sensor's persisted load_score column uses
// (Sensor.ComputeLoadScoreWithWeights), evaluated with the deployment's
// SENSOR_LB_* weights. Scoring here rather than reading load_score keeps the
// decision consistent even for rows written before the weights changed.
//
// Sensors at or above their concurrency limit are skipped, matching the
// previous behavior (which started at 100% load and required a strict
// improvement). Ties keep the first candidate, so selection stays stable.
func (s *SensorSelector) selectLeastLoaded(sensors []*sensordom.Sensor) *sensordom.Sensor {
	if len(sensors) == 0 {
		return nil
	}

	var best *sensordom.Sensor
	bestScore := math.MaxFloat64
	now := time.Now()

	for _, a := range sensors {
		if a.EffectiveMaxConcurrentJobs() <= 0 {
			// Sensor has no limit, assume 0 load
			return a
		}
		if a.FreeSlots(now) <= 0 {
			// No free slot (server count of its commands, narrowed by a
			// fresh load report) — never a candidate.
			continue
		}
		score := s.loadScore(a, now)
		if score < bestScore {
			best = a
			bestScore = score
		}
	}

	return best
}

// loadScore returns the weighted load score used for ranking. When the sensor
// has no fresh resource metrics only the job-load term contributes, so an
// sensor that has never reported CPU/memory is ranked purely on queue depth
// instead of being flattered by zeroed metrics.
func (s *SensorSelector) loadScore(a *sensordom.Sensor, now time.Time) float64 {
	if a.MetricsUpdatedAt == nil || now.Sub(*a.MetricsUpdatedAt) > metricsFreshness {
		return s.weights.JobLoad * a.JobLoadPercent()
	}
	return a.ComputeLoadScoreWithWeights(s.weights)
}

// CheckSensorAvailability checks if any sensor is available for the given scan configuration.
// This should be called before creating a scan to ensure execution is possible.
func (s *SensorSelector) CheckSensorAvailability(ctx context.Context, tenantID shared.ID, toolName string, tenantOnly bool) *SensorAvailabilityResult {
	result := &SensorAvailabilityResult{}

	// Check for tenant sensors (online and with capacity)
	sensors, err := s.sensorRepo.FindAvailableWithCapacity(ctx, tenantID, nil, toolName)
	if err == nil && len(sensors) > 0 {
		result.HasTenantSensor = true
	}

	// Determine overall availability
	result.Available = result.HasTenantSensor

	// Generate message
	if result.Available {
		result.Message = "Tenant sensor available"
	} else {
		result.Message = "No tenant sensor available. Deploy a sensor to execute scans."
	}

	return result
}
