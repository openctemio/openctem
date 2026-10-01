package app

// Compatibility shim — real impl lives in internal/app/sensor/.
// See internal/app/audit_service.go for the pattern rationale.

import "github.com/openctemio/api/internal/app/sensor"

type (
	SensorService                     = sensor.SensorService
	SensorSelector                    = sensor.SensorSelector
	SensorConfigTemplateService       = sensor.SensorConfigTemplateService
	SensorAvailabilityResult          = sensor.SensorAvailabilityResult
	SensorHeartbeatData               = sensor.SensorHeartbeatData
	SensorHeartbeatInput              = sensor.SensorHeartbeatInput
	SensorSelectionMode               = sensor.SensorSelectionMode
	SensorTemplateData                = sensor.SensorTemplateData
	CreateSensorInput                 = sensor.CreateSensorInput
	CreateSensorOutput                = sensor.CreateSensorOutput
	ListSensorsInput                  = sensor.ListSensorsInput
	PlatformStatsOutput               = sensor.PlatformStatsOutput
	PlatformTierStats                 = sensor.PlatformTierStats
	RenderedTemplates                 = sensor.RenderedTemplates
	SelectSensorRequest               = sensor.SelectSensorRequest
	SelectSensorResult                = sensor.SelectSensorResult
	TenantAvailableCapabilitiesOutput = sensor.TenantAvailableCapabilitiesOutput
	UpdateSensorInput                 = sensor.UpdateSensorInput
)

var (
	NewSensorService               = sensor.NewSensorService
	NewSensorSelector              = sensor.NewSensorSelector
	NewSensorConfigTemplateService = sensor.NewSensorConfigTemplateService
	ErrNoSensorAvailable           = sensor.ErrNoSensorAvailable
)

// Selection-mode constants re-exported for legacy callers.
const (
	SelectTenantOnly = sensor.SelectTenantOnly
	SelectAny        = sensor.SelectAny
)
