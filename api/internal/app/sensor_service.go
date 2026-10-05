package app

// Compatibility shim — real impl lives in internal/app/sensor/.
// See internal/app/audit_service.go for the pattern rationale.

import "github.com/openctemio/openctem/api/internal/app/sensor"

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
	SensorIdentity                    = sensor.SensorIdentity
	Doorbell                          = sensor.Doorbell
	DoorbellConfig                    = sensor.DoorbellConfig
	DoorbellRequest                   = sensor.DoorbellRequest
	SensorManifestResult              = sensor.ManifestResult
)

var (
	NewSensorService               = sensor.NewSensorService
	NewSensorSelector              = sensor.NewSensorSelector
	NewSensorConfigTemplateService = sensor.NewSensorConfigTemplateService
	// LoadSensorCACertificate reads the platform CA for the install snippets.
	LoadSensorCACertificate = sensor.LoadCACertificate
	// PolicyFromZones prefills the sensor-local policy template (RFC-040).
	PolicyFromZones       = sensor.PolicyFromZones
	ErrNoSensorAvailable  = sensor.ErrNoSensorAvailable
	NewDoorbell           = sensor.NewDoorbell
	DefaultDoorbellConfig = sensor.DefaultDoorbellConfig
	// Sensor manifest (RFC-033).
	ErrManifestUnavailable    = sensor.ErrManifestUnavailable
	ErrManifestSensorInactive = sensor.ErrManifestSensorInactive
	ErrManifestNotRegistered  = sensor.ErrManifestNotRegistered
	// Sensor config report (research/26).
	ErrConfigReportUnavailable    = sensor.ErrConfigReportUnavailable
	ErrConfigReportSensorInactive = sensor.ErrConfigReportSensorInactive
)

// SensorConfigReportView is a sensor setup checklist (research/26).
type SensorConfigReportView = sensor.ConfigReportView

// Selection-mode constants re-exported for legacy callers.
const (
	SelectTenantOnly = sensor.SelectTenantOnly
	SelectAny        = sensor.SelectAny
)
