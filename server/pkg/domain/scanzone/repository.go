package scanzone

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxZonesPerTenant bounds how many zones one tenant may define, so routing
// (which loads them all per trigger) stays cheap.
const MaxZonesPerTenant = 500

// Errors. Each wraps a shared sentinel so handlers map them to HTTP codes.
var (
	ErrZoneNotFound     = fmt.Errorf("%w: scan zone not found", shared.ErrNotFound)
	ErrSensorNotFound   = fmt.Errorf("%w: sensor not found", shared.ErrNotFound)
	ErrZoneNameTaken    = shared.NewDomainError("ZONE_NAME_TAKEN", "a scan zone with this name already exists", shared.ErrAlreadyExists)
	ErrDefaultZoneTaken = shared.NewDomainError("DEFAULT_ZONE_EXISTS", "the tenant already has a default scan zone", shared.ErrAlreadyExists)
	ErrZoneInUse        = shared.NewDomainError("ZONE_IN_USE", "the scan zone has queued or running jobs; wait for them to finish or cancel them first", shared.ErrConflict)
	ErrTooManyZones     = shared.NewDomainError("TOO_MANY_ZONES", fmt.Sprintf("a tenant may define at most %d scan zones", MaxZonesPerTenant), shared.ErrValidation)
)

// ErrZoneSelectedByScans refuses deleting a zone that n scans pin their
// targets to (the zone picker).
func ErrZoneSelectedByScans(n int) error {
	return shared.NewDomainError("ZONE_IN_USE", fmt.Sprintf(
		"%d scan(s) are pinned to this scan zone; switch them to Automatic or another zone first", n), shared.ErrConflict)
}

// SensorCandidate is a sensor that can take a zone's jobs now: assigned to
// the zone, active, online, pulling jobs, key not expired.
type SensorCandidate struct {
	ID                shared.ID
	Name              string
	ActiveCommands    int // pending/acknowledged/running commands pinned to it
	CurrentJobs       int
	MaxConcurrentJobs int
	// LocalPolicy is the sensor-local policy the sensor last reported (nil:
	// never reported); the trigger pins no batch to a sensor whose policy
	// refuses it (sensor.Accepts).
	LocalPolicy *sensor.LocalPolicyReport
}

// ZoneCoverage is the coverage of one zone.
type ZoneCoverage struct {
	ZoneID          shared.ID
	Name            string
	IsDefault       bool
	HasPrivateRange bool
	AssignedSensors int
	HealthySensors  int
	Addresses       int // inventory addresses inside the zone's ranges
}

// Coverage summarizes how a tenant's inventory addresses map onto its zones.
type Coverage struct {
	InventoryAddresses int // distinct IP addresses in the asset inventory
	InZones            int // inside at least one zone range
	OutsidePublic      int // public, in no range (default zone, or pre-zone dispatch)
	OutsidePrivate     int // private, in no range: scans skip these (RFC-023 D6)
	HasDefaultZone     bool
	Zones              []ZoneCoverage
}

// Repository persists zones and their sensor assignments. Every method is
// tenant-scoped in SQL; ids from another tenant behave as not found.
type Repository interface {
	Create(ctx context.Context, z *Zone) error
	Update(ctx context.Context, z *Zone) error
	// Delete removes a zone. It returns ErrZoneInUse while commands routed to
	// the zone are still pending, acknowledged or running, or while scans pin
	// their targets to it.
	Delete(ctx context.Context, tenantID, id shared.ID) error
	GetByID(ctx context.Context, tenantID, id shared.ID) (*Zone, error)
	// List returns every zone of the tenant with its assigned sensor ids.
	List(ctx context.Context, tenantID shared.ID) ([]*Zone, error)
	Count(ctx context.Context, tenantID shared.ID) (int, error)

	// AssignSensor assigns a sensor of the same tenant to a zone (idempotent).
	// A zone or sensor of another tenant, or a platform sensor, is rejected
	// by the schema and reported as ErrZoneNotFound / ErrSensorNotFound.
	AssignSensor(ctx context.Context, tenantID, zoneID, sensorID shared.ID, assignedBy *shared.ID) error
	// UnassignSensor removes the assignment and unpins the zone's pending
	// commands from that sensor so another sensor of the zone can take them.
	// Returns false when the sensor was not assigned.
	UnassignSensor(ctx context.Context, tenantID, zoneID, sensorID shared.ID) (bool, error)

	// RoutableSensors returns, per zone, the sensors that can take a job for
	// tool now (tool "" = any), least busy first.
	RoutableSensors(ctx context.Context, tenantID shared.ID, zoneIDs []shared.ID, tool string) (map[shared.ID][]SensorCandidate, error)
	// Coverage reports inventory addresses against the zones.
	Coverage(ctx context.Context, tenantID shared.ID) (*Coverage, error)
}
