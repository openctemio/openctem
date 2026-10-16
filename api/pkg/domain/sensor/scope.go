package sensor

// Sensor scopes (docs/rfcs/RFC-100-shared-sensors.md §3): who owns a sensor.
// The value is stored in sensors.scope and fixed when the sensor is created.

// Scope says who owns a sensor.
type Scope string

const (
	// ScopeOrganization: the sensor belongs to one organization (TenantID).
	ScopeOrganization Scope = "organization"
	// ScopeInstance: a shared sensor that belongs to the instance. It has no
	// tenant and is never visible on the tenant plane.
	ScopeInstance Scope = "instance"
)

// IsValid reports whether s is a known scope.
func (s Scope) IsValid() bool {
	return s == ScopeOrganization || s == ScopeInstance
}

// String returns the stored value.
func (s Scope) String() string {
	return string(s)
}
