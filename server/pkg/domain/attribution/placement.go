package attribution

import "context"

// Placement is where a job runs: on a sensor of the tenant's own, or on a
// platform (shared) sensor. On the hosted service (MANAGED_SERVICE) only a
// job on platform sensors needs the ownership of a discovered asset
// confirmed and keeps a wildcard-only name passive: the platform sends those
// packets from its own addresses. On a tenant's own sensor, and on every
// self-hosted install, the tenant's scope entries are the authority.
// docs/architecture/scan-targets.md ("Where ownership confirmation applies").
type Placement int

const (
	// PlacementUnknown is a job whose sensor is not known yet. On the hosted
	// service it is judged as a platform job (fail closed).
	PlacementUnknown Placement = iota
	// PlacementTenant is a job for the tenant's own sensors.
	PlacementTenant
	// PlacementPlatform is a job for shared platform sensors.
	PlacementPlatform
)

type placementKey struct{}

// WithPlacement returns a context that tells the ownership gate where the
// job it checks runs. PlacementUnknown leaves the context unchanged.
func WithPlacement(ctx context.Context, p Placement) context.Context {
	if p == PlacementUnknown {
		return ctx
	}
	return context.WithValue(ctx, placementKey{}, p)
}

// PlacementOf is the placement the context carries (PlacementUnknown when
// none was set).
func PlacementOf(ctx context.Context) Placement {
	p, _ := ctx.Value(placementKey{}).(Placement)
	return p
}
