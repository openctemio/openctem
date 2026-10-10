package shared

import "context"

// Program-only assets (RFC-065 §16.5) are left out of the organization's
// dashboards and metrics unless the request asks for them.

type includeProgramAssetsKey struct{}

// WithProgramAssets marks a context whose metrics include program-only
// assets.
func WithProgramAssets(ctx context.Context) context.Context {
	return context.WithValue(ctx, includeProgramAssetsKey{}, true)
}

// ProgramAssetsIncluded reports whether metrics include program-only assets.
func ProgramAssetsIncluded(ctx context.Context) bool {
	v, _ := ctx.Value(includeProgramAssetsKey{}).(bool)
	return v
}
