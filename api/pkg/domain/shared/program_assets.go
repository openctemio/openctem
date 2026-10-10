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

// ProgramViewer is who asks for metrics that include program-only assets:
// the private program assets of programs the viewer is not a member of stay
// out of them unless the viewer is an owner (RFC-065 §15.3).
type ProgramViewer struct {
	UserID ID
	Owner  bool
}

type programViewerKey struct{}

// WithProgramViewer records who reads program-only assets in the metrics.
func WithProgramViewer(ctx context.Context, v ProgramViewer) context.Context {
	return context.WithValue(ctx, programViewerKey{}, v)
}

// ProgramViewerOf returns the recorded viewer (false when none: an internal
// call).
func ProgramViewerOf(ctx context.Context) (ProgramViewer, bool) {
	v, ok := ctx.Value(programViewerKey{}).(ProgramViewer)
	return v, ok
}
