package shared

import "context"

// FindingViewer is who reads finding rows through a metrics surface (the
// dashboards) that builds its own SQL instead of compiling a findings filter.
// It carries what the findings list's member visibility rule needs: the acting
// user and whether they are an administrator (who sees every pentest finding).
// The tenant always comes from the query, never from the viewer.
type FindingViewer struct {
	UserID ID
	Admin  bool
}

type findingViewerKey struct{}

// WithFindingViewer records who reads findings in the metrics. Set it from
// the authenticated principal, never from request input.
func WithFindingViewer(ctx context.Context, v FindingViewer) context.Context {
	return context.WithValue(ctx, findingViewerKey{}, v)
}

// FindingViewerOf returns the recorded viewer (false when none: an internal
// call that is not on behalf of a user).
func FindingViewerOf(ctx context.Context) (FindingViewer, bool) {
	v, ok := ctx.Value(findingViewerKey{}).(FindingViewer)
	return v, ok
}
