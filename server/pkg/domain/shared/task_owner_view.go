package shared

import "context"

type taskOwnerViewKey struct{}

// WithTaskOwnerView marks a request the by-id data-scope guard admitted only
// through the task-owner relation (the caller owns a live task holding the
// finding) for a route of the fix workflow. The services that apply the data
// scope again read it (TaskOwnerView) and re-check the relation; nothing
// else honors the relation, so a route outside the fix workflow keeps the
// finding's real scope.
func WithTaskOwnerView(ctx context.Context) context.Context {
	return context.WithValue(ctx, taskOwnerViewKey{}, true)
}

// TaskOwnerView reports whether the guard admitted this request through the
// task-owner relation.
func TaskOwnerView(ctx context.Context) bool {
	v, _ := ctx.Value(taskOwnerViewKey{}).(bool)
	return v
}
