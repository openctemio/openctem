package shared

import "context"

// Metrics count the attributed inventory by default (research/124, RFC-054
// §15.6): what the organization claimed or its scope entries cover. A
// request that asks for include_discovered=true counts the whole inventory,
// discovered assets included. It changes counts only, never authorization.

type includeDiscoveredAssetsKey struct{}

// WithDiscoveredAssets marks the request as counting discovered assets.
func WithDiscoveredAssets(ctx context.Context) context.Context {
	return context.WithValue(ctx, includeDiscoveredAssetsKey{}, true)
}

// DiscoveredAssetsIncluded reports whether metrics count discovered assets.
func DiscoveredAssetsIncluded(ctx context.Context) bool {
	v, _ := ctx.Value(includeDiscoveredAssetsKey{}).(bool)
	return v
}
