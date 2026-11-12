package brand

import "sync/atomic"

// The instance brand, set once at startup from configuration and read by
// code that names the product deep in a call path (report footers, ticket
// comments, MCP texts). It is process configuration like the logger: no
// tenant data, the same for every request. A later per-organization brand
// is resolved per request instead (docs/architecture/brand.md).
var instance atomic.Pointer[Brand]

// SetInstance sets the instance brand. Call it once, after validation.
func SetInstance(b Brand) {
	instance.Store(&b)
}

// Instance returns the instance brand, or Default() before SetInstance.
func Instance() Brand {
	if b := instance.Load(); b != nil {
		return *b
	}
	return Default()
}

// Name is the instance brand's product name.
func Name() string { return Instance().DisplayName() }
