package asset

import (
	"reflect"
	"testing"
)

// The service repository takes a tenant but no data scope. Convenience
// listers that wrap it must not exist on the interface: a handler wired to
// one would list services of assets the caller cannot see. Add a scoped
// lister (with the data-scope parameter) instead of reviving these.
func TestAssetServiceRepository_NoUnscopedListHelpers(t *testing.T) {
	typ := reflect.TypeOf((*AssetServiceRepository)(nil)).Elem()
	for _, name := range []string{"ListPublic", "ListHighRisk"} {
		if _, ok := typ.MethodByName(name); ok {
			t.Errorf("AssetServiceRepository.%s lists across data scope; remove it or add a scope parameter", name)
		}
	}
}
