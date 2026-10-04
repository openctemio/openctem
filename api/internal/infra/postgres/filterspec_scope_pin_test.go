package postgres

import (
	"reflect"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
)

// TestFilterspecScopeSQLMatchesDataScopeCond pins the data-scope predicate
// the list query compiler emits (RFC-048) to the one every hand-written
// scoped read uses. A change to the scope rule (for example read-time
// expiry) must change both, or this test fails.
func TestFilterspecScopeSQLMatchesDataScopeCond(t *testing.T) {
	scope := &shared.DataScope{TenantID: shared.NewID(), UserID: shared.NewID()}
	for _, first := range []int{1, 3, 17} {
		wantSQL, wantArgs := dataScopeCondAt("f.asset_id", scope, first)
		gotSQL, gotArgs := filterspec.ScopeSQL("f.asset_id", scope, first)
		if gotSQL != wantSQL || !reflect.DeepEqual(gotArgs, wantArgs) {
			t.Fatalf("scope predicates diverged at $%d:\nfilterspec: %s %v\npostgres:   %s %v", first, gotSQL, gotArgs, wantSQL, wantArgs)
		}
	}
}
