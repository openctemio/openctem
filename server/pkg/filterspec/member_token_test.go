package filterspec

import (
	"strings"
	"testing"
)

// MemberToken in a field's SQL and SortSQL renders TRUE for a member and
// FALSE for an administrator, in a filter, a sort and a bool template alike,
// so a count that applies a member rule cannot be read around through any
// of them. UserToken in the same SQL is bound, never spliced.
func TestMemberToken_RenderedInFilterSortAndBool(t *testing.T) {
	const count = "(SELECT count(*) FROM x WHERE x.a = a.id AND (NOT {member} OR x.owner = {user}))"
	reg, err := NewRegistry(Registry{Name: "assets", TenantSQL: "a.tenant_id", ScopeAssetSQL: "a.id", IDSQL: "a.id"},
		Field{Name: "open_count", Type: TypeInt, Ops: []Op{OpGte}, SQL: count, Sortable: true},
		Field{Name: "has_open", Type: TypeBool, Ops: []Op{OpEq}, SQL: "a.id", BoolTemplate: "EXISTS (SELECT 1 FROM x WHERE (NOT {member} OR x.owner = {user}))"})
	if err != nil {
		t.Fatal(err)
	}
	spec := &Spec{
		Root: &Node{All: []*Node{
			{Leaf: &Leaf{Field: "open_count", Op: OpGte, Values: []any{int64(1)}}},
			{Leaf: &Leaf{Field: "has_open", Op: OpEq, Values: []any{true}}},
		}},
		Sort: []SortKey{{Field: "open_count", Desc: true}},
	}
	for name, c := range map[string]struct {
		actor Actor
		want  string
	}{
		"member": {memberActor(t), "NOT TRUE"},
		"admin":  {adminActor(t), "NOT FALSE"},
	} {
		w, err := Compile(spec, reg, c.actor)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		all := w.SQL + " ORDER BY " + w.OrderBy
		if strings.Contains(all, "{member}") || strings.Contains(all, "{user}") {
			t.Fatalf("%s: token left in %q", name, all)
		}
		if got := strings.Count(all, c.want); got != 3 {
			t.Fatalf("%s: %q appears %d times in %q, want 3 (filter, bool, sort)", name, c.want, got, all)
		}
	}
}
