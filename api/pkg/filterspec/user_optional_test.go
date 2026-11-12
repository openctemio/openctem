package filterspec

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A user-relative template is refused without a user, unless the field
// says it still means something then: the zero id is bound and matches no
// member (fail closed for the user-relative part only).
func TestUserOptionalTemplate(t *testing.T) {
	reg := MustRegistry(Registry{Name: "things", TenantSQL: "t.tenant_id", IDSQL: "t.id", Unscoped: "test"},
		Field{Name: "mine", Type: TypeString, Ops: []Op{OpIn}, SQL: "t.tag",
			Templates: map[Op]string{OpIn: "(t.tag = ANY({arg}) AND t.owner = {user})"}},
		Field{Name: "visible_tag", Type: TypeString, Ops: []Op{OpIn}, SQL: "t.tag", UserOptional: true,
			Templates: map[Op]string{OpIn: "(t.tag = ANY({arg}) OR t.viewer = {user})"}},
	)
	tenant := shared.NewID()
	for _, actor := range []Actor{SystemActor(tenant, "test"), mustUserActor(t, tenant, shared.ID{})} {
		spec := &Spec{Root: &Node{Leaf: &Leaf{Field: "mine", Op: OpIn, Values: []any{"a"}}}}
		if _, err := Compile(spec, reg, actor); err == nil {
			t.Fatal("a user-relative field compiled without a user")
		}
		spec = &Spec{Root: &Node{Leaf: &Leaf{Field: "visible_tag", Op: OpIn, Values: []any{"a"}}}}
		w, err := Compile(spec, reg, actor)
		if err != nil {
			t.Fatalf("user-optional field refused: %v", err)
		}
		found := false
		for _, a := range w.Args {
			if a == (shared.ID{}).String() {
				found = true
			}
		}
		if !found || !strings.Contains(w.SQL, "::uuid") {
			t.Fatalf("the zero user is not bound: %s %v", w.SQL, w.Args)
		}
	}
}

func mustUserActor(t *testing.T, tenant, user shared.ID) Actor {
	t.Helper()
	a, err := UserActor(UserActorInput{TenantID: tenant, UserID: user})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
