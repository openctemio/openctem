package postgres

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The flat findings list must support the "assigned to / owned by me" predicate
// (RelatedToUserID) so a scoped user can pull up their work queue — the same
// relatedness the finding-groups endpoint uses. buildWhereClause is pure (no DB).
func TestBuildWhereClause_RelatedToUser(t *testing.T) {
	r := &FindingRepository{}

	tid := shared.NewID()
	uid := shared.NewID()
	f := vulnerability.NewFindingFilter()
	f.TenantID = &tid
	f.RelatedToUserID = &uid

	where, args := r.buildWhereClause(f)

	if strings.Contains(where, "owner_id") {
		t.Errorf("WHERE still reads assets.owner_id: %s", where)
	}
	for _, frag := range []string{
		"assigned_to = $",
		"FROM asset_owners oao",
		"oao.user_id = $",
		"oao.ownership_type IN ('primary', 'secondary')",
		"finding_group_assignments",
		"gm.user_id = $",
		"g.is_active = true",
	} {
		if !strings.Contains(where, frag) {
			t.Errorf("WHERE missing %q\nfull: %s", frag, where)
		}
	}

	// tenant_id ($1) + related user ($2) + related tenant ($3) = 3 args.
	if len(args) != 3 {
		t.Fatalf("expected 3 args, got %d: %#v", len(args), args)
	}
	if args[1] != uid.String() {
		t.Errorf("arg[1] = %v, want user id %s", args[1], uid.String())
	}
}

// RelatedToUserID requires TenantID; with the field unset the clause must not
// appear (no accidental always-on "assigned to me").
func TestBuildWhereClause_NoRelatedClauseWhenUnset(t *testing.T) {
	r := &FindingRepository{}
	tid := shared.NewID()
	f := vulnerability.NewFindingFilter()
	f.TenantID = &tid

	where, _ := r.buildWhereClause(f)
	if strings.Contains(where, "finding_group_assignments") {
		t.Errorf("unset RelatedToUserID leaked the my-work clause: %s", where)
	}
}
