package accesscontrol

import (
	"context"
	"errors"
	"testing"
	"time"

	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type capMembers struct{ m *tenantdom.Membership }

func (c capMembers) GetMembership(context.Context, shared.ID, shared.ID) (*tenantdom.Membership, error) {
	if c.m == nil {
		return nil, shared.ErrNotFound
	}
	return c.m, nil
}

func capRole(id roledom.ID, fullData bool) *roledom.Role {
	now := time.Now()
	return roledom.Reconstruct(id, nil, "r", "R", "", true, 1, fullData, nil, now, now, nil)
}

// An external member (RFC-058) may be a viewer or a member: never owner,
// admin, or a role with full data access. Internal members are unaffected.
func TestCapExternalTarget(t *testing.T) {
	tid, uid := roledom.NewID(), roledom.NewID()
	ext, _ := tenantdom.NewMembership(shared.NewID(), shared.NewID(), tenantdom.RoleViewer, nil)
	until := time.Now().Add(time.Hour)
	if err := ext.Classify(tenantdom.Classification{Kind: tenantdom.MemberKindExternal, Domain: "gmail.com"},
		tenantdom.ExternalAccess{ExpiresAt: &until}, time.Now()); err != nil {
		t.Fatal(err)
	}
	internal, _ := tenantdom.NewMembership(shared.NewID(), shared.NewID(), tenantdom.RoleMember, nil)

	extSvc := &RoleService{membershipReader: capMembers{ext}}
	inSvc := &RoleService{membershipReader: capMembers{internal}}
	ctx := context.Background()

	for _, r := range []*roledom.Role{
		capRole(roledom.OwnerRoleID, true), capRole(roledom.AdminRoleID, true), capRole(roledom.NewID(), true),
	} {
		if err := extSvc.capExternalTarget(ctx, tid, uid, r); !errors.Is(err, ErrExternalRoleCeiling) {
			t.Errorf("external + %s: want ErrExternalRoleCeiling, got %v", r.ID(), err)
		}
		if err := inSvc.capExternalTarget(ctx, tid, uid, r); err != nil {
			t.Errorf("internal + %s: want nil, got %v", r.ID(), err)
		}
	}
	for _, r := range []*roledom.Role{capRole(roledom.ViewerRoleID, false), capRole(roledom.MemberRoleID, false), capRole(roledom.NewID(), false)} {
		if err := extSvc.capExternalTarget(ctx, tid, uid, r); err != nil {
			t.Errorf("external + %s: want nil, got %v", r.ID(), err)
		}
	}
	if !errors.Is(ErrExternalRoleCeiling, shared.ErrForbidden) {
		t.Error("the ceiling must answer 403")
	}
}
