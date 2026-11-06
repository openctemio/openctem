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

// stepUpGate answers like the real gate: nil for anyone but the requester.
type stepUpGate struct {
	requester string
	fresh     bool
}

var errStepUp = errors.New("step-up required")

func (g stepUpGate) RequireRecentAuth(_ context.Context, actorID string) error {
	if actorID == "" || actorID != g.requester || g.fresh {
		return nil
	}
	return errStepUp
}

// An outside member (RFC-058, amended by RFC-095 §4.2) may hold any role but
// owner. A privileged role needs the actor's recent re-authentication; the
// grant carried out for someone else (an invitation being accepted) is not
// asked. Internal members are unaffected.
func TestCapExternalTarget(t *testing.T) {
	tid, uid := roledom.NewID(), roledom.NewID()
	ext, _ := tenantdom.NewMembership(shared.NewID(), shared.NewID(), tenantdom.RoleViewer, nil)
	until := time.Now().Add(time.Hour)
	if err := ext.Classify(tenantdom.Classification{Kind: tenantdom.MemberKindExternal, Domain: "gmail.com"},
		tenantdom.ExternalAccess{ExpiresAt: &until}, time.Now()); err != nil {
		t.Fatal(err)
	}
	internal, _ := tenantdom.NewMembership(shared.NewID(), shared.NewID(), tenantdom.RoleMember, nil)

	actor := "actor"
	extSvc := &RoleService{membershipReader: capMembers{ext}, stepUp: stepUpGate{requester: actor}}
	freshSvc := &RoleService{membershipReader: capMembers{ext}, stepUp: stepUpGate{requester: actor, fresh: true}}
	inSvc := &RoleService{membershipReader: capMembers{internal}, stepUp: stepUpGate{requester: actor}}
	ctx := context.Background()

	if err := freshSvc.capExternalTarget(ctx, actor, tid, uid, capRole(roledom.OwnerRoleID, true)); !errors.Is(err, ErrExternalRoleCeiling) {
		t.Errorf("external owner: want ErrExternalRoleCeiling, got %v", err)
	}
	privileged := []*roledom.Role{capRole(roledom.AdminRoleID, true), capRole(roledom.NewID(), true),
		roledom.Reconstruct(roledom.NewID(), nil, "inviter", "Inviter", "", false, 1, false,
			[]string{"team:members:invite"}, time.Now(), time.Now(), nil)}
	for _, r := range privileged {
		if err := extSvc.capExternalTarget(ctx, actor, tid, uid, r); !errors.Is(err, errStepUp) {
			t.Errorf("external + privileged %s without step-up: want step-up, got %v", r.Slug(), err)
		}
		if err := freshSvc.capExternalTarget(ctx, actor, tid, uid, r); err != nil {
			t.Errorf("external + privileged %s after step-up: %v", r.Slug(), err)
		}
		if err := extSvc.capExternalTarget(ctx, "inviter-not-requester", tid, uid, r); err != nil {
			t.Errorf("external + privileged %s carried out for someone else: %v", r.Slug(), err)
		}
		if err := inSvc.capExternalTarget(ctx, actor, tid, uid, r); err != nil {
			t.Errorf("internal + %s: want nil, got %v", r.Slug(), err)
		}
	}
	for _, r := range []*roledom.Role{capRole(roledom.ViewerRoleID, false), capRole(roledom.MemberRoleID, false), capRole(roledom.NewID(), false)} {
		if err := extSvc.capExternalTarget(ctx, actor, tid, uid, r); err != nil {
			t.Errorf("external + %s: want nil, got %v", r.ID(), err)
		}
	}
	if !errors.Is(ErrExternalRoleCeiling, shared.ErrForbidden) {
		t.Error("the ceiling must answer 403")
	}
}

// A trust that caps the home organization's people at viewer refuses member.
func TestCapExternalTarget_TrustViewerCeiling(t *testing.T) {
	tid, uid := roledom.NewID(), roledom.NewID()
	home := shared.NewID()
	ext, _ := tenantdom.NewMembership(shared.NewID(), shared.NewID(), tenantdom.RoleViewer, nil)
	if err := ext.Classify(tenantdom.Classification{Kind: tenantdom.MemberKindExternal, HomeTenantID: &home, Domain: "home.example"},
		tenantdom.ExternalAccess{}, time.Now()); err != nil {
		t.Fatal(err)
	}
	svc := &RoleService{membershipReader: capMembers{ext}}
	svc.SetExternalRoleCeiling(func(context.Context, shared.ID, shared.ID) (string, error) { return "viewer", nil })
	if err := svc.capExternalTarget(context.Background(), "", tid, uid, capRole(roledom.MemberRoleID, false)); !errors.Is(err, ErrExternalViewerCeiling) {
		t.Fatalf("member under a viewer ceiling: want ErrExternalViewerCeiling, got %v", err)
	}
	if err := svc.capExternalTarget(context.Background(), "", tid, uid, capRole(roledom.ViewerRoleID, false)); err != nil {
		t.Fatalf("viewer under a viewer ceiling: %v", err)
	}
	svc.SetExternalRoleCeiling(func(context.Context, shared.ID, shared.ID) (string, error) { return "member", nil })
	if err := svc.capExternalTarget(context.Background(), "", tid, uid, capRole(roledom.MemberRoleID, false)); err != nil {
		t.Fatalf("member under a member ceiling: %v", err)
	}
	// Any trust ceiling refuses admin and full data access.
	for _, r := range []*roledom.Role{capRole(roledom.AdminRoleID, true), capRole(roledom.NewID(), true)} {
		if err := svc.capExternalTarget(context.Background(), "", tid, uid, r); !errors.Is(err, ErrExternalRoleCeiling) {
			t.Fatalf("privileged under a member ceiling: want ErrExternalRoleCeiling, got %v", err)
		}
	}
	// No active trust: no ceiling.
	svc.SetExternalRoleCeiling(func(context.Context, shared.ID, shared.ID) (string, error) { return "", nil })
	if err := svc.capExternalTarget(context.Background(), "", tid, uid, capRole(roledom.AdminRoleID, true)); err != nil {
		t.Fatalf("admin without a trust: %v", err)
	}
}
