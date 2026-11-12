package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// A person who belongs to two organizations is suspended or offboarded in one
// of them. Only that organization's access ends: the sessions its own IdP
// signed in end, every other session (password, social, the other
// organization's IdP) stays, so an administrator of one organization cannot
// sign a member of another out. research/72 D3.

type scopedRevokeFixture struct {
	svc      *tenantapp.TenantService
	repo     *mockTenantRepo
	sessRepo *mockSessionRepo
	tenantA  shared.ID
	tenantB  shared.ID
	userID   shared.ID
	member   *tenant.Membership
	password *session.Session // no issuing organization
	byA      *session.Session // signed in by A's IdP
	byB      *session.Session // signed in by B's IdP
}

func newScopedRevokeFixture(t *testing.T, alsoInB bool) *scopedRevokeFixture {
	t.Helper()
	svc, repo := newTestTenantService()
	sessionSvc, sessRepo, _ := newTestSessionService()
	svc.SetSessionService(sessionSvc)
	f := &scopedRevokeFixture{svc: svc, repo: repo, sessRepo: sessRepo,
		tenantA: shared.NewID(), tenantB: shared.NewID(), userID: shared.NewID()}

	m, err := svc.AddMember(context.Background(), f.tenantA.String(),
		tenantapp.AddMemberInput{UserID: f.userID, Role: "member"}, shared.ID{}, audit.AuditContext{TenantID: f.tenantA.String()})
	if err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	f.member = m

	tA, _ := tenant.NewTenant("A", "org-a", shared.NewID().String())
	tB, _ := tenant.NewTenant("B", "org-b", shared.NewID().String())
	tA = tenant.Reconstitute(f.tenantA, tA.Name(), tA.Slug(), tA.Description(), tA.LogoURL(), tA.Settings(), tA.CreatedBy(), tA.CreatedAt(), tA.UpdatedAt())
	tB = tenant.Reconstitute(f.tenantB, tB.Name(), tB.Slug(), tB.Description(), tB.LogoURL(), tB.Settings(), tB.CreatedBy(), tB.CreatedAt(), tB.UpdatedAt())
	repo.tenantsWithRole = []*tenant.TenantWithRole{{Tenant: tA, Role: tenant.RoleMember}}
	if alsoInB {
		repo.tenantsWithRole = append(repo.tenantsWithRole, &tenant.TenantWithRole{Tenant: tB, Role: tenant.RoleMember})
	}

	mk := func(idp *shared.ID) *session.Session {
		s, _ := session.New(f.userID, "tok-"+shared.NewID().String(), "127.0.0.1", "UA", time.Hour)
		if idp != nil {
			s.SetAuthMethod(session.AuthMethodSSO)
			s.SetIDPTenant(*idp)
		}
		sessRepo.sessions[s.ID().String()] = s
		return s
	}
	f.password = mk(nil)
	f.byA = mk(&f.tenantA)
	f.byB = mk(&f.tenantB)
	return f
}

func (f *scopedRevokeFixture) assertScoped(t *testing.T) {
	t.Helper()
	if f.byA.IsActive() {
		t.Error("the session A's own IdP signed in must end")
	}
	if !f.password.IsActive() || !f.byB.IsActive() {
		t.Error("sessions that serve the person's other organization must stay")
	}
	if f.sessRepo.revokeAllCalls != 0 {
		t.Errorf("no account-wide revocation expected, RevokeAllByUserID calls = %d", f.sessRepo.revokeAllCalls)
	}
}

func TestSuspendMember_OtherOrganization_KeepsItsSessions(t *testing.T) {
	f := newScopedRevokeFixture(t, true)
	if err := f.svc.SuspendMember(context.Background(), f.member.ID().String(),
		audit.AuditContext{TenantID: f.tenantA.String(), ActorEmail: "scim-provisioning"}); err != nil {
		t.Fatalf("SuspendMember: %v", err)
	}
	if !f.repo.memberships[f.member.ID().String()].IsSuspended() {
		t.Fatal("membership in A must be suspended")
	}
	f.assertScoped(t)
}

// The person has no other organization: nothing to protect elsewhere, every
// session ends (as before).
func TestSuspendMember_OnlyOrganization_EndsEverySession(t *testing.T) {
	f := newScopedRevokeFixture(t, false)
	if err := f.svc.SuspendMember(context.Background(), f.member.ID().String(),
		audit.AuditContext{TenantID: f.tenantA.String(), ActorEmail: "scim-provisioning"}); err != nil {
		t.Fatalf("SuspendMember: %v", err)
	}
	if f.sessRepo.revokeAllCalls != 1 {
		t.Errorf("RevokeAllByUserID calls = %d, want 1", f.sessRepo.revokeAllCalls)
	}
}

// When the organizations cannot be listed, the tenant's access is still cut
// (membership checks), and other organizations' sessions are not ended.
func TestSuspendMember_OrganizationLookupFails_StaysScoped(t *testing.T) {
	f := newScopedRevokeFixture(t, false)
	f.repo.listTenantsByUserErr = errors.New("db down")
	if err := f.svc.SuspendMember(context.Background(), f.member.ID().String(),
		audit.AuditContext{TenantID: f.tenantA.String(), ActorEmail: "scim-provisioning"}); err != nil {
		t.Fatalf("SuspendMember: %v", err)
	}
	f.assertScoped(t)
}
