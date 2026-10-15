package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// External members (RFC-058, amended by RFC-095 §4): someone outside the
// organization may be invited to any role but owner, with an optional end of
// access (mandatory only by policy), and cannot be added directly.

const viewerRoleID = "00000000-0000-0000-0000-000000000004"
const memberRoleID = "00000000-0000-0000-0000-000000000003"

type extOwners map[string]shared.ID

func (o extOwners) OwnerOfDomain(_ context.Context, d string) (shared.ID, bool, error) {
	id, ok := o[d]
	return id, ok, nil
}

func newExternalTenantService(t *testing.T) (*tenantapp.TenantService, *mockTenantRepo, *tenant.Tenant, shared.ID) {
	t.Helper()
	svc, repo := newTestTenantService()
	host := seedTenant(repo, "Home", "home")
	partner := shared.NewID()
	svc.SetAddressClassifier(tenantapp.NewAddressClassifier(
		extOwners{"example.com": host.ID(), "example.com.au": partner},
		func(context.Context, shared.ID) (bool, error) { return true, nil }))
	return svc, repo, host, partner
}

func TestExternalInvitation_AnyRoleAllowed(t *testing.T) {
	svc, _, host, _ := newExternalTenantService(t)
	inv, err := svc.CreateInvitation(context.Background(), host.ID().String(), tenantapp.CreateInvitationInput{
		Email: "nam@example.com.au", Role: "member", RoleIDs: []string{memberRoleID},
	}, shared.NewID(), audit.AuditContext{})
	if err != nil {
		t.Fatalf("an outside person invited as member: %v", err)
	}
	if inv.Access().ExpiresAt != nil {
		t.Fatalf("an end of access was imposed: %v", inv.Access().ExpiresAt)
	}
}

func TestExternalInvitation_PersonalEndOptionalByDefault(t *testing.T) {
	svc, repo, host, _ := newExternalTenantService(t)
	inv, err := svc.CreateInvitation(context.Background(), host.ID().String(), tenantapp.CreateInvitationInput{
		Email: "j.doe@gmail.com", Role: "member", RoleIDs: []string{viewerRoleID},
	}, shared.NewID(), audit.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Access().ExpiresAt != nil {
		t.Fatalf("personal invitee got an end of access %v without the policy", inv.Access().ExpiresAt)
	}

	// The organization requires an end of access for unmanaged outsiders.
	settings := host.TypedSettings()
	settings.Security.ExternalAccessEndRequired = true
	if err := host.UpdateSettings(settings); err != nil {
		t.Fatal(err)
	}
	repo.tenants[host.ID().String()] = host
	inv, err = svc.CreateInvitation(context.Background(), host.ID().String(), tenantapp.CreateInvitationInput{
		Email: "k.doe@gmail.com", Role: "member", RoleIDs: []string{viewerRoleID},
	}, shared.NewID(), audit.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	at := inv.Access().ExpiresAt
	if at == nil || time.Until(*at) < 89*24*time.Hour || time.Until(*at) > 91*24*time.Hour {
		t.Fatalf("personal invitee access expiry = %v, want about 90 days", at)
	}
}

func TestExternalInvitation_ExpiryAboveMaxRefused(t *testing.T) {
	svc, _, host, _ := newExternalTenantService(t)
	tooLate := time.Now().Add(400 * 24 * time.Hour)
	_, err := svc.CreateInvitation(context.Background(), host.ID().String(), tenantapp.CreateInvitationInput{
		Email: "x@mssp.vn", Role: "member", RoleIDs: []string{viewerRoleID}, AccessExpiresAt: &tooLate,
	}, shared.NewID(), audit.AuditContext{})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want a validation error for 400 days, got %v", err)
	}
}

// The organization's own people are unaffected: any role, no expiry.
func TestInternalInvitation_Unchanged(t *testing.T) {
	svc, _, host, _ := newExternalTenantService(t)
	inv, err := svc.CreateInvitation(context.Background(), host.ID().String(), tenantapp.CreateInvitationInput{
		Email: "an@example.com", Role: "member", RoleIDs: []string{memberRoleID},
	}, shared.NewID(), audit.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Access().ExpiresAt != nil {
		t.Fatal("an internal invitee has no access expiry")
	}
}

func TestExternalInvitation_AcceptedWithInvitedRole(t *testing.T) {
	svc, repo, host, partner := newExternalTenantService(t)
	inviter := shared.NewID()
	seedMembershipInRepo(repo, inviter, host.ID(), tenant.RoleOwner)
	inv, err := svc.CreateInvitation(context.Background(), host.ID().String(), tenantapp.CreateInvitationInput{
		Email: "nam@example.com.au", Role: "member", RoleIDs: []string{memberRoleID},
	}, inviter, audit.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := svc.AcceptInvitation(context.Background(), inv.Token(), shared.NewID(), "nam@example.com.au", audit.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if !m.IsExternal() || m.HomeTenantID() == nil || *m.HomeTenantID() != partner || m.Role() != tenant.RoleMember {
		t.Fatalf("external=%v home=%v role=%s", m.IsExternal(), m.HomeTenantID(), m.Role())
	}
	if repo.acceptInvTxCalls != 1 {
		t.Fatal("membership not stored")
	}
}

// Someone outside the organization cannot be added without accepting an
// invitation (their consent).
func TestAddMember_ExternalRefused(t *testing.T) {
	svc, _, host, _ := newExternalTenantService(t)
	userRepo := newMockUserRepo()
	svc.SetUserService(newTestUserService(userRepo))
	u := createUserForTest(t, userRepo, "nam@example.com.au", "Nam")
	_, err := svc.AddMember(context.Background(), host.ID().String(),
		tenantapp.AddMemberInput{UserID: u.ID(), Role: "member"}, shared.NewID(), audit.AuditContext{TenantID: host.ID().String()})
	if !errors.Is(err, tenantapp.ErrExternalNeedsInvitation) {
		t.Fatalf("want ErrExternalNeedsInvitation, got %v", err)
	}
}

// An organization that has verified no domain treats every work address as
// its own for invitations. It still may not add an existing account without
// that person's consent: knowing someone's account id must not be enough to
// pull them into an organization.
func TestAddMember_NoVerifiedDomain_Refused(t *testing.T) {
	svc, repo := newTestTenantService()
	host := seedTenant(repo, "Free", "free")
	svc.SetAddressClassifier(tenantapp.NewAddressClassifier(extOwners{},
		func(context.Context, shared.ID) (bool, error) { return false, nil }))
	userRepo := newMockUserRepo()
	svc.SetUserService(newTestUserService(userRepo))
	u := createUserForTest(t, userRepo, "bob@b-corp.test", "Bob")
	_, err := svc.AddMember(context.Background(), host.ID().String(),
		tenantapp.AddMemberInput{UserID: u.ID(), Role: "viewer"}, shared.NewID(), audit.AuditContext{TenantID: host.ID().String()})
	if !errors.Is(err, tenantapp.ErrDirectAddNeedsVerifiedDomain) {
		t.Fatalf("want ErrDirectAddNeedsVerifiedDomain, got %v", err)
	}
	if repo.createMembershipCalls != 0 {
		t.Fatal("no membership may be created")
	}
}

// A personal address is never added directly, even by an organization that
// verified its own domain.
func TestAddMember_PersonalAddressRefused(t *testing.T) {
	svc, _, host, _ := newExternalTenantService(t)
	userRepo := newMockUserRepo()
	svc.SetUserService(newTestUserService(userRepo))
	u := createUserForTest(t, userRepo, "j.doe@gmail.com", "J")
	_, err := svc.AddMember(context.Background(), host.ID().String(),
		tenantapp.AddMemberInput{UserID: u.ID(), Role: "viewer"}, shared.NewID(), audit.AuditContext{TenantID: host.ID().String()})
	if err == nil {
		t.Fatal("a personal address must not be added directly")
	}
}

// The organization's own people, on its verified domain, are still added
// directly.
func TestAddMember_VerifiedDomainAllowed(t *testing.T) {
	svc, repo, host, _ := newExternalTenantService(t)
	userRepo := newMockUserRepo()
	svc.SetUserService(newTestUserService(userRepo))
	u := createUserForTest(t, userRepo, "an@example.com", "An")
	if _, err := svc.AddMember(context.Background(), host.ID().String(),
		tenantapp.AddMemberInput{UserID: u.ID(), Role: "viewer"}, shared.NewID(), audit.AuditContext{TenantID: host.ID().String()}); err != nil {
		t.Fatalf("AddMember on the verified domain: %v", err)
	}
	if repo.createMembershipCalls != 1 {
		t.Fatalf("membership must be created once, got %d", repo.createMembershipCalls)
	}
}
