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

// External members (RFC-058): someone outside the organization is invited as
// a viewer, with an expiry when no organization manages the address, and
// cannot be added directly.

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
	host := seedTenant(repo, "PTI", "pti")
	ipas := shared.NewID()
	svc.SetAddressClassifier(tenantapp.NewAddressClassifier(
		extOwners{"pti.com.vn": host.ID(), "ipas.com.vn": ipas},
		func(context.Context, shared.ID) (bool, error) { return true, nil }))
	return svc, repo, host, ipas
}

func TestExternalInvitation_MoreThanViewerRefused(t *testing.T) {
	svc, _, host, _ := newExternalTenantService(t)
	_, err := svc.CreateInvitation(context.Background(), host.ID().String(), tenantapp.CreateInvitationInput{
		Email: "nam@ipas.com.vn", Role: "member", RoleIDs: []string{memberRoleID},
	}, shared.NewID(), audit.AuditContext{})
	if !errors.Is(err, tenantapp.ErrExternalViewerOnly) {
		t.Fatalf("want ErrExternalViewerOnly, got %v", err)
	}
}

func TestExternalInvitation_PersonalGetsDefaultExpiry(t *testing.T) {
	svc, _, host, _ := newExternalTenantService(t)
	inv, err := svc.CreateInvitation(context.Background(), host.ID().String(), tenantapp.CreateInvitationInput{
		Email: "j.doe@gmail.com", Role: "member", RoleIDs: []string{viewerRoleID},
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
		Email: "an@pti.com.vn", Role: "member", RoleIDs: []string{memberRoleID},
	}, shared.NewID(), audit.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Access().ExpiresAt != nil {
		t.Fatal("an internal invitee has no access expiry")
	}
}

func TestExternalInvitation_AcceptedAsExternalViewer(t *testing.T) {
	svc, repo, host, ipas := newExternalTenantService(t)
	inv, err := svc.CreateInvitation(context.Background(), host.ID().String(), tenantapp.CreateInvitationInput{
		Email: "nam@ipas.com.vn", Role: "member", RoleIDs: []string{viewerRoleID},
	}, shared.NewID(), audit.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := svc.AcceptInvitation(context.Background(), inv.Token(), shared.NewID(), "nam@ipas.com.vn", audit.AuditContext{})
	if err != nil {
		t.Fatal(err)
	}
	if !m.IsExternal() || m.HomeTenantID() == nil || *m.HomeTenantID() != ipas || m.Role() != tenant.RoleViewer {
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
	u := createUserForTest(t, userRepo, "nam@ipas.com.vn", "Nam")
	_, err := svc.AddMember(context.Background(), host.ID().String(),
		tenantapp.AddMemberInput{UserID: u.ID(), Role: "member"}, shared.NewID(), audit.AuditContext{TenantID: host.ID().String()})
	if !errors.Is(err, tenantapp.ErrExternalNeedsInvitation) {
		t.Fatalf("want ErrExternalNeedsInvitation, got %v", err)
	}
}
