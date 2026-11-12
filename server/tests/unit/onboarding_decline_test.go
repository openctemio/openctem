package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/onboarding"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
)

type declineInvitations struct{ offers []tenantdom.InvitationOffer }

func (d declineInvitations) ListInvitationOffersForEmail(context.Context, string) ([]tenantdom.InvitationOffer, error) {
	return d.offers, nil
}

type declineMembers struct{}

func (declineMembers) GetMembership(context.Context, shared.ID, shared.ID) (*tenantdom.Membership, error) {
	return nil, shared.ErrNotFound
}
func (declineMembers) GetByID(context.Context, shared.ID) (*tenantdom.Tenant, error) {
	return nil, shared.ErrNotFound
}

type declineTenants struct {
	calls []string
}

func (d *declineTenants) AcceptInvitationByID(context.Context, shared.ID, shared.ID, shared.ID, string, bool, auditapp.AuditContext) (*tenantdom.Membership, error) {
	return nil, errors.New("not used")
}
func (d *declineTenants) DeclineInvitationByID(_ context.Context, tenantID, invitationID, _ shared.ID, email string, verified bool, _ auditapp.AuditContext) error {
	if !verified {
		return errors.New("unverified reached the tenant service")
	}
	d.calls = append(d.calls, tenantID.String()+"/"+invitationID.String()+"/"+email)
	return nil
}
func (d *declineTenants) AddMember(context.Context, string, onboarding.AddMemberInput, shared.ID, auditapp.AuditContext) (*tenantdom.Membership, error) {
	return nil, errors.New("not used")
}
func (d *declineTenants) AddMemberApprovingJoinRequest(context.Context, string, onboarding.AddMemberInput, shared.ID, shared.ID, auditapp.AuditContext) (*tenantdom.Membership, error) {
	return nil, errors.New("not used")
}
func (d *declineTenants) NotifyAdmins(context.Context, shared.ID, string, string, string) {}

// Declining an invitation from the account space: only a reference minted
// for this account, only an invitation reference, only a verified address
// (docs/architecture/tenantless-account-space.md).
func TestOnboardingDecline(t *testing.T) {
	ctx := context.Background()
	offer := tenantdom.InvitationOffer{InvitationID: shared.NewID(), TenantID: shared.NewID(), TenantName: "Acme", Role: "member", ExpiresAt: time.Now().Add(time.Hour)}
	tenants := &declineTenants{}
	svc := onboarding.NewService(declineInvitations{offers: []tenantdom.InvitationOffer{offer}}, declineMembers{}, tenants,
		nil, nil, nil, nil, []byte("onboarding-decline-test-key-0123456789"), nil)

	alice, _ := userdom.NewLocalUser("alice@it.test", "Alice", "x")
	alice.VerifyEmail()
	mallory, _ := userdom.NewLocalUser("mallory@it.test", "Mallory", "x")
	mallory.VerifyEmail()

	opts, err := svc.Options(ctx, alice)
	if err != nil || len(opts.Invitations) != 1 {
		t.Fatalf("options: %v %+v", err, opts)
	}
	ref := opts.Invitations[0].Ref

	// Another account cannot use Alice's reference.
	if err := svc.Decline(ctx, mallory, ref, auditapp.AuditContext{}); !errors.Is(err, onboarding.ErrInvalidRef) {
		t.Fatalf("foreign reference: %v", err)
	}
	// A tampered reference is refused.
	if err := svc.Decline(ctx, alice, ref+"x", auditapp.AuditContext{}); !errors.Is(err, onboarding.ErrInvalidRef) {
		t.Fatalf("tampered reference: %v", err)
	}
	// An unverified address is shown no invitation, so it has no reference
	// to decline with (Decline checks the address again for a reference
	// minted before the address changed).
	unverified, _ := userdom.NewLocalUser("alice2@it.test", "Alice", "x")
	if o, _ := svc.Options(ctx, unverified); len(o.Invitations) != 0 {
		t.Fatal("unverified address was shown invitations")
	}
	if len(tenants.calls) != 0 {
		t.Fatalf("a refused decline reached the tenant service: %v", tenants.calls)
	}
	// Alice declines her own invitation.
	if err := svc.Decline(ctx, alice, ref, auditapp.AuditContext{}); err != nil {
		t.Fatalf("decline: %v", err)
	}
	want := offer.TenantID.String() + "/" + offer.InvitationID.String() + "/alice@it.test"
	if len(tenants.calls) != 1 || tenants.calls[0] != want {
		t.Fatalf("decline calls: %v", tenants.calls)
	}
}
