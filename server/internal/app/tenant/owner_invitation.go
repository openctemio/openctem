package tenant

// Ownership invitations: an organization the platform administrator creates
// for a person who already has an account waits with no owner until that
// account accepts. Design: docs/architecture/organization-ownership-invitations.md.
//
// Threat model: nobody becomes the owner of an organization without their
// consent (an attacker may have registered a guessable address, and the
// administrator must never place an account of its choosing into an
// organization that holds data). So:
//   - the invitation is bound to the account id, not the email string, and
//     only that account, signed in, with a recent re-authentication and a
//     verified email address, can accept it; another account's invitation
//     answers "not found";
//   - it is single use (pending -> accepted / declined / canceled), expires
//     after seven days, and resends are rate limited;
//   - while it waits the organization has no member, so no tenant route
//     admits anyone; only the console's admin paths reach it;
//   - an invitation can be (re)issued only for an organization created
//     waiting for its owner, never accepted, with no member at all;
//   - acceptance takes the first-owner lock and refuses when the
//     organization has an owner by then;
//   - every step is in the organization's audit log, and the invitee is
//     emailed on each send and on a cancellation.

import (
	"context"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/server/pkg/domain/user"
)

// OwnerInvitationNotifier emails the invitee (the email service satisfies
// it). Best effort.
type OwnerInvitationNotifier interface {
	// SendOwnershipInvitation tells the invitee they are invited to own
	// organizationName and where to answer in the app.
	SendOwnershipInvitation(ctx context.Context, email, name, organizationName string, expiresAt time.Time)
	// NotifyOwnershipTransfer sends a plain security notice.
	NotifyOwnershipTransfer(ctx context.Context, email, name, subject, message string)
}

// SetOwnerInvitationRepository wires the invitation store. Without it the
// invitation paths refuse (fail closed).
func (s *TenantService) SetOwnerInvitationRepository(r tenantdom.OwnerInvitationRepository) {
	s.ownerInvitations = r
}

// SetOwnerInvitationNotifier wires the invitee emails.
func (s *TenantService) SetOwnerInvitationNotifier(n OwnerInvitationNotifier) {
	s.ownerInvitationNotices = n
}

// ErrOwnerInvitationsUnavailable: the store is not wired.
var ErrOwnerInvitationsUnavailable = fmt.Errorf("%w: ownership invitations are not configured", shared.ErrNotImplemented)

func (s *TenantService) ownerInvitationStore() (tenantdom.OwnerInvitationRepository, error) {
	if s.ownerInvitations == nil {
		return nil, ErrOwnerInvitationsUnavailable
	}
	return s.ownerInvitations, nil
}

func ownerInvitationNow() time.Time { return time.Now().UTC() }

// CreateTenantAwaitingOwner creates an organization with no member and an
// ownership invitation to invitee (an existing account), atomically. The
// organization starts with the same limits as CreateTenant gives it.
// invitedBy is the platform administrator (may be zero).
func (s *TenantService) CreateTenantAwaitingOwner(ctx context.Context, input CreateTenantInput, invitee *userdom.User, invitedBy shared.ID, actx auditapp.AuditContext) (*tenantdom.Tenant, *tenantdom.OwnerInvitation, error) {
	store, err := s.ownerInvitationStore()
	if err != nil {
		return nil, nil, err
	}
	if invitee == nil {
		return nil, nil, tenantdom.ErrOwnerInviteeNotEligible
	}
	var inv *tenantdom.OwnerInvitation
	t, err := s.createTenant(ctx, input, invitee.ID(), actx, func(t *tenantdom.Tenant) error {
		var err error
		inv, err = tenantdom.NewOwnerInvitation(t.ID(), invitee.ID(), invitee.Email(), invitedBy, ownerInvitationNow())
		if err != nil {
			return err
		}
		return store.CreateWithOwnerInvitation(ctx, t, inv)
	})
	if err != nil {
		return nil, nil, err
	}
	s.auditOwnerInvitation(ctx, actx, inv, audit.ActionMemberOwnerInvitationSent,
		fmt.Sprintf("Ownership of the organization offered to %s by a platform administrator", inv.InviteeEmail))
	s.sendOwnerInvitation(ctx, inv, invitee.Name(), t.Name())
	return t, inv, nil
}

// InviteOwner replaces the pending invitation of an organization that is
// waiting for its first owner with one to invitee (the console's "change
// invitee"). ErrOwnerInvitationNotAllowed for any other organization.
func (s *TenantService) InviteOwner(ctx context.Context, tenantID shared.ID, invitee *userdom.User, invitedBy shared.ID, actx auditapp.AuditContext) (*tenantdom.OwnerInvitation, error) {
	store, err := s.ownerInvitationStore()
	if err != nil {
		return nil, err
	}
	if invitee == nil {
		return nil, tenantdom.ErrOwnerInviteeNotEligible
	}
	t, err := s.repo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if !t.TypedSettings().Security.EmailDomainAllowed(invitee.Email()) {
		return nil, ErrEmailDomainNotAllowed
	}
	inv, err := tenantdom.NewOwnerInvitation(tenantID, invitee.ID(), invitee.Email(), invitedBy, ownerInvitationNow())
	if err != nil {
		return nil, err
	}
	canceled, err := store.ReplaceOwnerInvitation(ctx, inv)
	if err != nil {
		return nil, err
	}
	actx.TenantID = tenantID.String()
	if canceled != nil {
		s.auditOwnerInvitation(ctx, actx, canceled, audit.ActionMemberOwnerInvitationCanceled,
			fmt.Sprintf("Ownership invitation to %s canceled: the platform administrator invited someone else", canceled.InviteeEmail))
		s.noticeOwnerInvitationCanceled(ctx, canceled, t.Name())
	}
	s.auditOwnerInvitation(ctx, actx, inv, audit.ActionMemberOwnerInvitationSent,
		fmt.Sprintf("Ownership of the organization offered to %s by a platform administrator", inv.InviteeEmail))
	s.sendOwnerInvitation(ctx, inv, invitee.Name(), t.Name())
	return inv, nil
}

// LatestOwnerInvitation returns the organization's newest invitation
// (shared.ErrNotFound when it has none). Console read.
func (s *TenantService) LatestOwnerInvitation(ctx context.Context, tenantID shared.ID) (*tenantdom.OwnerInvitation, error) {
	store, err := s.ownerInvitationStore()
	if err != nil {
		return nil, err
	}
	return store.LatestOwnerInvitation(ctx, tenantID)
}

// ResendOwnerInvitation sends the pending invitation again and renews its
// expiry (at most OwnerInvitationMaxSends sends, OwnerInvitationResendInterval
// apart).
func (s *TenantService) ResendOwnerInvitation(ctx context.Context, tenantID shared.ID, actx auditapp.AuditContext) (*tenantdom.OwnerInvitation, error) {
	store, err := s.ownerInvitationStore()
	if err != nil {
		return nil, err
	}
	t, err := s.repo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	inv, err := store.ResendOwnerInvitation(ctx, tenantID, ownerInvitationNow())
	if err != nil {
		return nil, err
	}
	actx.TenantID = tenantID.String()
	s.auditOwnerInvitation(ctx, actx, inv, audit.ActionMemberOwnerInvitationResent,
		fmt.Sprintf("Ownership invitation to %s sent again by a platform administrator", inv.InviteeEmail))
	s.sendOwnerInvitation(ctx, inv, "", t.Name())
	return inv, nil
}

// CancelOwnerInvitation withdraws the pending invitation. The organization
// stays, with no owner; the administrator can invite again or create a
// first owner.
func (s *TenantService) CancelOwnerInvitation(ctx context.Context, tenantID shared.ID, actx auditapp.AuditContext) (*tenantdom.OwnerInvitation, error) {
	store, err := s.ownerInvitationStore()
	if err != nil {
		return nil, err
	}
	t, err := s.repo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	inv, err := store.CancelOwnerInvitation(ctx, tenantID, ownerInvitationNow())
	if err != nil {
		return nil, err
	}
	actx.TenantID = tenantID.String()
	s.auditOwnerInvitation(ctx, actx, inv, audit.ActionMemberOwnerInvitationCanceled,
		fmt.Sprintf("Ownership invitation to %s canceled by a platform administrator", inv.InviteeEmail))
	s.noticeOwnerInvitationCanceled(ctx, inv, t.Name())
	return inv, nil
}

// ListMyOwnerInvitations lists the invitations the account can accept now.
func (s *TenantService) ListMyOwnerInvitations(ctx context.Context, userID shared.ID) ([]tenantdom.OwnerInvitationOffer, error) {
	store, err := s.ownerInvitationStore()
	if err != nil {
		return nil, err
	}
	return store.ListOpenOwnerInvitations(ctx, userID, ownerInvitationNow())
}

// AcceptOwnerInvitation makes u the owner of the invitation's organization.
// u must be the invitee (anyone else gets ErrOwnerInvitationNotFound), have a
// verified email address and have re-authenticated recently (the route asks
// for it too).
func (s *TenantService) AcceptOwnerInvitation(ctx context.Context, invitationID shared.ID, u *userdom.User, actx auditapp.AuditContext) (*tenantdom.OwnerInvitation, error) {
	store, err := s.ownerInvitationStore()
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, tenantdom.ErrOwnerInvitationNotFound
	}
	if err := s.requireStepUp(ctx, u.ID().String()); err != nil {
		return nil, err
	}
	if !u.EmailVerified() {
		return nil, tenantdom.ErrOwnerInviteeEmailUnverified
	}
	inv, _, err := store.AcceptOwnerInvitation(ctx, invitationID, u.ID(), func(tenantID shared.ID) (*tenantdom.Membership, error) {
		return tenantdom.NewOwnerMembership(u.ID(), tenantID)
	}, ownerInvitationNow())
	if err != nil {
		return nil, err
	}
	actx.TenantID = inv.TenantID.String()
	actx.ActorID = u.ID().String()
	actx.ActorEmail = u.Email()
	s.auditOwnerInvitation(ctx, actx, inv, audit.ActionMemberOwnerInvitationAccepted,
		fmt.Sprintf("%s accepted the ownership invitation and owns the organization", inv.InviteeEmail))
	return inv, nil
}

// DeclineOwnerInvitation records u's refusal. The organization stays with no
// owner for the administrator to decide.
func (s *TenantService) DeclineOwnerInvitation(ctx context.Context, invitationID shared.ID, u *userdom.User, actx auditapp.AuditContext) error {
	store, err := s.ownerInvitationStore()
	if err != nil {
		return err
	}
	if u == nil {
		return tenantdom.ErrOwnerInvitationNotFound
	}
	inv, err := store.DeclineOwnerInvitation(ctx, invitationID, u.ID(), ownerInvitationNow())
	if err != nil {
		return err
	}
	actx.TenantID = inv.TenantID.String()
	actx.ActorID = u.ID().String()
	actx.ActorEmail = u.Email()
	s.auditOwnerInvitation(ctx, actx, inv, audit.ActionMemberOwnerInvitationDeclined,
		fmt.Sprintf("%s declined the ownership invitation", inv.InviteeEmail))
	return nil
}

func (s *TenantService) auditOwnerInvitation(ctx context.Context, actx auditapp.AuditContext, inv *tenantdom.OwnerInvitation, action audit.Action, msg string) {
	if actx.TenantID == "" {
		actx.TenantID = inv.TenantID.String()
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(action, audit.ResourceTypeTenant, inv.TenantID.String()).
		WithResourceName(inv.InviteeEmail).
		WithMessage(msg).
		WithMetadata("invitation_id", inv.ID.String()).
		WithMetadata("invitee_user_id", inv.InviteeUserID.String()).
		WithMetadata("expires_at", inv.ExpiresAt.Format(time.RFC3339)).
		WithMetadata("send_count", inv.SendCount))
}

func (s *TenantService) sendOwnerInvitation(ctx context.Context, inv *tenantdom.OwnerInvitation, name, orgName string) {
	if s.ownerInvitationNotices == nil {
		return
	}
	s.ownerInvitationNotices.SendOwnershipInvitation(ctx, inv.InviteeEmail, name, orgName, inv.ExpiresAt)
}

func (s *TenantService) noticeOwnerInvitationCanceled(ctx context.Context, inv *tenantdom.OwnerInvitation, orgName string) {
	if s.ownerInvitationNotices == nil {
		return
	}
	s.ownerInvitationNotices.NotifyOwnershipTransfer(ctx, inv.InviteeEmail, "",
		"Ownership invitation withdrawn",
		fmt.Sprintf("The platform administrator withdrew the invitation to own the organization %q. Nothing changed for your account.", orgName))
}
