package tenant

// Ownership transfer: the owner asks an existing member to take the
// organization; the member accepts with their own re-authentication within
// 72 hours. Design: docs/rfcs/RFC-095-role-templates-and-invitations.md.
//
// Threat model: ownership is the one power no role carries (delete the
// organization, promote administrators, change security settings), so the
// flow is owner-only with a recent re-authentication on both sides; the new
// owner must have two-factor authentication and must not be managed by
// another organization; the change is one transaction that leaves exactly one
// owner; both people are told by email and the audit log records every step.
// Every lookup is scoped to the caller's organization (the token tenant):
// another organization's member or request answers 404.

import (
	"context"
	"errors"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// OwnershipTransferNotifier emails the two people involved in a transfer
// (the email service satisfies it). Best effort.
type OwnershipTransferNotifier interface {
	NotifyOwnershipTransfer(ctx context.Context, email, name, subject, message string)
}

// SetOwnershipTransferRepository wires the transfer store. Without it the
// transfer endpoints refuse (fail closed).
func (s *TenantService) SetOwnershipTransferRepository(r tenantdom.OwnershipTransferRepository) {
	s.ownershipTransfers = r
}

// SetOwnershipTransferNotifier wires the transfer emails.
func (s *TenantService) SetOwnershipTransferNotifier(n OwnershipTransferNotifier) {
	s.ownershipNotifier = n
}

// errOwnershipTransferUnavailable: the store is not wired.
var errOwnershipTransferUnavailable = errors.New("ownership transfer is not configured")

// StartOwnershipTransferInput is the owner's request.
type StartOwnershipTransferInput struct {
	// MembershipID of the member who will own the organization.
	MembershipID string
	// PreviousOwnerRole is what the current owner becomes: admin (default),
	// member or viewer.
	PreviousOwnerRole string
	// ConfirmInternal: the owner confirms that an outside member becomes an
	// internal member on acceptance.
	ConfirmInternal bool
}

// OwnershipTransferView is a transfer as the API shows it.
type OwnershipTransferView struct {
	ID                string    `json:"id"`
	Status            string    `json:"status"`
	FromUserID        string    `json:"from_user_id"`
	FromName          string    `json:"from_name,omitempty"`
	ToUserID          string    `json:"to_user_id"`
	ToName            string    `json:"to_name,omitempty"`
	PreviousOwnerRole string    `json:"previous_owner_role"`
	MakeInternal      bool      `json:"make_internal"`
	CreatedAt         time.Time `json:"created_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	// Viewer is the caller's side: "owner" or "new_owner".
	Viewer string `json:"viewer"`
}

func (s *TenantService) ownershipStore() (tenantdom.OwnershipTransferRepository, error) {
	if s.ownershipTransfers == nil {
		return nil, errOwnershipTransferUnavailable
	}
	return s.ownershipTransfers, nil
}

// requireActiveOwner returns the caller's membership when they are the
// organization's active owner.
func (s *TenantService) requireActiveOwner(ctx context.Context, tenantID, actorID shared.ID) (*tenantdom.Membership, error) {
	m, err := s.repo.GetMembership(ctx, actorID, tenantID)
	if err != nil || m == nil || !m.IsOwner() || !m.IsActive() {
		return nil, tenantdom.ErrOwnershipTransferNotOwner
	}
	return m, nil
}

func parseActor(actx auditapp.AuditContext) (tenantID, actorID shared.ID, err error) {
	tenantID, err = shared.IDFromString(actx.TenantID)
	if err != nil || tenantID.IsZero() {
		return tenantID, actorID, shared.ErrNotFound
	}
	actorID, err = shared.IDFromString(actx.ActorID)
	if err != nil || actorID.IsZero() {
		return tenantID, actorID, fmt.Errorf("%w: invalid acting user id", shared.ErrValidation)
	}
	return tenantID, actorID, nil
}

// StartOwnershipTransfer asks a member to take ownership. The caller must be
// the active owner and have re-authenticated recently (the route also
// requires it).
func (s *TenantService) StartOwnershipTransfer(ctx context.Context, input StartOwnershipTransferInput, actx auditapp.AuditContext) (*OwnershipTransferView, error) {
	store, err := s.ownershipStore()
	if err != nil {
		return nil, err
	}
	tenantID, actorID, err := parseActor(actx)
	if err != nil {
		return nil, err
	}
	s.expireLapsedTransfers(ctx, store, tenantID)
	if _, err := s.requireActiveOwner(ctx, tenantID, actorID); err != nil {
		return nil, err
	}
	if err := s.requireStepUp(ctx, actx.ActorID); err != nil {
		return nil, err
	}
	membershipID, err := shared.IDFromString(input.MembershipID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid member id", shared.ErrValidation)
	}
	cand, err := store.OwnershipCandidate(ctx, tenantID, membershipID)
	if err != nil {
		return nil, err
	}
	if cand.UserID == actorID {
		return nil, tenantdom.ErrOwnershipTargetSelf
	}
	if err := tenantdom.CheckOwnershipCandidate(*cand, input.ConfirmInternal); err != nil {
		return nil, err
	}
	t, err := tenantdom.NewOwnershipTransfer(tenantID, actorID, cand.UserID,
		tenantdom.Role(input.PreviousOwnerRole), cand.External, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err := store.CreateOwnershipTransfer(ctx, t); err != nil {
		return nil, err
	}

	view := s.transferView(ctx, t, "owner")
	org := s.orgName(ctx, tenantID)
	s.auditTransfer(ctx, actx, audit.ActionMemberOwnershipTransferRequested, t, audit.SeverityHigh,
		fmt.Sprintf("Ownership transfer to %s requested", displayOr(view.ToName, "a member")))
	s.emailTransfer(ctx, t.ToUserID, "You have been asked to own "+org,
		fmt.Sprintf("%s asked you to become the owner of %s. Open the Members page in %s to accept or decline. Accepting asks you to sign in again. The request expires on %s.",
			displayOr(view.FromName, "The owner"), org, org, t.ExpiresAt.Format("January 2, 2006 at 3:04 PM MST")))
	s.emailTransfer(ctx, t.FromUserID, "You asked to transfer ownership of "+org,
		fmt.Sprintf("You asked %s to become the owner of %s. Nothing changes until they accept; you can cancel the request on the Members page until then. When they accept, you become %s.",
			displayOr(view.ToName, "a member"), org, roleLabel(t.PreviousOwnerRole)))
	s.notifyUser(ctx, tenantID, t.ToUserID, "You have been asked to own this organization",
		fmt.Sprintf("%s asked you to become the owner of %s. Accept or decline on the Members page.", displayOr(view.FromName, "The owner"), org))
	return view, nil
}

// PendingOwnershipTransfer returns the open request when the caller is the
// owner or the person asked; anyone else gets ErrOwnershipTransferNotFound.
func (s *TenantService) PendingOwnershipTransfer(ctx context.Context, actx auditapp.AuditContext) (*OwnershipTransferView, error) {
	store, err := s.ownershipStore()
	if err != nil {
		return nil, err
	}
	tenantID, actorID, err := parseActor(actx)
	if err != nil {
		return nil, err
	}
	s.expireLapsedTransfers(ctx, store, tenantID)
	t, err := store.PendingOwnershipTransfer(ctx, tenantID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	switch actorID {
	case t.ToUserID:
		return s.transferView(ctx, t, "new_owner"), nil
	case t.FromUserID:
		if _, err := s.requireActiveOwner(ctx, tenantID, actorID); err == nil {
			return s.transferView(ctx, t, "owner"), nil
		}
	}
	return nil, tenantdom.ErrOwnershipTransferNotFound
}

// CancelOwnershipTransfer withdraws the open request (the owner).
func (s *TenantService) CancelOwnershipTransfer(ctx context.Context, actx auditapp.AuditContext) error {
	return s.closeTransfer(ctx, actx, tenantdom.OwnershipTransferCanceled)
}

// DeclineOwnershipTransfer refuses the open request (the person asked).
func (s *TenantService) DeclineOwnershipTransfer(ctx context.Context, actx auditapp.AuditContext) error {
	return s.closeTransfer(ctx, actx, tenantdom.OwnershipTransferDeclined)
}

func (s *TenantService) closeTransfer(ctx context.Context, actx auditapp.AuditContext, status tenantdom.OwnershipTransferStatus) error {
	store, err := s.ownershipStore()
	if err != nil {
		return err
	}
	tenantID, actorID, err := parseActor(actx)
	if err != nil {
		return err
	}
	s.expireLapsedTransfers(ctx, store, tenantID)
	now := time.Now().UTC()
	open, err := store.PendingOwnershipTransfer(ctx, tenantID, now)
	if err != nil {
		return err
	}
	if status == tenantdom.OwnershipTransferCanceled {
		if _, err := s.requireActiveOwner(ctx, tenantID, actorID); err != nil {
			return err
		}
	} else if open.ToUserID != actorID {
		return tenantdom.ErrOwnershipTransferNotFound
	}
	t, err := store.CloseOwnershipTransfer(ctx, tenantID, open.ID, status, actorID, now)
	if err != nil {
		return err
	}
	view := s.transferView(ctx, t, "")
	org := s.orgName(ctx, tenantID)
	if status == tenantdom.OwnershipTransferCanceled {
		s.auditTransfer(ctx, actx, audit.ActionMemberOwnershipTransferCanceled, t, audit.SeverityMedium,
			"Ownership transfer canceled by the owner")
		s.emailTransfer(ctx, t.ToUserID, "The ownership transfer of "+org+" was canceled",
			fmt.Sprintf("%s canceled the request for you to become the owner of %s. Nothing changed.", displayOr(view.FromName, "The owner"), org))
		return nil
	}
	s.auditTransfer(ctx, actx, audit.ActionMemberOwnershipTransferDeclined, t, audit.SeverityMedium,
		"Ownership transfer declined")
	s.emailTransfer(ctx, t.FromUserID, "Your ownership transfer of "+org+" was declined",
		fmt.Sprintf("%s declined to become the owner of %s. You are still the owner.", displayOr(view.ToName, "The member"), org))
	return nil
}

// AcceptOwnershipTransfer makes the caller the owner. The route requires a
// recent re-authentication; the service checks it again.
func (s *TenantService) AcceptOwnershipTransfer(ctx context.Context, actx auditapp.AuditContext) (*OwnershipTransferView, error) {
	store, err := s.ownershipStore()
	if err != nil {
		return nil, err
	}
	tenantID, actorID, err := parseActor(actx)
	if err != nil {
		return nil, err
	}
	s.expireLapsedTransfers(ctx, store, tenantID)
	now := time.Now().UTC()
	open, err := store.PendingOwnershipTransfer(ctx, tenantID, now)
	if err != nil {
		return nil, err
	}
	if open.ToUserID != actorID {
		return nil, tenantdom.ErrOwnershipTransferNotFound
	}
	if err := s.requireStepUp(ctx, actx.ActorID); err != nil {
		return nil, err
	}
	res, err := store.AcceptOwnershipTransfer(ctx, tenantID, open.ID, actorID, now)
	if err != nil {
		return nil, err
	}
	t := res.Transfer
	tid := tenantID.String()
	for _, uid := range []shared.ID{t.FromUserID, t.ToUserID} {
		s.invalidateMembershipCache(ctx, tid, uid.String())
		s.invalidateUserPermissions(ctx, tid, uid.String())
		s.bumpPermissionVersion(ctx, tid, uid.String())
	}

	view := s.transferView(ctx, t, "new_owner")
	org := s.orgName(ctx, tenantID)
	event := auditapp.NewSuccessEvent(audit.ActionMemberOwnershipTransferred, audit.ResourceTypeMembership, res.ToMembershipID.String()).
		WithChanges(audit.NewChanges().
			Set("owner", t.FromUserID.String(), t.ToUserID.String()).
			Set("previous_owner_role", tenantdom.RoleOwner.String(), res.PreviousOwnerRole.String())).
		WithSeverity(audit.SeverityCritical).
		WithMessage(fmt.Sprintf("Ownership transferred from %s to %s", displayOr(view.FromName, "the previous owner"), displayOr(view.ToName, "a member"))).
		WithMetadata("transfer_id", t.ID.String()).
		WithMetadata("from_user_id", t.FromUserID.String()).
		WithMetadata("to_user_id", t.ToUserID.String()).
		WithMetadata("from_membership_id", res.FromMembershipID.String()).
		WithMetadata("previous_owner_role", res.PreviousOwnerRole.String()).
		WithMetadata("became_internal", res.BecameInternal)
	actx.TenantID = tid
	s.logAudit(ctx, actx, event)

	s.emailTransfer(ctx, t.ToUserID, "You are now the owner of "+org,
		fmt.Sprintf("You accepted ownership of %s. You can now delete the organization, make people administrators and change its security settings.", org))
	s.emailTransfer(ctx, t.FromUserID, "Ownership of "+org+" was transferred",
		fmt.Sprintf("%s accepted ownership of %s. You are now %s.", displayOr(view.ToName, "The member"), org, roleLabel(res.PreviousOwnerRole)))
	s.notifyAdmins(ctx, tenantID, "The organization has a new owner",
		fmt.Sprintf("%s is now the owner of %s; %s is now %s.", displayOr(view.ToName, "A member"), org,
			displayOr(view.FromName, "the previous owner"), roleLabel(res.PreviousOwnerRole)), notificationdom.SeverityHigh)
	view.Status = string(tenantdom.OwnershipTransferAccepted)
	return view, nil
}

// expireLapsedTransfers closes and audits the requests whose 72 hours are
// up, so a lapsed request leaves a trace when it is noticed. Best effort.
func (s *TenantService) expireLapsedTransfers(ctx context.Context, store tenantdom.OwnershipTransferRepository, tenantID shared.ID) {
	lapsed, err := store.ExpireLapsedOwnershipTransfers(ctx, tenantID, time.Now().UTC())
	if err != nil {
		s.logger.Warn("expire lapsed ownership transfers", "error", err)
		return
	}
	for _, t := range lapsed {
		// The system closed it, not the person whose request noticed it.
		sys := auditapp.AuditContext{TenantID: t.TenantID.String()}
		s.auditTransfer(ctx, sys, audit.ActionMemberOwnershipTransferExpired, t, audit.SeverityLow,
			"Ownership transfer expired without an answer")
	}
}

func (s *TenantService) transferView(ctx context.Context, t *tenantdom.OwnershipTransfer, viewer string) *OwnershipTransferView {
	return &OwnershipTransferView{
		ID:                t.ID.String(),
		Status:            string(t.Status),
		FromUserID:        t.FromUserID.String(),
		FromName:          s.GetUserDisplayName(ctx, t.FromUserID),
		ToUserID:          t.ToUserID.String(),
		ToName:            s.GetUserDisplayName(ctx, t.ToUserID),
		PreviousOwnerRole: t.PreviousOwnerRole.String(),
		MakeInternal:      t.MakeInternal,
		CreatedAt:         t.CreatedAt,
		ExpiresAt:         t.ExpiresAt,
		Viewer:            viewer,
	}
}

func (s *TenantService) auditTransfer(ctx context.Context, actx auditapp.AuditContext, action audit.Action, t *tenantdom.OwnershipTransfer, sev audit.Severity, msg string) {
	actx.TenantID = t.TenantID.String()
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(action, audit.ResourceTypeTenant, t.TenantID.String()).
		WithSeverity(sev).
		WithMessage(msg).
		WithMetadata("transfer_id", t.ID.String()).
		WithMetadata("from_user_id", t.FromUserID.String()).
		WithMetadata("to_user_id", t.ToUserID.String()).
		WithMetadata("previous_owner_role", t.PreviousOwnerRole.String()).
		WithMetadata("make_internal", t.MakeInternal).
		WithMetadata("expires_at", t.ExpiresAt.Format(time.RFC3339)))
}

func (s *TenantService) emailTransfer(ctx context.Context, userID shared.ID, subject, message string) {
	if s.ownershipNotifier == nil || s.userService == nil {
		return
	}
	users, err := s.userService.GetUsersByIDs(ctx, []string{userID.String()})
	if err != nil || len(users) == 0 || users[0].Email() == "" {
		s.logger.Warn("ownership transfer email skipped: user lookup failed", "user_id", userID.String(), "error", err)
		return
	}
	s.ownershipNotifier.NotifyOwnershipTransfer(ctx, users[0].Email(), users[0].Name(), subject, message)
}

// notifyUser leaves an in-app notification for one person. Best effort.
func (s *TenantService) notifyUser(ctx context.Context, tenantID, userID shared.ID, title, body string) {
	if s.lifecycleNotifier == nil {
		return
	}
	uid := userID
	if err := s.lifecycleNotifier.Notify(ctx, notificationdom.NotificationParams{
		TenantID:         tenantID,
		Audience:         notificationdom.AudienceUser,
		AudienceID:       &uid,
		NotificationType: notificationdom.TypeMemberLifecycle,
		Title:            title,
		Body:             body,
		Severity:         notificationdom.SeverityHigh,
		ResourceType:     "membership",
		URL:              "/settings/members",
	}); err != nil {
		s.logger.Warn("notify ownership transfer", "error", err)
	}
}

func (s *TenantService) orgName(ctx context.Context, tenantID shared.ID) string {
	if t, err := s.repo.GetByID(ctx, tenantID); err == nil && t != nil && t.Name() != "" {
		return t.Name()
	}
	return "the organization"
}

func displayOr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func roleLabel(r tenantdom.Role) string {
	switch r {
	case tenantdom.RoleAdmin:
		return "an administrator"
	case tenantdom.RoleMember:
		return "a member"
	case tenantdom.RoleViewer:
		return "a viewer"
	}
	return string(r)
}
