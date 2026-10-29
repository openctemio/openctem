package tenant

// Invitation links without email. A server that cannot send email still has
// to get an invitee their link: the administrator copies a new one. The raw
// token is not stored (only its hash), so a new link means a new token: the
// previous link stops working. The link is shown once, to the caller, and is
// never logged.

import (
	"context"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// InvitationLink is an invitation with its freshly issued raw token.
type InvitationLink struct {
	Invitation *tenantdom.Invitation
	// Token is the raw token for the invite link; shown once.
	Token string
}

// RegenerateInvitationLink rotates the token of a pending invitation and
// returns the new raw token without sending any email. The old link stops
// working; expiry is unchanged. A privileged invitation (a role above member
// for someone outside the organization) needs the caller's recent
// re-authentication, as creating it did.
func (s *TenantService) RegenerateInvitationLink(ctx context.Context, tenantID, invitationID string, actx auditapp.AuditContext) (*InvitationLink, error) {
	return s.reissueInvitationLink(ctx, tenantID, invitationID, actx, false)
}

// RenewInvitation gives an expired invitation a new lifetime and a new link
// (token rotated, nothing emailed). A pending invitation is refused: copy its
// link instead.
func (s *TenantService) RenewInvitation(ctx context.Context, tenantID, invitationID string, actx auditapp.AuditContext) (*InvitationLink, error) {
	return s.reissueInvitationLink(ctx, tenantID, invitationID, actx, true)
}

func (s *TenantService) reissueInvitationLink(ctx context.Context, tenantID, invitationID string, actx auditapp.AuditContext, renew bool) (*InvitationLink, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	iid, err := shared.IDFromString(invitationID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid invitation id format", shared.ErrValidation)
	}
	// Scoped to the tenant in the query: another organization's invitation is
	// a 404.
	inv, err := s.repo.GetInvitationByID(ctx, tid, iid)
	if err != nil {
		return nil, err
	}
	if inv.TenantID() != tid {
		return nil, shared.ErrNotFound
	}
	if inv.IsAccepted() {
		return nil, fmt.Errorf("%w: invitation has already been accepted", shared.ErrValidation)
	}
	if renew && !inv.IsExpired() {
		return nil, fmt.Errorf("%w: invitation has not expired; copy its link instead", shared.ErrValidation)
	}
	if !renew && inv.IsExpired() {
		return nil, fmt.Errorf("%w: invitation has expired; renew it", shared.ErrValidation)
	}
	if inv.InviteeInfo().Privileged {
		if err := s.requireStepUp(ctx, actx.ActorID); err != nil {
			return nil, err
		}
	}

	rawToken, err := inv.RotateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to rotate invitation token: %w", err)
	}
	inv.SetToken(crypto.HashToken(rawToken))
	if renew {
		inv.Renew(time.Now())
	}
	if err := s.repo.UpdateInvitation(ctx, inv); err != nil {
		return nil, fmt.Errorf("failed to persist rotated invitation token: %w", err)
	}
	// Hand back the raw token on the in-memory entity (the row keeps the hash).
	inv.SetToken(rawToken)

	action, msg := audit.ActionInvitationLinkRegenerated, "New invitation link copied for %s"
	if renew {
		action, msg = audit.ActionInvitationRenewed, "Expired invitation renewed for %s"
	}
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(action, audit.ResourceTypeInvitation, invitationID).
		WithResourceName(inv.Email()).
		WithSeverity(audit.SeverityLow).
		WithMessage(fmt.Sprintf(msg, inv.Email())).
		WithMetadata("email", inv.Email()).
		WithMetadata("privileged", inv.InviteeInfo().Privileged)
	if inv.InviteeInfo().Privileged {
		event = event.WithSeverity(audit.SeverityHigh)
	}
	s.logAudit(ctx, actx, event)

	return &InvitationLink{Invitation: inv, Token: rawToken}, nil
}
