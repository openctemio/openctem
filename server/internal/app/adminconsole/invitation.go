package adminconsole

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A new platform administrator is invited, never handed a password. Provision
// creates the account without one and a single-use set-password link that
// expires after AdminInvitationTTL. The link goes to the new address, so only
// the person who controls that mailbox can set the password and enroll the
// second factor; the administrator who made the invitation never learns
// anything that signs in as the new account. That is what keeps the four-eyes
// approval of a new super administrator meaningful: the requester cannot walk
// through the approved account.

// AdminInvitationTTL is how long an administrator's set-password link works.
const AdminInvitationTTL = 24 * time.Hour

// Invitation is the single-use set-password token of a new administrator's
// account. Only a hash of the token is stored.
type Invitation struct {
	Token     string
	ExpiresAt time.Time
}

// InvitationMailer delivers an invitation through the platform's own mail
// sender. It is optional: without it nothing can be emailed.
type InvitationMailer interface {
	// CanDeliver reports whether mail can be sent at all.
	CanDeliver(ctx context.Context) bool
	// SetupURL is the page where the token is used to choose a password.
	SetupURL(token string) string
	// SendAdminInvitation emails the link to the new administrator.
	SendAdminInvitation(ctx context.Context, email, name, token string, expiresIn time.Duration) error
}

// SetInvitationMailer wires the mail sender used for invitations.
func (s *Service) SetInvitationMailer(m InvitationMailer) { s.invites = m }

// CanSendInvitation reports whether an invitation can be e-mailed.
func (s *Service) CanSendInvitation(ctx context.Context) bool {
	return s != nil && s.invites != nil && s.invites.CanDeliver(ctx)
}

// ErrInvitationNeedsEmail refuses a new super administrator while approvals
// are on and the platform cannot send mail. Without mail the link would have
// to be shown to the person who asked for the account, who could then sign in
// as the account the second administrator just approved.
var ErrInvitationNeedsEmail = fmt.Errorf("%w: while approvals are on, a new super admin is invited by e-mail only; configure SMTP first", shared.ErrValidation)

// Provisioned is the outcome of Provision.
type Provisioned struct {
	Admin *admin.AdminUser
	// Emailed: the invitation was sent to the new address.
	Emailed bool
	// EmailFailed: mail is configured but the send failed. No link is
	// returned; the administrator can use "forgot password" on the sign-in
	// page, or the account can be removed and added again.
	EmailFailed bool
	// SetupLink is returned only when the platform cannot send mail and the
	// role may be handed the link (a non-super role, or any role while
	// approvals are off). It is shown once and never stored.
	SetupLink string
	// ExpiresAt is when the invitation stops working.
	ExpiresAt time.Time
}
