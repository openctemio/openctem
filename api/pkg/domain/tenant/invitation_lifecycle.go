package tenant

// Invitation lifecycle details
// (docs/rfcs/RFC-095-role-templates-and-invitations.md §5).

import (
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	// ResendCooldown is the shortest time between two sends of one invitation.
	ResendCooldown = 10 * time.Minute
	// MaxInvitationResends caps how often one invitation is sent again.
	MaxInvitationResends = 5
	// InvitationsPerInviterPerHour caps how many invitations one person sends
	// in an hour, on every plan (the plan's daily limit applies on top).
	InvitationsPerInviterPerHour = 50
)

// ErrInvitationResendTooSoon refuses a resend within ResendCooldown of the
// last send, or beyond MaxInvitationResends.
var ErrInvitationResendTooSoon = errors.New("this invitation was sent recently or too often; wait before sending it again")

// ErrInvitationRateLimited refuses an invitation beyond
// InvitationsPerInviterPerHour.
var ErrInvitationRateLimited = errors.New("too many invitations sent in the last hour; try again later")

var errInvalidInviteeKind = fmt.Errorf("%w: invalid invitee kind", shared.ErrValidation)

// InviteeInfo is what the inviter was told when the invitation was created:
// whether the invitee is outside the organization and whether the roles are
// above member (so two-factor will be required). Shown in the pending list;
// the acceptance classifies the invitee again.
type InviteeInfo struct {
	Kind       MemberKind
	Privileged bool
}

// SetInviteeInfo records the invitee information.
func (i *Invitation) SetInviteeInfo(info InviteeInfo) error {
	switch info.Kind {
	case "", MemberKindInternal, MemberKindExternal:
	default:
		return errInvalidInviteeKind
	}
	i.invitee = info
	return nil
}

// InviteeInfo returns the invitee information (internal when unknown).
func (i *Invitation) InviteeInfo() InviteeInfo {
	info := i.invitee
	if info.Kind == "" {
		info.Kind = MemberKindInternal
	}
	return info
}

// LastSentAt is when the invitation email was last sent (created or resent).
func (i *Invitation) LastSentAt() time.Time {
	if i.lastSentAt != nil {
		return *i.lastSentAt
	}
	return i.createdAt
}

// ResendCount is how many times the invitation was sent again.
func (i *Invitation) ResendCount() int { return i.resendCount }

// SetSendHistory restores the send history from persistence.
func (i *Invitation) SetSendHistory(lastSentAt *time.Time, resendCount int) {
	i.lastSentAt = lastSentAt
	i.resendCount = resendCount
}

// MarkResent records a resend at now, refusing one within ResendCooldown of
// the last send or beyond MaxInvitationResends.
func (i *Invitation) MarkResent(now time.Time) error {
	if i.resendCount >= MaxInvitationResends || now.Sub(i.LastSentAt()) < ResendCooldown {
		return ErrInvitationResendTooSoon
	}
	t := now.UTC()
	i.lastSentAt = &t
	i.resendCount++
	return nil
}
