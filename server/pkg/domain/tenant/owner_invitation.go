package tenant

// Ownership invitations: an organization a platform administrator created
// for a person who already has an account waits, with no owner and no
// member, until that account accepts. Design:
// docs/architecture/organization-ownership-invitations.md.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Ownership invitation lifetimes and resend limits.
const (
	// OwnerInvitationTTL is how long an invitation (or a resent one) stays
	// open.
	OwnerInvitationTTL = 7 * 24 * time.Hour
	// OwnerInvitationResendInterval is the shortest time between two sends.
	OwnerInvitationResendInterval = 10 * time.Minute
	// OwnerInvitationMaxSends caps the sends of one invitation (the first
	// included); a new invitee starts a new invitation.
	OwnerInvitationMaxSends = 5
)

// OwnerInvitationStatus is the stored state of an invitation. An expired
// invitation stays pending in storage; View reports it as expired.
type OwnerInvitationStatus string

const (
	OwnerInvitationPending  OwnerInvitationStatus = "pending"
	OwnerInvitationAccepted OwnerInvitationStatus = "accepted"
	OwnerInvitationDeclined OwnerInvitationStatus = "declined"
	OwnerInvitationCanceled OwnerInvitationStatus = "canceled"
	// OwnerInvitationExpired is reported, never stored.
	OwnerInvitationExpired OwnerInvitationStatus = "expired"
)

// Ownership invitation errors.
var (
	// ErrOwnerInvitationNotFound: no such invitation for this account (also
	// the answer for another account's invitation, so it tells nothing).
	ErrOwnerInvitationNotFound = fmt.Errorf("%w: this invitation is no longer available", shared.ErrNotFound)
	// ErrOwnerInvitationExpired: the invitation lapsed; the administrator
	// can send it again.
	ErrOwnerInvitationExpired = fmt.Errorf("%w: this invitation has expired; ask the platform administrator to send it again", shared.ErrValidation)
	// ErrOwnerInvitationNotAllowed: an invitation can only be (re)issued for
	// an organization created waiting for its owner that nobody has entered.
	ErrOwnerInvitationNotAllowed = fmt.Errorf("%w: an ownership invitation can only be sent for an organization that is waiting for its first owner and has no members", shared.ErrConflict)
	// ErrOwnerInvitationResendTooSoon: resent within the interval.
	ErrOwnerInvitationResendTooSoon = fmt.Errorf("%w: the invitation was sent a moment ago; try again in a few minutes", shared.ErrConflict)
	// ErrOwnerInvitationResendLimit: the invitation was sent too many times.
	ErrOwnerInvitationResendLimit = fmt.Errorf("%w: this invitation was sent the maximum number of times; cancel it or invite again", shared.ErrConflict)
	// ErrOwnerInviteeNotEligible: the account cannot own an organization
	// (inactive or a service account).
	ErrOwnerInviteeNotEligible = fmt.Errorf("%w: this account cannot own an organization", shared.ErrValidation)
	// ErrOwnerInviteeEmailUnverified: the invitee must verify their email
	// address before accepting.
	ErrOwnerInviteeEmailUnverified = fmt.Errorf("%w: verify your email address before accepting", shared.ErrValidation)
)

// OwnerInvitation invites one account to become an organization's owner.
type OwnerInvitation struct {
	ID            shared.ID
	TenantID      shared.ID
	InviteeUserID shared.ID
	InviteeEmail  string
	// InvitedBy is the platform administrator (zero when unknown).
	InvitedBy shared.ID
	Status    OwnerInvitationStatus
	ExpiresAt time.Time
	// SendCount is how many times the invitee was emailed; 0 when the
	// installation could not send email (LastSentAt is then nil).
	SendCount   int
	LastSentAt  *time.Time
	RespondedAt *time.Time
	CreatedAt   time.Time
}

// NewOwnerInvitation builds a pending invitation for the account inviteeID.
func NewOwnerInvitation(tenantID, inviteeID shared.ID, inviteeEmail string, invitedBy shared.ID, now time.Time) (*OwnerInvitation, error) {
	email := strings.ToLower(strings.TrimSpace(inviteeEmail))
	if tenantID.IsZero() || inviteeID.IsZero() || email == "" {
		return nil, fmt.Errorf("%w: an ownership invitation needs an organization and an account", shared.ErrValidation)
	}
	now = now.UTC()
	return &OwnerInvitation{
		ID: shared.NewID(), TenantID: tenantID, InviteeUserID: inviteeID, InviteeEmail: email,
		InvitedBy: invitedBy, Status: OwnerInvitationPending, ExpiresAt: now.Add(OwnerInvitationTTL),
		SendCount: 1, LastSentAt: &now, CreatedAt: now,
	}, nil
}

// MarkNotSent records that the invitee was not emailed (the installation
// cannot send email): no send is counted and there is no send time. The
// invitee still finds it in the app after signing in.
func (i *OwnerInvitation) MarkNotSent() {
	i.SendCount = 0
	i.LastSentAt = nil
}

// IsExpired reports whether a pending invitation has lapsed at now.
func (i *OwnerInvitation) IsExpired(now time.Time) bool {
	return i.Status == OwnerInvitationPending && !now.Before(i.ExpiresAt)
}

// IsOpen reports whether the invitation can still be accepted at now.
func (i *OwnerInvitation) IsOpen(now time.Time) bool {
	return i.Status == OwnerInvitationPending && now.Before(i.ExpiresAt)
}

// EffectiveStatus is the status to show: expired for a lapsed pending one.
func (i *OwnerInvitation) EffectiveStatus(now time.Time) OwnerInvitationStatus {
	if i.IsExpired(now) {
		return OwnerInvitationExpired
	}
	return i.Status
}

// ResendAllowedAt is the earliest time the invitation may be sent again.
func (i *OwnerInvitation) ResendAllowedAt() time.Time {
	if i.LastSentAt == nil {
		return time.Time{} // never sent: no interval to wait
	}
	return i.LastSentAt.Add(OwnerInvitationResendInterval)
}

// CheckResend reports whether the invitation may be sent again at now.
func (i *OwnerInvitation) CheckResend(now time.Time) error {
	switch {
	case i.Status != OwnerInvitationPending:
		return ErrOwnerInvitationNotFound
	case i.SendCount >= OwnerInvitationMaxSends:
		return ErrOwnerInvitationResendLimit
	case now.Before(i.ResendAllowedAt()):
		return ErrOwnerInvitationResendTooSoon
	}
	return nil
}

// OwnerInvitationOffer is a pending invitation as the invitee sees it.
type OwnerInvitationOffer struct {
	ID               shared.ID
	TenantID         shared.ID
	OrganizationName string
	OrganizationSlug string
	CreatedAt        time.Time
	ExpiresAt        time.Time
}

// OwnerInvitationRepository stores ownership invitations. Every write that
// creates an owner, or (re)issues an invitation, runs in one transaction
// under the organization's first-owner lock.
type OwnerInvitationRepository interface {
	// CreateWithOwnerInvitation creates the organization with no member and
	// its pending invitation atomically.
	CreateWithOwnerInvitation(ctx context.Context, t *Tenant, inv *OwnerInvitation) error
	// LatestOwnerInvitation returns the organization's newest invitation
	// (shared.ErrNotFound when it has none).
	LatestOwnerInvitation(ctx context.Context, tenantID shared.ID) (*OwnerInvitation, error)
	// ReplaceOwnerInvitation cancels the organization's pending invitation
	// and stores inv, only while the organization is waiting for its first
	// owner (an invitation history, none accepted) and has no member at all;
	// ErrOwnerInvitationNotAllowed otherwise. It returns the canceled one.
	ReplaceOwnerInvitation(ctx context.Context, inv *OwnerInvitation) (canceled *OwnerInvitation, err error)
	// ResendOwnerInvitation records a new send of the pending invitation
	// (renewing its expiry) when CheckResend allows it at now.
	ResendOwnerInvitation(ctx context.Context, tenantID shared.ID, now time.Time) (*OwnerInvitation, error)
	// CancelOwnerInvitation cancels the pending invitation.
	CancelOwnerInvitation(ctx context.Context, tenantID shared.ID, now time.Time) (*OwnerInvitation, error)
	// ListOpenOwnerInvitations lists the invitations userID can accept now.
	ListOpenOwnerInvitations(ctx context.Context, userID shared.ID, now time.Time) ([]OwnerInvitationOffer, error)
	// AcceptOwnerInvitation makes the membership newOwner builds (an owner
	// membership of userID) the organization's owner when invitation id is
	// userID's, pending and open, and the organization has no owner; it
	// marks the invitation accepted. ErrOwnerInvitationNotFound for anyone
	// else's or a used invitation.
	AcceptOwnerInvitation(ctx context.Context, id, userID shared.ID, newOwner func(tenantID shared.ID) (*Membership, error), now time.Time) (*OwnerInvitation, *Membership, error)
	// DeclineOwnerInvitation marks userID's pending invitation declined.
	DeclineOwnerInvitation(ctx context.Context, id, userID shared.ID, now time.Time) (*OwnerInvitation, error)
}
