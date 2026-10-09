package accesscontrol

// Team membership expiry (RFC-050 W22, the team slice). A membership may carry
// an end date: an engagement team for a vendor tester, an audit team for an
// auditor, a contractor on a project. Teams of type "external" require one.
// The membership-expiry controller removes a membership within a minute of
// its end date; removing it recomputes the member's data scope (the
// group_members trigger) and ends every other effect of the team.

import (
	"context"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	groupdom "github.com/openctemio/openctem/api/pkg/domain/group"
	"github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ErrExpiryRequired is returned when a membership of an external team has no
// end date.
var ErrExpiryRequired = fmt.Errorf("%w: a membership of an external team needs an end date (expires_at)", shared.ErrValidation)

// WithExpiredMemberLister wires the cross-organization lister the expiry
// controller uses.
func WithExpiredMemberLister(l groupdom.ExpiredMemberLister) GroupServiceOption {
	return func(s *GroupService) { s.expiredLister = l }
}

// applyMembershipExpiry sets the end date on m and enforces that external
// teams have one.
func applyMembershipExpiry(g *groupdom.Group, m *groupdom.Member, expiresAt *time.Time, reason string, now time.Time) error {
	if expiresAt == nil && g.GroupType() == groupdom.GroupTypeExternal {
		return ErrExpiryRequired
	}
	return m.SetExpiry(expiresAt, reason, now)
}

// SetGroupMemberAccessInput changes when a team membership ends.
type SetGroupMemberAccessInput struct {
	GroupID string    `json:"-"`
	UserID  shared.ID `json:"-"`
	// ExpiresAt nil removes the end date (not allowed on external teams).
	ExpiresAt *time.Time `json:"expires_at"`
	Reason    string     `json:"reason" validate:"max=500"`
}

// SetMemberAccess sets, moves or clears the end date of a team membership.
// Extending someone's membership keeps their access, so it has the same cap
// as adding them: the caller cannot change their own membership and needs
// every asset of the team in their own scope (D13).
func (s *GroupService) SetMemberAccess(ctx context.Context, input SetGroupMemberAccessInput, actx auditapp.AuditContext) (*groupdom.Member, error) {
	groupID, err := shared.IDFromString(input.GroupID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid group id format", shared.ErrValidation)
	}
	g, err := s.groupForTenant(ctx, groupID, actx.TenantID)
	if err != nil {
		return nil, err
	}
	if err := s.checkMembershipDelegation(ctx, g, input.UserID, actx.ActorID); err != nil {
		return nil, err
	}
	member, err := s.repo.GetMember(ctx, groupID, input.UserID)
	if err != nil {
		return nil, err
	}
	old := member.ExpiresAt()
	if err := applyMembershipExpiry(g, member, input.ExpiresAt, input.Reason, time.Now().UTC()); err != nil {
		return nil, err
	}
	if err := s.repo.UpdateMember(ctx, member); err != nil {
		return nil, fmt.Errorf("failed to update member access: %w", err)
	}

	actx.TenantID = g.TenantID().String()
	event := auditapp.NewSuccessEvent(audit.ActionMemberAccessChanged, audit.ResourceTypeGroup, input.GroupID).
		WithMessage("Team membership end date changed").
		WithMetadata("user_id", input.UserID.String()).
		WithMetadata("expires_at_before", formatExpiry(old)).
		WithMetadata("expires_at", formatExpiry(member.ExpiresAt())).
		WithMetadata("reason", member.ExpiryReason()).
		WithSeverity(audit.SeverityMedium)
	s.logAudit(ctx, actx, event)
	return member, nil
}

func formatExpiry(t *time.Time) string {
	if t == nil {
		return "none"
	}
	return t.UTC().Format(time.RFC3339)
}

// ExpireMemberships removes up to batch memberships whose end date has
// passed, in every organization. Each removal recomputes that member's data
// scope (database trigger), is audited and tells the member. It returns how
// many were removed.
func (s *GroupService) ExpireMemberships(ctx context.Context, now time.Time, batch int) (int, error) {
	if s.expiredLister == nil {
		return 0, nil
	}
	expired, err := s.expiredLister.ListExpiredMembers(ctx, now, batch)
	if err != nil {
		return 0, fmt.Errorf("list expired memberships: %w", err)
	}
	removed := 0
	for _, e := range expired {
		if err := s.repo.RemoveMember(ctx, e.GroupID, e.UserID); err != nil {
			if groupdom.IsMemberNotFound(err) {
				continue // removed meanwhile
			}
			s.logger.Error("failed to remove an expired team membership", "error", err,
				"group_id", e.GroupID.String(), "user_id", e.UserID.String())
			continue
		}
		removed++
		if s.accessControlRepo != nil {
			if err := s.accessControlRepo.RefreshAccessForMemberRemove(ctx, e.GroupID, e.UserID); err != nil {
				s.logger.Error("failed to refresh access for an expired membership", "error", err)
			}
		}
		actx := auditapp.AuditContext{TenantID: e.TenantID.String()}
		event := auditapp.NewSuccessEvent(audit.ActionMemberRemoved, audit.ResourceTypeGroup, e.GroupID.String()).
			WithResourceName(e.GroupName).
			WithMessage("Team membership ended (end date reached)").
			WithMetadata("user_id", e.UserID.String()).
			WithMetadata("reason", "expired").
			WithMetadata("expires_at", e.ExpiresAt.UTC().Format(time.RFC3339)).
			WithMetadata("expiry_reason", e.Reason).
			WithSeverity(audit.SeverityHigh)
		s.logAudit(ctx, actx, event)

		if s.notificationService != nil {
			audienceID, groupID := e.UserID, e.GroupID
			if err := s.notificationService.Notify(ctx, notification.NotificationParams{
				TenantID:         e.TenantID,
				Audience:         notification.AudienceUser,
				AudienceID:       &audienceID,
				NotificationType: notification.TypeRoleChanged,
				Title:            fmt.Sprintf("Your membership of team %q has ended", e.GroupName),
				Body:             fmt.Sprintf("Your membership of the team %q reached its end date.", e.GroupName),
				Severity:         notification.SeverityInfo,
				ResourceType:     "group",
				ResourceID:       &groupID,
				URL:              teamsSettingsURL,
			}); err != nil {
				s.logger.Error("failed to notify an expired member", "error", err, "user_id", e.UserID.String())
			}
		}
	}
	return removed, nil
}
