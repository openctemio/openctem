package tenant

// Teams on an invitation: the invitee joins teams (data access) at
// acceptance. Design: docs/rfcs/RFC-095-role-templates-and-invitations.md §5.
//
// Threat model: an invitation is a deferred grant, so the teams pass the same
// rules as adding a member to a team, for the inviter, both when the
// invitation is created (with step-up for a privileged team) and again at
// acceptance (an inviter who lost the right voids the invitation; nothing is
// granted). A team carrying a role above member counts toward the
// outside-member two-factor rule. Teams are looked up in the invitation's own
// organization only; another organization's team answers 404 at creation and
// is never inserted at acceptance.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	roledom "github.com/openctemio/openctem/api/pkg/domain/role"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// InvitationTeams checks and applies the teams of an invitation (the group
// service satisfies it).
type InvitationTeams interface {
	CheckInvitationTeams(ctx context.Context, in accesscontrol.InvitationTeamCheck) ([]accesscontrol.InvitationTeam, error)
	ApplyInvitationTeams(ctx context.Context, tenantID string, userID shared.ID, groupIDs []string)
	InvitationTeamNames(ctx context.Context, tenantID string, groupIDs []string) []accesscontrol.InvitationTeam
}

// SetInvitationTeams wires teams on invitations. Without it an invitation
// with teams is refused.
func (s *TenantService) SetInvitationTeams(t InvitationTeams) { s.invitationTeams = t }

// errInvitationTeamsUnavailable: teams were asked for but the group service
// is not wired.
var errInvitationTeamsUnavailable = fmt.Errorf("%w: adding people to teams from an invitation is not available", shared.ErrValidation)

// normalizeTeamIDs trims, lowercases and de-duplicates team ids, and caps
// their number.
func normalizeTeamIDs(ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, raw := range ids {
		id := strings.ToLower(strings.TrimSpace(raw))
		if _, err := shared.IDFromString(id); err != nil {
			return nil, fmt.Errorf("%w: invalid team id format", shared.ErrValidation)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	if len(out) > tenantdom.MaxInvitationTeams {
		return nil, fmt.Errorf("%w: an invitation can add at most %d teams", shared.ErrValidation, tenantdom.MaxInvitationTeams)
	}
	return out, nil
}

// checkInvitationTeams checks the teams for the inviter when an invitation
// is created. It returns whether a team carries a role above member.
func (s *TenantService) checkInvitationTeams(ctx context.Context, tenantID shared.ID, inviterID string, groupIDs []string, external bool, accessEnd *time.Time) (bool, error) {
	if len(groupIDs) == 0 {
		return false, nil
	}
	if s.invitationTeams == nil {
		return false, errInvitationTeamsUnavailable
	}
	teams, err := s.invitationTeams.CheckInvitationTeams(ctx, accesscontrol.InvitationTeamCheck{
		TenantID: tenantID.String(), InviterID: inviterID, GroupIDs: groupIDs,
		External: external, AccessEnd: accessEnd, AtCreation: true,
	})
	if err != nil {
		return false, err
	}
	for _, t := range teams {
		if t.AboveMember {
			return true, nil
		}
	}
	return false, nil
}

// reauthorizeInvitationTeams re-checks the teams for the inviter at
// acceptance; a refusal voids the invitation.
func (s *TenantService) reauthorizeInvitationTeams(ctx context.Context, inv *tenantdom.Invitation) error {
	groupIDs := inv.GroupIDs()
	if len(groupIDs) == 0 {
		return nil
	}
	if s.invitationTeams == nil {
		return ErrInvitationNoLongerValid
	}
	_, err := s.invitationTeams.CheckInvitationTeams(ctx, accesscontrol.InvitationTeamCheck{
		TenantID: inv.TenantID().String(), InviterID: inv.InvitedBy().String(), GroupIDs: groupIDs,
		External:  inv.InviteeInfo().Kind == tenantdom.MemberKindExternal,
		AccessEnd: inv.Access().ExpiresAt,
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, accesscontrol.ErrGrantForbidden), errors.Is(err, shared.ErrNotFound),
		errors.Is(err, roledom.ErrRoleNotFound), errors.Is(err, shared.ErrValidation):
		s.logger.Info("invitation acceptance refused: the inviter can no longer add the invitee to its teams",
			"invitation_id", inv.ID().String(), "reason", err.Error())
		return ErrInvitationNoLongerValid
	default:
		return err
	}
}

// previewTeams adds the teams to a preview. A team the inviter cannot add
// the person to refuses the invitation (TEAM_NOT_GRANTABLE).
func (s *TenantService) previewTeams(ctx context.Context, tid shared.ID, groupIDs []string, inviterID string, out *InvitationPreview) error {
	ids, err := normalizeTeamIDs(groupIDs)
	if err != nil {
		out.refuse(PreviewTeamNotGrantable)
		return nil //nolint:nilerr // a malformed id is a refusal, not a failure
	}
	if len(ids) == 0 {
		return nil
	}
	if s.invitationTeams == nil {
		out.refuse(PreviewTeamNotGrantable)
		return nil
	}
	// The end of access is chosen after the preview; an external team only
	// needs one to exist, which the dialog then asks for.
	end := time.Now().UTC().Add(24 * time.Hour)
	teams, err := s.invitationTeams.CheckInvitationTeams(ctx, accesscontrol.InvitationTeamCheck{
		TenantID: tid.String(), InviterID: inviterID, GroupIDs: ids, External: out.Outside, AccessEnd: &end,
	})
	if err != nil {
		if errors.Is(err, accesscontrol.ErrGrantForbidden) || errors.Is(err, shared.ErrNotFound) ||
			errors.Is(err, shared.ErrValidation) {
			out.refuse(PreviewTeamNotGrantable)
			return nil
		}
		return err
	}
	for _, t := range teams {
		if t.Privileged {
			out.StepUpRequired = true
		}
		if t.AboveMember && out.Outside {
			out.Privileged, out.MFARequired, out.StepUpRequired = true, true, true
		}
	}
	return nil
}
