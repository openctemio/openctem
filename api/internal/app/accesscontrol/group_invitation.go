package accesscontrol

// Teams on an invitation: the inviter adds the invitee to teams, applied at
// acceptance. Design: docs/rfcs/RFC-095-role-templates-and-invitations.md §5.
//
// The rules are those of adding a member to a team (AddMember), checked
// against the inviter instead of the request's caller: the team belongs to
// the organization and is active; the inviter may grant every role the team
// carries; a team carrying a privileged role is the owner's to change (with
// step-up when the invitation is created); an external team needs an end of
// access; someone outside the organization never gets full data access
// through a team. At acceptance the same checks run again for the inviter,
// without step-up.

import (
	"context"
	"fmt"
	"time"

	groupdom "github.com/openctemio/openctem/api/pkg/domain/group"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ErrInvitationTeamInactive: a team on an invitation is not active.
var ErrInvitationTeamInactive = fmt.Errorf("%w: this team is not active", shared.ErrValidation)

// InvitationTeamCheck is what the invitation says about its invitee.
type InvitationTeamCheck struct {
	TenantID  string
	InviterID string
	GroupIDs  []string
	// External: the invitee is outside the organization.
	External bool
	// AccessEnd: the invitation's end of access (nil: none).
	AccessEnd *time.Time
	// AtCreation: the invitation is being created (step-up and the
	// inviter's data-scope cap apply); false at acceptance.
	AtCreation bool
}

// InvitationTeam is one checked team.
type InvitationTeam struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// AboveMember: the team carries a role above the member level (the
	// outside-member two-factor rule counts it).
	AboveMember bool `json:"above_member"`
	// Privileged: the team carries a privileged role, so only the owner adds
	// members to it (with step-up).
	Privileged bool `json:"privileged"`
}

// CheckInvitationTeams applies the team rules for an invitation. It returns
// the teams in the order given.
func (s *GroupService) CheckInvitationTeams(ctx context.Context, in InvitationTeamCheck) ([]InvitationTeam, error) {
	out := make([]InvitationTeam, 0, len(in.GroupIDs))
	for _, raw := range in.GroupIDs {
		id, err := shared.IDFromString(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid team id format", shared.ErrValidation)
		}
		g, err := s.groupForTenant(ctx, id, in.TenantID)
		if err != nil {
			return nil, err
		}
		if !g.IsActive() {
			return nil, ErrInvitationTeamInactive
		}
		if g.GroupType() == groupdom.GroupTypeExternal && in.AccessEnd == nil {
			return nil, ErrExpiryRequired
		}
		if in.AtCreation {
			if err := s.requireWholeGroupInScope(ctx, g); err != nil {
				return nil, err
			}
		}
		above, privileged, err := s.checkInvitationTeamRoles(ctx, g, in)
		if err != nil {
			return nil, err
		}
		out = append(out, InvitationTeam{ID: g.ID().String(), Name: g.Name(), AboveMember: above, Privileged: privileged})
	}
	return out, nil
}

// checkInvitationTeamRoles checks the roles team g carries for the inviter.
// It returns whether a role is above member and whether one is privileged.
func (s *GroupService) checkInvitationTeamRoles(ctx context.Context, g *groupdom.Group, in InvitationTeamCheck) (bool, bool, error) {
	roles, err := s.boundRoles(ctx, g)
	if err != nil || len(roles) == 0 {
		return false, false, err
	}
	a, err := s.roles.loadGrantActor(ctx, asRoleID(g.TenantID()), in.InviterID)
	if err != nil {
		return false, false, err
	}
	privileged, fullData, above := false, false, false
	for _, r := range roles {
		if err := a.mayGrant(r); err != nil {
			return false, false, err
		}
		privileged = privileged || isPrivileged(r)
		fullData = fullData || r.HasFullDataAccess()
		above = above || permission.IsAboveMember(r.Permissions(), r.HasFullDataAccess())
	}
	if privileged {
		if in.AtCreation {
			if err := s.requireOwnerStepUp(ctx, a); err != nil {
				return false, false, err
			}
		} else if !a.system && !a.owner {
			return false, false, ErrPrivilegedTeamOwnerOnly
		}
	}
	if fullData && in.External {
		return false, false, ErrExternalTeamFullData
	}
	return above, privileged, nil
}

// ApplyInvitationTeams finishes adding a new member to the teams the
// acceptance inserted: their data scope is refreshed and their cached
// permissions dropped (a team may carry roles). Best effort.
func (s *GroupService) ApplyInvitationTeams(ctx context.Context, tenantID string, userID shared.ID, groupIDs []string) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return
	}
	for _, raw := range groupIDs {
		gid, err := shared.IDFromString(raw)
		if err != nil {
			continue
		}
		if s.accessControlRepo != nil {
			if err := s.accessControlRepo.RefreshAccessForMemberAdd(ctx, gid, userID); err != nil {
				s.logger.Error("refresh access for an invited team member", "error", err, "group_id", raw)
			}
		}
	}
	s.invalidateMembers(ctx, tid, []shared.ID{userID})
}

// InvitationTeamNames returns the active teams among groupIDs that belong to
// tenantID, with their names, for the acceptance page. Unknown ids and other
// organizations' teams are left out.
func (s *GroupService) InvitationTeamNames(ctx context.Context, tenantID string, groupIDs []string) []InvitationTeam {
	out := make([]InvitationTeam, 0, len(groupIDs))
	for _, raw := range groupIDs {
		id, err := shared.IDFromString(raw)
		if err != nil {
			continue
		}
		g, err := s.groupForTenant(ctx, id, tenantID)
		if err != nil || !g.IsActive() {
			continue
		}
		out = append(out, InvitationTeam{ID: g.ID().String(), Name: g.Name()})
	}
	return out
}
