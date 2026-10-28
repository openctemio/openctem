package accesscontrol

import (
	"context"
	"fmt"

	assetgroupdom "github.com/openctemio/openctem/api/pkg/domain/assetgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Asset groups that teams depend on. A team's scope rules can name an asset
// group, so who is in that group decides what the team sees. When the team
// holds a privileged role, changing the group's members or rule is as
// sensitive as changing the team: only the owner, with a recent sign-in
// (the rule for privileged team changes in group_role.go).

// FlagPrivileged marks each team that holds a privileged role. A team that
// cannot be read is treated as privileged (fail closed).
func (s *GroupService) FlagPrivileged(ctx context.Context, tenantID shared.ID, teams []assetgroupdom.Use) ([]assetgroupdom.Use, error) {
	out := make([]assetgroupdom.Use, len(teams))
	copy(out, teams)
	if s.roles == nil || s.bindings == nil {
		return out, nil
	}
	for i := range out {
		g, err := s.repo.GetByTenantAndID(ctx, tenantID, out[i].ID)
		if err != nil {
			out[i].Privileged = true
			continue
		}
		roles, err := s.boundRoles(ctx, g)
		if err != nil {
			out[i].Privileged = true
			continue
		}
		for _, r := range roles {
			if isPrivileged(r) {
				out[i].Privileged = true
				break
			}
		}
	}
	return out, nil
}

// RequireOwnerStepUp passes only for the tenant's owner with a recent
// sign-in. An actor that cannot be identified is refused.
func (s *GroupService) RequireOwnerStepUp(ctx context.Context, tenantID shared.ID, actorID string) error {
	if s.roles == nil {
		return fmt.Errorf("%w: only the owner changes a group that a privileged team uses", ErrGrantForbidden)
	}
	if actorID == "" {
		return ErrPrivilegedTeamOwnerOnly
	}
	a, err := s.roles.loadGrantActor(ctx, asRoleID(tenantID), actorID)
	if err != nil {
		return err
	}
	return s.requireOwnerStepUp(ctx, a)
}
