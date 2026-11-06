package accesscontrol

// Edits to the security pool group (the group the organization's approval
// policy names as the pool whose members sign off high-risk decisions) need a
// recent re-authentication of the person making them: membership of that
// group is what lets an account sign a decision that hides a risk, so a
// stolen session must not be able to add an accomplice in the same sitting.
// Together with the minimum age of a pool member (finding.SecurityPoolMinAge)
// this closes the path. When the check cannot be made the edit is refused.

import (
	"context"
	"fmt"

	groupdom "github.com/openctemio/openctem/api/pkg/domain/group"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SecurityPoolLookup tells whether a group is the security pool of its
// organization (in the policy in force or the pending one).
type SecurityPoolLookup func(ctx context.Context, tenantID, groupID shared.ID) (bool, error)

// ErrSecurityPoolStepUpUnavailable refuses an edit of the security pool when
// re-authentication cannot be checked (fail closed).
var ErrSecurityPoolStepUpUnavailable = fmt.Errorf("%w: re-authentication is not available; the security pool group cannot be changed", shared.ErrForbidden)

// SetSecurityPoolGuard wires the security pool lookup and the recent
// re-authentication check. Without the lookup nothing is guarded.
func (s *GroupService) SetSecurityPoolGuard(lookup SecurityPoolLookup) { s.poolLookup = lookup }

// SetStepUpGate wires the recent re-authentication check for edits of the
// security pool group.
func (s *GroupService) SetStepUpGate(g shared.RecentAuthGate) { s.poolStepUp = g }

// requireSecurityPoolStepUp asks for a recent re-authentication when g is
// the organization's security pool group.
func (s *GroupService) requireSecurityPoolStepUp(ctx context.Context, g *groupdom.Group, actorID string) error {
	if s.poolLookup == nil {
		return nil
	}
	isPool, err := s.poolLookup(ctx, g.TenantID(), g.ID())
	if err != nil {
		return fmt.Errorf("check the security pool group: %w", err)
	}
	if !isPool {
		return nil
	}
	if s.poolStepUp == nil || actorID == "" {
		return ErrSecurityPoolStepUpUnavailable
	}
	return s.poolStepUp.RequireRecentAuth(ctx, actorID)
}
