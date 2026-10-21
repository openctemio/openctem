package remediation

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/participation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ParticipationAccess answers the access questions of watchers on remediation
// tasks (RFC-120). A task is read through its findings: a person can read it
// when at least one of its member findings is in their data scope, the rule
// GetTask applies to the caller.
type ParticipationAccess struct{ s *TaskService }

var _ participation.ItemAccess = ParticipationAccess{}

// ParticipationAccess returns the task side of the watchers feature.
func (s *TaskService) ParticipationAccess() ParticipationAccess { return ParticipationAccess{s: s} }

// CallerAccess checks that the caller can read the task (ErrNotFound
// otherwise).
func (a ParticipationAccess) CallerAccess(ctx context.Context, tenantID, taskID shared.ID) (participation.Access, error) {
	if _, err := a.s.GetTask(ctx, tenantID, taskID); err != nil {
		return participation.Access{}, err
	}
	return participation.Access{}, nil
}

// UserMayRead reports whether the person could read the task: one of its
// member findings is inside their data scope.
func (a ParticipationAccess) UserMayRead(ctx context.Context, tenantID, taskID, userID shared.ID) (bool, error) {
	s := a.s
	if _, err := s.repo.GetTask(ctx, tenantID, taskID); err != nil {
		return false, err
	}
	if s.dataScope == nil {
		return true, nil
	}
	scope, err := s.dataScope.ForUser(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}
	if scope == nil {
		return true, nil
	}
	counts, err := s.repo.ScopedCounts(ctx, tenantID, []shared.ID{taskID}, scope)
	if err != nil {
		return false, err
	}
	c := counts[taskID]
	return c.Total > 0 || c.Related > 0, nil
}
