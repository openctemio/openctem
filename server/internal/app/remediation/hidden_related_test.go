package remediation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type scopeRepoStub struct{ datascope.Repository }

func (scopeRepoStub) HasFullDataRole(context.Context, shared.ID, shared.ID) (bool, error) {
	return false, nil
}

// storedRepo holds one task with stored counters and answers the scoped
// counters the test sets.
type storedRepo struct {
	remediationdom.TaskRepository
	task   remediationdom.Task
	scoped remediationdom.TaskCounts
}

func (r *storedRepo) GetTask(context.Context, shared.ID, shared.ID) (*remediationdom.Task, error) {
	cp := r.task
	return &cp, nil
}

func (r *storedRepo) ScopedCounts(_ context.Context, _ shared.ID, ids []shared.ID, _ *shared.DataScope) (map[shared.ID]remediationdom.TaskCounts, error) {
	return map[shared.ID]remediationdom.TaskCounts{ids[0]: r.scoped}, nil
}

func newScopedService(repo remediationdom.TaskRepository) *TaskService {
	s := NewTaskService(repo, logger.NewNop())
	user := shared.NewID().String()
	s.SetDataScope(datascope.New(scopeRepoStub{}, func(context.Context) datascope.Caller {
		return datascope.Caller{UserID: user}
	}, logger.NewNop()))
	return s
}

// A task whose only hidden members are related ones stays visible, shows no
// hidden primary members, and is still read-only for the caller.
func TestWritableTask_HiddenRelatedMemberBlocksWrites(t *testing.T) {
	tenant, id := shared.NewID(), shared.NewID()
	repo := &storedRepo{
		task:   remediationdom.Task{ID: id, TenantID: tenant, Counts: remediationdom.TaskCounts{Total: 2, Related: 3}},
		scoped: remediationdom.TaskCounts{Total: 2, Related: 2},
	}
	s := newScopedService(repo)

	got, err := s.GetTask(context.Background(), tenant, id)
	require.NoError(t, err)
	assert.Equal(t, 0, got.HiddenMembers, "the displayed hidden count stays primary only")
	assert.Equal(t, 1, got.HiddenRelated)
	assert.True(t, got.HasHidden())

	_, err = s.writableTask(context.Background(), tenant, id)
	assert.ErrorIs(t, err, remediationdom.ErrTaskHiddenMembers)

	// Everything visible: writable.
	repo.scoped = remediationdom.TaskCounts{Total: 2, Related: 3}
	_, err = s.writableTask(context.Background(), tenant, id)
	assert.NoError(t, err)
}
