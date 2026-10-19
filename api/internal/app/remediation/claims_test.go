package remediation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// claimRepo answers GetTask for the tasks it knows; others are not found
// (what a caller who cannot read a task gets).
type claimRepo struct {
	remediationdom.TaskRepository
	tasks map[shared.ID]*remediationdom.Task
}

func (r *claimRepo) GetTask(_ context.Context, _, id shared.ID) (*remediationdom.Task, error) {
	if t, ok := r.tasks[id]; ok {
		cp := *t
		return &cp, nil
	}
	return nil, remediationdom.ErrTaskNotFound
}

func TestDescribeConflicts_CountOnlyForUnreadableTask(t *testing.T) {
	tenant, readable, hidden := shared.NewID(), shared.NewID(), shared.NewID()
	group := shared.NewID()
	repo := &claimRepo{tasks: map[shared.ID]*remediationdom.Task{
		readable: {ID: readable, Title: "Patch the gateway", AssigneeGroupID: &group, State: remediationdom.TaskStateOpen},
	}}
	s := NewTaskService(repo, logger.NewNop())
	f1, f2 := shared.NewID(), shared.NewID()
	in := &remediationdom.FindingsInOtherTaskError{Conflicts: []remediationdom.FindingConflict{
		{FindingID: f1, FindingTitle: "a", TaskID: readable},
		{FindingID: f2, FindingTitle: "b", TaskID: hidden},
	}}

	err := s.describeConflicts(context.Background(), tenant, in, true)
	e, ok := remediationdom.AsFindingsInOtherTask(err)
	require.True(t, ok)
	require.Len(t, e.Conflicts, 2)
	require.NotNil(t, e.Conflicts[0].TaskTitle)
	assert.Equal(t, "Patch the gateway", *e.Conflicts[0].TaskTitle)
	assert.Equal(t, &group, e.Conflicts[0].AssigneeGroupID)
	assert.True(t, e.Conflicts[0].CanMove)

	assert.Equal(t, hidden, e.Conflicts[1].TaskID)
	assert.Nil(t, e.Conflicts[1].TaskTitle, "no title of a task the caller cannot read")
	assert.Nil(t, e.Conflicts[1].AssigneeUserID)
	assert.Nil(t, e.Conflicts[1].AssigneeGroupID)
	assert.False(t, e.Conflicts[1].CanMove)

	// Without remediation write access nothing can be moved.
	err = s.describeConflicts(context.Background(), tenant, in, false)
	e, _ = remediationdom.AsFindingsInOtherTask(err)
	assert.False(t, e.Conflicts[0].CanMove)
	require.NotNil(t, e.Conflicts[0].TaskTitle)
}

func TestPrepareConflicts_MoveNeedsWriteAccess(t *testing.T) {
	s := NewTaskService(&claimRepo{}, logger.NewNop())
	f := shared.NewID()
	_, err := s.prepareConflicts(context.Background(), shared.NewID(), []shared.ID{f},
		remediationdom.ConflictResolution{Move: []shared.ID{f}, MoveReason: "x"}, false, nil)
	assert.ErrorIs(t, err, remediationdom.ErrMoveNotAllowed)

	res, err := s.prepareConflicts(context.Background(), shared.NewID(), []shared.ID{f},
		remediationdom.ConflictResolution{Skip: true, MovableFrom: map[shared.ID]bool{shared.NewID(): true}}, false, nil)
	require.NoError(t, err)
	assert.Nil(t, res.MovableFrom, "a client cannot pre-clear source tasks")
}
