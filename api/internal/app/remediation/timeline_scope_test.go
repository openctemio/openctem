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

type timelineRepo struct {
	remediationdom.TaskRepository
	counts map[shared.ID]remediationdom.TaskCounts
	asked  []shared.ID
}

func (r *timelineRepo) ScopedCounts(_ context.Context, _ shared.ID, ids []shared.ID, _ *shared.DataScope) (map[shared.ID]remediationdom.TaskCounts, error) {
	r.asked = append(r.asked, ids...)
	return r.counts, nil
}

func TestScopeEvents_RedactsTasksTheReaderCannotOpen(t *testing.T) {
	tenant, self, open, hidden := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	repo := &timelineRepo{counts: map[shared.ID]remediationdom.TaskCounts{
		open: {Total: 2}, hidden: {Total: 0, Related: 0},
	}}
	s := NewTaskService(repo, logger.NewNop())
	scope := &shared.DataScope{}

	events := []remediationdom.TaskEvent{
		{Kind: remediationdom.TaskEventMembersRemoved, Data: map[string]any{
			"count": 3, "to_task_id": hidden.String(), "to_task_title": "Secret payroll fix", "move_reason": "payroll breach",
		}},
		{Kind: remediationdom.TaskEventMembersAdded, Data: map[string]any{
			"count": 1, "from_task_id": open.String(), "from_task_title": "Patch the gateway", "move_reason": "same fix",
		}},
		{Kind: remediationdom.TaskEventCreated, Data: map[string]any{"split_from": hidden.String(), "split_from_title": "Hidden parent", "title": "own title"}},
		{Kind: remediationdom.TaskEventUpdated, Data: map[string]any{"regression_of": "not-an-id", "regression_of_title": "x"}},
		{Kind: remediationdom.TaskEventUpdated, Data: nil},
	}
	require.NoError(t, s.scopeEvents(context.Background(), tenant, self, scope, events))

	h := events[0].Data
	assert.Equal(t, 3, h["count"], "counts stay")
	assert.NotContains(t, h, "to_task_id")
	assert.NotContains(t, h, "to_task_title")
	assert.NotContains(t, h, "move_reason", "free text about a move to an unreadable task is not shown")
	assert.Equal(t, true, h[TimelineHiddenKey])

	o := events[1].Data
	assert.Equal(t, "Patch the gateway", o["from_task_title"], "a readable task keeps its title")
	assert.Equal(t, "same fix", o["move_reason"])
	assert.NotContains(t, o, TimelineHiddenKey)

	sp := events[2].Data
	assert.NotContains(t, sp, "split_from")
	assert.NotContains(t, sp, "split_from_title")
	assert.Equal(t, "own title", sp["title"])

	assert.NotContains(t, events[3].Data, "regression_of", "an unparsable id fails closed")
	assert.NotContains(t, events[3].Data, "regression_of_title")
	assert.NotContains(t, repo.asked, self, "the viewed task is not looked up")
}

func TestScopeEvents_NoScopeLeavesEventsAlone(t *testing.T) {
	hidden := shared.NewID()
	repo := &timelineRepo{}
	s := NewTaskService(repo, logger.NewNop())
	events := []remediationdom.TaskEvent{{Data: map[string]any{"to_task_id": hidden.String(), "to_task_title": "T", "move_reason": "r"}}}
	require.NoError(t, s.scopeEvents(context.Background(), shared.NewID(), shared.NewID(), nil, events))
	assert.Equal(t, "T", events[0].Data["to_task_title"])
	assert.Empty(t, repo.asked)
}
