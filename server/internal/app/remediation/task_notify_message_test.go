package remediation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	remediationdom "github.com/openctemio/openctem/server/pkg/domain/remediation"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type captureNotifier struct {
	got []notificationdom.NotificationParams
}

func (c *captureNotifier) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	c.got = append(c.got, p)
	return nil
}

func TestTaskNotices_MessageCodes(t *testing.T) {
	tenant, user, actor := shared.NewID(), shared.NewID(), shared.NewID()
	src := &remediationdom.Task{ID: shared.NewID(), TenantID: tenant, Title: "Patch A", AssigneeUserID: &user}
	dst := &remediationdom.Task{ID: shared.NewID(), TenantID: tenant, Title: "Patch B", AssigneeUserID: &user}
	cn := &captureNotifier{}
	s := &TaskService{
		repo:     &claimRepo{tasks: map[shared.ID]*remediationdom.Task{src.ID: src, dst.ID: dst}},
		notifier: cn, queryNotifier: cn, logger: logger.NewNop(),
	}
	ctx := context.Background()

	s.notifyNewOwner(ctx, src, &user, nil, &actor)
	require.Len(t, cn.got, 1)
	assert.Equal(t, "remediation.task_assigned", cn.got[0].Message.Code)
	assert.Equal(t, "Patch A", cn.got[0].Message.Params["task"])

	cn.got = nil
	s.notifyMoveOwners(ctx, remediationdom.TaskMoveEvent{TenantID: tenant, FromTaskID: src.ID, FromTitle: "Patch A",
		ToTaskID: &dst.ID, ToTitle: "Patch B", Findings: 3, ActorID: &actor})
	require.Len(t, cn.got, 2)
	m := cn.got[0].Message
	assert.Equal(t, "remediation.findings_moved", m.Code)
	assert.Equal(t, 3, m.Params["count"])
	assert.Equal(t, "Patch A", m.Params["task"])
	assert.Equal(t, "Patch B", m.Params["to_task"])
	m = cn.got[1].Message
	assert.Equal(t, "remediation.findings_joined", m.Code)
	assert.Equal(t, 3, m.Params["count"])
	assert.Equal(t, "Patch B", m.Params["task"])
	assert.Equal(t, "Patch A", m.Params["from_task"])

	cn.got = nil
	s.notifyMoveOwners(ctx, remediationdom.TaskMoveEvent{TenantID: tenant, FromTaskID: src.ID, Findings: 1, ActorID: &actor})
	require.Len(t, cn.got, 1)
	assert.Equal(t, "remediation.findings_taken_out", cn.got[0].Message.Code)
	assert.Equal(t, 1, cn.got[0].Message.Params["count"])
}

func TestQueryOwnerNotice_Message(t *testing.T) {
	owner := shared.NewID()
	task := &remediationdom.Task{ID: shared.NewID(), TenantID: shared.NewID(), Title: "Auto"}
	q := &remediationdom.TaskQuery{OwnerUserID: &owner}
	cn := &captureNotifier{}
	s := &TaskService{queryNotifier: cn, logger: logger.NewNop()}

	s.notifyQueryOwner(context.Background(), task, q, "b",
		notificationdom.Msg("remediation.query_added", "count", 2, "task", task.Title))
	require.Len(t, cn.got, 1)
	assert.Equal(t, "remediation.query_added", cn.got[0].Message.Code)
}

func TestSafeReasonSegment(t *testing.T) {
	assert.Equal(t, "other", safeReasonSegment("Bad Reason"))
	assert.Equal(t, "other", safeReasonSegment(""))
	assert.Equal(t, "owner_lost_access", safeReasonSegment("owner_lost_access"))
}
