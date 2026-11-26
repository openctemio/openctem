package scan

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/scan"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type ownerNoticeSink struct {
	got []notificationdom.NotificationParams
}

func (c *ownerNoticeSink) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	c.got = append(c.got, p)
	return nil
}

type ownerNoticeAdmins struct{}

func (ownerNoticeAdmins) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) {
	return []shared.ID{shared.NewID()}, nil
}

func TestNotifyOwnerlessPause_MessageCode(t *testing.T) {
	sink := &ownerNoticeSink{}
	s := &Service{logger: logger.NewNop(), ownerAdmins: ownerNoticeAdmins{}, ownerNotifier: sink}
	sc := &scan.Scan{ID: shared.NewID(), TenantID: shared.NewID(), Name: "Nightly"}

	s.notifyOwnerlessPause(context.Background(), sc, OwnerStateInactive)
	s.notifyOwnerlessPause(context.Background(), sc, "missing")
	require.Len(t, sink.got, 2)
	assert.Equal(t, "scan.paused_owner_inactive", sink.got[0].Message.Code)
	assert.Equal(t, "Nightly", sink.got[0].Message.Params["scan"])
	assert.Equal(t, "scan.paused_no_owner", sink.got[1].Message.Code)
	assert.Equal(t, "Nightly", sink.got[1].Message.Params["scan"])
}
