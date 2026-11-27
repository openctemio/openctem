package liveness

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type capInApp struct {
	got []notificationdom.NotificationParams
}

func (c *capInApp) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	c.got = append(c.got, p)
	return nil
}

type oneAdmin struct{}

func (oneAdmin) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) {
	return []shared.ID{shared.NewID()}, nil
}

func TestNotify_MessageCodes(t *testing.T) {
	c := &capInApp{}
	s := &Service{logger: logger.NewNop(), admins: oneAdmin{}, inApp: c}
	ctx := context.Background()

	s.notify(ctx, shared.NewID(), Result{Closed: []shared.ID{shared.NewID(), shared.NewID()}, ClosedCritical: 1, GoneHeld: 3})
	require.Len(t, c.got, 1)
	m := c.got[0].Message
	require.NotNil(t, m)
	assert.Equal(t, "liveness.closed", m.Code)
	assert.Equal(t, 2, m.Params["count"])
	assert.Equal(t, 1, m.Params["critical"])
	assert.Equal(t, 3, m.Params["held"])

	c.got = nil
	s.notify(ctx, shared.NewID(), Result{GoneHeld: 4})
	require.Len(t, c.got, 1)
	m = c.got[0].Message
	assert.Equal(t, "liveness.held", m.Code)
	assert.Equal(t, 4, m.Params["held"])
}
