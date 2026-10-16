package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type behindStub struct{ refs []ticketlink.TaskLinkRef }

func (b behindStub) TaskLinksBehindForPlatform(context.Context, int) ([]ticketlink.TaskLinkRef, error) {
	return b.refs, nil
}

type syncStub struct {
	fail   shared.ID
	pushed []ticketlink.TaskLinkRef
}

func (s *syncStub) SyncTaskIssue(_ context.Context, tenantID, taskID shared.ID) error {
	if taskID == s.fail {
		return errors.New("tracker unavailable")
	}
	s.pushed = append(s.pushed, ticketlink.TaskLinkRef{TenantID: tenantID, TaskID: taskID})
	return nil
}

// Each task is pushed in its own tenant; a failed push does not stop the
// pass (it is retried on the next one).
func TestTaskTicketController_PushesEachInItsTenant(t *testing.T) {
	a := ticketlink.TaskLinkRef{TenantID: shared.NewID(), TaskID: shared.NewID()}
	b := ticketlink.TaskLinkRef{TenantID: shared.NewID(), TaskID: shared.NewID()}
	c := ticketlink.TaskLinkRef{TenantID: shared.NewID(), TaskID: shared.NewID()}
	s := &syncStub{fail: b.TaskID}
	ctl := NewTaskTicketController(behindStub{refs: []ticketlink.TaskLinkRef{a, b, c}}, s, 0, logger.NewNop())
	n, err := ctl.Reconcile(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(s.pushed) != 2 || s.pushed[0] != a || s.pushed[1] != c {
		t.Fatalf("pushed %+v", s.pushed)
	}
	if ctl.Interval().Minutes() != 1 {
		t.Fatalf("interval %s", ctl.Interval())
	}
}
