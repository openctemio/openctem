package mcpoauth

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/mcpoauth"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type msgNotifier struct {
	got []notificationdom.NotificationParams
}

func (m *msgNotifier) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	m.got = append(m.got, p)
	return nil
}

type msgRequests struct {
	mcpoauth.AccessRequestRepository
	admins []shared.ID
}

func (m msgRequests) DecideAccessRequest(context.Context, shared.ID, shared.ID, shared.ID, bool, time.Time) error {
	return nil
}
func (m msgRequests) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) {
	return m.admins, nil
}

func TestAccessRequestNotices_MessageCodes(t *testing.T) {
	requester, admin, decider := shared.NewID(), shared.NewID(), shared.NewID()
	ar := &mcpoauth.AccessRequest{ID: shared.NewID(), TenantID: shared.NewID(), ClientHost: "vendor.example.com",
		ClientName: "Assistant", RequestedBy: &requester}

	rec := &msgNotifier{}
	s := &Service{notifier: rec, accessRequests: msgRequests{admins: []shared.ID{admin}}, now: time.Now, log: logger.NewNop()}
	s.notifyAdmins(context.Background(), ar.TenantID, requester, ar)
	if len(rec.got) != 1 || rec.got[0].Message == nil {
		t.Fatalf("notices = %+v", rec.got)
	}
	if m := rec.got[0].Message; m.Code != "mcp.access_requested" || m.Params["app"] != "Assistant" || m.Params["host"] != "vendor.example.com" {
		t.Errorf("requested = %+v", m)
	}

	for _, tc := range []struct {
		approve bool
		code    string
		app     any
	}{{true, "mcp.access_approved", "Assistant"}, {false, "mcp.access_declined", nil}} {
		rec.got = nil
		if err := s.closeAccessRequest(context.Background(), ar, decider, tc.approve, Actor{}); err != nil {
			t.Fatal(err)
		}
		if len(rec.got) != 1 || rec.got[0].Message == nil {
			t.Fatalf("notices = %+v", rec.got)
		}
		m := rec.got[0].Message
		if m.Code != tc.code || m.Params["host"] != "vendor.example.com" || m.Params["app"] != tc.app {
			t.Errorf("%s = %+v", tc.code, m)
		}
	}
}
