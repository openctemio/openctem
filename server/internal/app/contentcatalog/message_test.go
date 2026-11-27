package contentcatalog

import (
	"context"
	"testing"
	"time"

	dom "github.com/openctemio/openctem/server/pkg/domain/contentcatalog"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type msgRepo struct {
	dom.Repository
	admins []shared.ID
}

func (m msgRepo) ListAdmins(context.Context, shared.ID) ([]shared.ID, error) { return m.admins, nil }

type msgNotifier struct {
	got []notificationdom.NotificationParams
}

func (m *msgNotifier) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	m.got = append(m.got, p)
	return nil
}

func TestNoticeApprovalOff_MessageCode(t *testing.T) {
	rec := &msgNotifier{}
	s := &Service{repo: msgRepo{admins: []shared.ID{shared.NewID()}}, notifier: rec, logger: logger.NewNop()}
	at := time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC)
	s.noticeApprovalOff(context.Background(), shared.NewID(), nil, at)
	if len(rec.got) != 1 || rec.got[0].Message == nil {
		t.Fatalf("notices = %+v", rec.got)
	}
	m := rec.got[0].Message
	if m.Code != "content.approval_off" || m.Params["effective_at"] != "2026-12-01T10:00:00Z" {
		t.Errorf("message = %+v", m)
	}
}
