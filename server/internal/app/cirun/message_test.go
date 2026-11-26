package cirun

import (
	"context"
	"testing"

	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

type msgAdmins struct{ ids []shared.ID }

func (m msgAdmins) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) { return m.ids, nil }

type msgInApp struct {
	got []notificationdom.NotificationParams
}

func (m *msgInApp) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	m.got = append(m.got, p)
	return nil
}

func TestAlertAdmins_CarriesMessage(t *testing.T) {
	rec := &msgInApp{}
	n := NewAdminAlerts(msgAdmins{ids: []shared.ID{shared.NewID()}}, rec, nil, nil)
	n.AlertAdmins(context.Background(), shared.NewID(), AdminAlert{
		Title: "t", Body: "b", Message: notificationdom.Msg("ci.test", "k", "v"),
	})
	if len(rec.got) != 1 || rec.got[0].Message == nil || rec.got[0].Message.Code != "ci.test" || rec.got[0].Message.Params["k"] != "v" {
		t.Fatalf("notices = %+v", rec.got)
	}
}
