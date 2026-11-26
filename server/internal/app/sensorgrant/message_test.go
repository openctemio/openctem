package sensorgrant

import (
	"context"
	"testing"

	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	sensordom "github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type msgAdmins struct{ ids []shared.ID }

func (m msgAdmins) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) { return m.ids, nil }

type msgNotifier struct {
	got []notificationdom.NotificationParams
}

func (m *msgNotifier) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	m.got = append(m.got, p)
	return nil
}

func TestGrantWidened_MessageCode(t *testing.T) {
	rec := &msgNotifier{}
	s := &Service{admins: msgAdmins{ids: []shared.ID{shared.NewID()}}, notifier: rec, log: logger.NewNop()}
	g := sensordom.Grant{TenantID: shared.NewID(), SensorID: shared.NewID()}
	s.onChanged(context.Background(), Actor{TenantID: g.TenantID, Email: "a@example.com"}, g, g,
		[]string{"tools", "zones"}, []string{"tools"})
	if len(rec.got) != 1 || rec.got[0].Message == nil {
		t.Fatalf("notices = %+v", rec.got)
	}
	m := rec.got[0].Message
	if m.Code != "sensor.grant_widened" || m.Params["by"] != "a@example.com" || m.Params["changed"] != "tools, zones" {
		t.Errorf("message = %+v", m)
	}
	if m.Params["sensor"] != g.SensorID.String() {
		t.Errorf("sensor = %v", m.Params["sensor"])
	}
}
