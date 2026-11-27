package sensorpairing

import (
	"context"
	"net"
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

func TestOnApproved_MessageCode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		repair bool
		ip     net.IP
		code   string
		from   any
	}{
		{"paired", false, net.ParseIP("10.1.2.3"), "sensor.paired", "10.1.2.3"},
		{"repaired", true, nil, "sensor.repaired", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &msgNotifier{}
			s := &Service{admins: msgAdmins{ids: []shared.ID{shared.NewID()}}, notifier: rec, log: logger.NewNop()}
			p := &sensordom.Pairing{SAS: "ABCD", SourceIP: tc.ip, Thumbprint: "t"}
			res := &sensordom.PairingApprovalResult{Pairing: p, SensorID: shared.NewID(), Repair: tc.repair}
			s.onApproved(context.Background(), Actor{TenantID: shared.NewID(), Email: "a@example.com"}, res, "edge-1", "collector")
			if len(rec.got) != 1 || rec.got[0].Message == nil {
				t.Fatalf("notices = %+v", rec.got)
			}
			m := rec.got[0].Message
			if m.Code != tc.code || m.Params["sensor"] != "edge-1" || m.Params["by"] != "a@example.com" || m.Params["sas"] != "ABCD" {
				t.Errorf("message = %+v", m)
			}
			if tc.from != nil && m.Params["from"] != tc.from {
				t.Errorf("from = %v", m.Params["from"])
			}
			if tc.from == nil {
				if fm, ok := m.Params["from"].(*notificationdom.Message); !ok || fm.Code != "sensor.unknown_address" {
					t.Errorf("from = %v", m.Params["from"])
				}
			}
			pm, ok := m.Params["profile"].(*notificationdom.Message)
			if !ok || pm.Code != "sensor.profile.collector" {
				t.Errorf("profile = %v", m.Params["profile"])
			}
			if _, ok := m.Params["key_fingerprint"].(string); !ok {
				t.Errorf("key_fingerprint missing")
			}
			if err := m.Validate(); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestSensorProfileMessage(t *testing.T) {
	for in, want := range map[string]string{"internal-network-scanner": "sensor.profile.internal_network_scanner", "x y": "sensor.profile.other"} {
		if got := sensorProfileMessage(in).Code; got != want {
			t.Errorf("%q -> %s, want %s", in, got, want)
		}
	}
}
