package sensorpairing

import (
	"context"
	"net"
	"testing"
	"time"

	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	sensordom "github.com/openctemio/openctem/server/pkg/domain/sensor"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type a2DenyRepo struct{ sensordom.PairingRepository }

func (a2DenyRepo) Deny(context.Context, shared.ID, shared.ID, shared.ID, string, time.Time) (*sensordom.Pairing, error) {
	return nil, nil
}

func TestFingerprintMismatch_MessageCode(t *testing.T) {
	for _, tc := range []struct {
		ip   net.IP
		from any
	}{{net.ParseIP("198.51.100.4"), "198.51.100.4"}, {nil, nil}} {
		rec := &msgNotifier{}
		s := &Service{repo: a2DenyRepo{}, admins: msgAdmins{ids: []shared.ID{shared.NewID()}}, notifier: rec,
			log: logger.NewNop(), now: time.Now}
		p := &sensordom.Pairing{ID: shared.NewID(), SourceIP: tc.ip, Thumbprint: "t"}
		s.fingerprintMismatch(context.Background(), Actor{TenantID: shared.NewID(), Email: "a@example.com"}, p, "code")
		if len(rec.got) != 1 || rec.got[0].Message == nil {
			t.Fatalf("notices = %+v", rec.got)
		}
		m := rec.got[0].Message
		if m.Code != "sensor.pairing_wrong_fingerprint" || m.Params["by"] != "a@example.com" {
			t.Fatalf("message = %+v", m)
		}
		if tc.from != nil && m.Params["from"] != tc.from {
			t.Errorf("from = %v", m.Params["from"])
		}
		if tc.from == nil {
			if fm, ok := m.Params["from"].(*notificationdom.Message); !ok || fm.Code != "sensor.unknown_address" {
				t.Errorf("from = %v", m.Params["from"])
			}
		}
	}
}
