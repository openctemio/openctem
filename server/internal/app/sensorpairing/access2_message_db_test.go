package sensorpairing_test

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/sensorpairing"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

type a2Admins struct{ ids []shared.ID }

func (a a2Admins) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) { return a.ids, nil }

type a2Notifier struct {
	got []notificationdom.NotificationParams
}

func (n *a2Notifier) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	n.got = append(n.got, p)
	return nil
}

func (n *a2Notifier) find(code string) *notificationdom.Message {
	for _, p := range n.got {
		if p.Message != nil && p.Message.Code == code {
			return p.Message
		}
	}
	return nil
}

// Every enrollment notice carries its message code and the values its
// English text shows.
func TestEnrollmentNotices_MessageCodes_DB(t *testing.T) {
	f, a := enrollmentFixture(t)
	rec := &a2Notifier{}
	f.svc.SetNotifications(a2Admins{ids: []shared.ID{a.UserID}}, rec)

	v := f.createToken(a, sensorpairing.CreateEnrollmentTokenInput{Name: "k8s-prod", MaxUses: 3, RequireApproval: true})
	m := rec.find("sensor.enrollment_token_created")
	if m == nil || m.Params["token"] != "k8s-prod" || m.Params["uses"] != 3 || m.Params["by"] != a.Email {
		t.Fatalf("token created: %+v", m)
	}
	if _, ok := m.Params["expires_at"].(string); !ok {
		t.Errorf("expires_at = %v", m.Params["expires_at"])
	}
	if ap, _ := m.Params["approval"].(*notificationdom.Message); ap == nil || ap.Code != "sensor.approval.required" {
		t.Errorf("approval = %v", m.Params["approval"])
	}

	s := newSensor(7)
	if err := f.enroll(s, v.Token, "203.0.113.31"); err != nil {
		t.Fatal(err)
	}
	f.reveal(s)
	w := rec.find("sensor.waits_for_approval")
	if w == nil || w.Params["token"] != "k8s-prod" || w.Params["from"] != "203.0.113.31" || w.Params["sensor"] == "" || w.Params["sas"] == "" {
		t.Fatalf("waits for approval: %+v", w)
	}

	// An automatic token enrolls at once and says so.
	rec.got = nil
	v2 := f.createToken(a, sensorpairing.CreateEnrollmentTokenInput{Name: "auto", MaxUses: 1})
	if m := rec.find("sensor.enrollment_token_created"); m == nil ||
		m.Params["approval"].(*notificationdom.Message).Code != "sensor.approval.automatic" {
		t.Fatalf("automatic token: %+v", m)
	}
	s2 := newSensor(8)
	if err := f.enroll(s2, v2.Token, "203.0.113.32"); err != nil {
		t.Fatal(err)
	}
	f.reveal(s2)
	e := rec.find("sensor.enrolled")
	if e == nil || e.Params["token"] != "auto" || e.Params["from"] != "203.0.113.32" || e.Params["sas"] == "" || e.Params["key_fingerprint"] == "" {
		t.Fatalf("enrolled: %+v", e)
	}
	if pm, _ := e.Params["profile"].(*notificationdom.Message); pm == nil {
		t.Errorf("profile = %v", e.Params["profile"])
	}
}
