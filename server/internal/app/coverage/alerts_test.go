package coverage

import (
	"context"
	"strings"
	"testing"
	"time"

	covdom "github.com/openctemio/openctem/server/pkg/domain/coverage"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// The unreachable alert names the capability and a count, never a target.
func TestDescribeCondition_Unreachable(t *testing.T) {
	title, body, url, _ := describeAlert([]covdom.AlertCondition{{Capability: "probe.http", Kind: covdom.AlertUnreachable, Count: 7}})
	if title != "Coverage: probe.http targets unreachable" {
		t.Fatalf("title %q", title)
	}
	if !strings.HasPrefix(body, "7 assets did not answer probe.http from your sensors;") || !strings.Contains(body, "Check that a sensor") {
		t.Fatalf("body %q", body)
	}
	if url != "/assets" {
		t.Fatalf("url %q", url)
	}
}

// A single condition carries its code and values: the capability key, the
// count, the readiness reason and the action as nested codes, so the web never
// shows the raw key or the English sentence.
func TestDescribeAlert_MessageCode(t *testing.T) {
	_, _, _, m := describeAlert([]covdom.AlertCondition{{Capability: "capture.screenshot", Kind: covdom.AlertReadiness, Reason: covdom.ReadyFeatureOff, Count: 4}})
	if m == nil || m.Code != "coverage.readiness" {
		t.Fatalf("message %+v", m)
	}
	if m.Params["capability"] != "capture.screenshot" || m.Params["count"] != 4 {
		t.Fatalf("params %+v", m.Params)
	}
	if r, ok := m.Params["readiness"].(*notificationdom.Message); !ok || r.Code != "coverage.readiness.feature_off" {
		t.Fatalf("readiness %+v", m.Params["readiness"])
	}
	if a, ok := m.Params["action"].(*notificationdom.Message); !ok || a.Code != "coverage.action.feature_off" {
		t.Fatalf("action %+v", m.Params["action"])
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
}

// A digest is coverage.digest with one coded line per condition; an unknown
// kind is a gap and a reason that is not a code segment becomes "other".
func TestDescribeAlert_DigestLines(t *testing.T) {
	_, body, _, m := describeAlert([]covdom.AlertCondition{
		{Capability: "probe.http", Kind: covdom.AlertFailing, Count: 2},
		{Capability: "dns.email", Kind: "paused", Count: 1},
		{Capability: "lookup.asn", Kind: covdom.AlertReadiness, Reason: "Bad Reason!", Count: 3},
	})
	if m.Code != "coverage.digest" || m.Params["count"] != 3 {
		t.Fatalf("message %+v", m)
	}
	lines, ok := m.Params["lines"].([]notificationdom.Message)
	if !ok || len(lines) != 3 {
		t.Fatalf("lines %+v", m.Params["lines"])
	}
	if lines[0].Code != "coverage.failing" || lines[0].Params["streak"] != covdom.FailingStreak {
		t.Fatalf("line 0 %+v", lines[0])
	}
	if lines[1].Code != "coverage.gap" {
		t.Fatalf("line 1 %+v", lines[1])
	}
	if r := lines[2].Params["readiness"].(*notificationdom.Message); r.Code != "coverage.readiness.other" {
		t.Fatalf("line 2 readiness %+v", r)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	// The English body for e-mail and chat is unchanged: one line each.
	if strings.Count(body, "\n") != 2 {
		t.Fatalf("body %q", body)
	}
}

type recordingNotifier struct {
	got []*notificationdom.Notification
}

func (r *recordingNotifier) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	r.got = append(r.got, notificationdom.NewNotification(p))
	return nil
}

type oneAdmin struct{ id shared.ID }

func (o oneAdmin) ActiveAdminIDs(context.Context, shared.ID) ([]shared.ID, error) {
	return []shared.ID{o.id}, nil
}

// A coverage alert's in-app notification is stamped with the emission time:
// the service's detection clock (here hours ahead, as the clock of a host
// that jumped) never becomes the notification time.
func TestSendAlert_NotificationTimeIsEmissionTime(t *testing.T) {
	rec := &recordingNotifier{}
	svc := NewService(nil, logger.NewNop())
	svc.now = func() time.Time { return time.Now().Add(3*time.Hour + 30*time.Minute) }
	svc.EnableAlerts(nil, oneAdmin{id: shared.NewID()}, rec, nil)

	svc.sendAlert(context.Background(), shared.NewID(), []covdom.AlertCondition{{Capability: "enumerate.web_paths", Kind: "paused", Count: 3}})

	if len(rec.got) != 1 {
		t.Fatalf("notifications = %d, want 1", len(rec.got))
	}
	if d := time.Since(rec.got[0].CreatedAt()); d < -time.Second || d > 5*time.Second {
		t.Fatalf("notification time is %v away from emission time", d)
	}
}
