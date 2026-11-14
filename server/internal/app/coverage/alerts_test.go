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
	title, body, url := describeAlert([]covdom.AlertCondition{{Capability: "probe.http", Kind: covdom.AlertUnreachable, Count: 7}})
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
