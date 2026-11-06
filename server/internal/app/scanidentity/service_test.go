package scanidentity

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	cst "github.com/openctemio/openctem/api/internal/app/consolesetting/consolesettingtest"
	"github.com/openctemio/openctem/api/pkg/domain/platformsetting"
	"github.com/openctemio/openctem/api/pkg/domain/scanident"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var layer = scanident.PlatformLayer{UserAgent: " openctem-scanner ", Headers: []scanident.Header{
	{Name: " X-Operator ", Value: " saas ", Enforced: true},
}}

func TestNothingStoredIsAnEmptyLayer(t *testing.T) {
	svc := NewService(cst.NewRepo(), cst.Recorder(&cst.Audit{}, &cst.Notifier{}))
	l, err := svc.PlatformLayer(context.Background())
	if err != nil || l.UserAgent != "" || len(l.Headers) != 0 {
		t.Fatalf("%+v %v", l, err)
	}
}

// A change is trimmed, validated, needs a reason and an administrator, is
// audited, and a stale form is refused.
func TestUpdate(t *testing.T) {
	audit := &cst.Audit{}
	svc := NewService(cst.NewRepo(), cst.Recorder(audit, &cst.Notifier{}))
	ctx := context.Background()
	actor := cst.SuperAdmin(t)
	if _, err := svc.Update(ctx, nil, layer, "why", 0, "", ""); !errors.Is(err, ErrNoActor) {
		t.Fatalf("no actor: %v", err)
	}
	if _, err := svc.Update(ctx, actor, layer, "  ", 0, "", ""); !errors.Is(err, consolesetting.ErrReasonRequired) {
		t.Fatalf("no reason: %v", err)
	}
	for _, bad := range []scanident.PlatformLayer{
		{Headers: []scanident.Header{{Name: "Authorization", Value: "Bearer x"}}},
		{Headers: []scanident.Header{{Name: "X-A", Value: "a\r\nX-B: b"}}},
		{Headers: []scanident.Header{{Name: "X-A", Value: "1"}, {Name: "x-a", Value: "2"}}},
		{Headers: []scanident.Header{{Name: "A", Value: "1"}, {Name: "B", Value: "1"}, {Name: "C", Value: "1"}, {Name: "D", Value: "1"}, {Name: "E", Value: "1"}}},
	} {
		if _, err := svc.Update(ctx, actor, bad, "why", 0, "", ""); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%+v accepted: %v", bad, err)
		}
	}
	if len(audit.Entries) != 0 {
		t.Fatal("a refused change was audited")
	}
	g, err := svc.Update(ctx, actor, layer, "operator identity", 0, "", "")
	if err != nil || g.Version != 1 || g.Layer.UserAgent != "openctem-scanner" || g.Layer.Headers[0].Name != "X-Operator" || g.Layer.Headers[0].Value != "saas" {
		t.Fatalf("%+v %v", g, err)
	}
	if len(audit.Entries) != 1 {
		t.Fatalf("audit rows %d", len(audit.Entries))
	}
	if _, err := svc.Update(ctx, actor, layer, "again", 0, "", ""); !errors.Is(err, platformsetting.ErrVersionConflict) {
		t.Fatalf("stale form: %v", err)
	}
	l, err := svc.PlatformLayer(ctx)
	if err != nil || !l.Headers[0].Enforced {
		t.Fatalf("%+v %v", l, err)
	}
}
