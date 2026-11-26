package tenant

import (
	"context"
	"testing"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
	"github.com/openctemio/openctem/server/pkg/domain/scangov"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/server/pkg/domain/tenant"
)

func TestPolicyLoosenedWith_CarriesValues(t *testing.T) {
	rec := &recordingNotifier{}
	svc := a2Service(rec, nil)
	svc.notifyPolicyLoosenedWith(context.Background(), shared.NewID().String(), auditapp.AuditContext{ActorID: shared.NewID().String()},
		"settings.api_key_lifetime_raised", "t", "w", "/x", "from_days", 90, "to_days", 365)
	m := a2One(t, rec)
	if m.Code != "settings.api_key_lifetime_raised" || m.Params["who"] != "Alice" || m.Params["from_days"] != 90 || m.Params["to_days"] != 365 {
		t.Errorf("message = %+v", m)
	}
}

func TestClosureLoosenedParams(t *testing.T) {
	kv := notificationdom.Msg("x", closureLoosenedParams(tenantdom.ClosureSettings{Mode: tenantdom.ClosingModeAuto, CriticalAutoClose: true}, "2026-01-02T03:04:05Z")...)
	mode, _ := kv.Params["mode"].(*notificationdom.Message)
	crit, _ := kv.Params["critical"].(*notificationdom.Message)
	if mode == nil || mode.Code != "settings.closing_mode.auto" || crit == nil || crit.Code != "settings.closing_critical.yes" ||
		kv.Params["takes_effect_at"] != "2026-01-02T03:04:05Z" {
		t.Errorf("params = %+v", kv.Params)
	}
	unset := notificationdom.Msg("x", closureLoosenedParams(tenantdom.ClosureSettings{}, "t")...)
	if m, _ := unset.Params["mode"].(*notificationdom.Message); m == nil || m.Code != "settings.closing_mode.review" {
		t.Errorf("unset mode = %+v", unset.Params["mode"])
	}
}

func TestScanModeParam(t *testing.T) {
	for m, want := range map[scangov.Mode]string{scangov.ModeStrict: "strict", scangov.ModeOn: "on", scangov.ModeOff: "off", "": "off"} {
		if got := scanModeParam(m); got.Code != "settings.scan_approval_mode."+want {
			t.Errorf("%q -> %s", m, got.Code)
		}
	}
}
