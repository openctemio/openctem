package handler

import (
	"testing"

	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
)

func TestExclusionReducedMessage(t *testing.T) {
	for _, a := range []string{"shortened", "removed", "deactivated"} {
		m := exclusionReducedMessage(a, "domain", "x.example")
		if m.Code != "scope.exclusion_"+a || m.Params["type"] != "domain" || m.Params["pattern"] != "x.example" {
			t.Errorf("%s: %+v", a, m)
		}
	}
}

func TestT2DurationMessage(t *testing.T) {
	m := t2DurationMessage("90d", "audit")
	if m.Code != "scope.t2_duration_changed" || m.Params["duration"] != "90d" || m.Params["reason"] != "audit" {
		t.Errorf("90d: %+v", m)
	}
	p := t2DurationMessage("permanent", "r")
	if n, _ := p.Params["duration"].(*notificationdom.Message); n == nil || n.Code != "scope.t2_duration.permanent" {
		t.Errorf("permanent: %+v", p)
	}
}
