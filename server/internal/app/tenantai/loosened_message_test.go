package tenantai

import (
	"testing"

	aidom "github.com/openctemio/openctem/server/pkg/domain/aianalysis"
	notificationdom "github.com/openctemio/openctem/server/pkg/domain/notification"
)

func TestLoosenedMessages(t *testing.T) {
	next := aidom.UseCaseSetting{Ceiling: "internal", MinConfidence: 0.8}
	m := loosenedMessage([]string{aidom.LoosenAutoApplyOn, aidom.LoosenCeilingRaised, aidom.LoosenConfidenceLower}, next)
	lines, _ := m.Params["lines"].([]notificationdom.Message)
	if m.Code != "settings.ai_use_case.changes" || len(lines) != 3 ||
		lines[0].Code != "settings.ai_use_case.auto_apply_on" ||
		lines[1].Code != "settings.ai_use_case.ceiling_raised" || lines[1].Params["ceiling"] != "internal" ||
		lines[2].Code != "settings.ai_use_case.confidence_lower" || lines[2].Params["confidence"] != "0.80" {
		t.Errorf("use case changes = %+v", m)
	}

	hour := 5
	a := autonomyLoosenedMessage([]string{aidom.LoosenResumed, aidom.LoosenLimitRaised}, aidom.Autonomy{PerHour: &hour})
	al, _ := a.Params["lines"].([]notificationdom.Message)
	if a.Code != "settings.ai_autonomy.changes" || len(al) != 2 || al[0].Code != "settings.ai_autonomy.resumed" ||
		al[1].Code != "settings.ai_autonomy.limit_raised" || al[1].Params["per_hour"] != 5 {
		t.Errorf("autonomy changes = %+v", a)
	}
	if d, _ := al[1].Params["per_day"].(*notificationdom.Message); d == nil || d.Code != "settings.ai_autonomy.unlimited" {
		t.Errorf("per_day = %+v", al[1].Params["per_day"])
	}
}
