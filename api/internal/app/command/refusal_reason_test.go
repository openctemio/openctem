package command

import (
	"encoding/json"
	"strings"
	"testing"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
)

func TestRequeueableLayer(t *testing.T) {
	for layer, want := range map[string]bool{
		sensordom.RefusalLayerLocal:            true,
		sensordom.RefusalLayerManaged:          true,
		sensordom.RefusalLayerPlatformToolGate: true,
		sensordom.RefusalLayerScope:            false, // fail closed: platform bug or attack
		sensordom.RefusalLayerBuiltin:          false, // same deny list on every sensor
		"unknown":                              false,
	} {
		if got := requeueableLayer(layer); got != want {
			t.Errorf("requeueableLayer(%q) = %v, want %v", layer, got, want)
		}
	}
}

func TestRefusalFailureReason(t *testing.T) {
	payload := json.RawMessage(`{"targets":["vndirect.example","pti.example"]}`)
	local := []commanddom.RefusalRecord{
		{SensorID: "0123456789abcdef", SensorName: "office-1", Layer: "local", Rule: "targets.allow", Detail: "outside"},
		{SensorID: "fedcba9876543210", Layer: "local", Rule: "tools.allow"},
	}
	got := RefusalFailureReason(payload, local, false)
	for _, want := range []string{
		sensordom.LocalPolicyRefusalPrefix + "tools.allow", // the last refusal leads (older readers parse it)
		`"vndirect.example" and 1 more target(s)`,
		"office-1 (local/targets.allow)",
		"sensor fedcba98 (local/tools.allow)",
		"sensors/office-1/policy/sensor-policy.yaml",
		LocalPolicyDocsURL,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("reason %q lacks %q", got, want)
		}
	}
	scope := RefusalFailureReason(payload, []commanddom.RefusalRecord{{SensorID: "x", Layer: "scope", Rule: "targets"}}, false)
	if !strings.Contains(scope, "signed") || strings.Contains(scope, "sensor-policy.yaml") {
		t.Errorf("scope reason %q: must point at the signed scope, not at the local policy", scope)
	}
	shared := RefusalFailureReason(payload, local, true)
	if strings.Contains(shared, "office-1") || strings.Contains(shared, "fedcba98") || strings.Contains(shared, "sensor-policy.yaml") {
		t.Errorf("shared reason %q names or identifies a shared sensor", shared)
	}
	if !strings.Contains(shared, "No shared sensor accepted") {
		t.Errorf("shared reason %q", shared)
	}
	if got := RefusalFailureReason(nil, nil, false); got == "" {
		t.Error("empty reason")
	}
}
