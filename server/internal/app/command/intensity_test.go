package command

import (
	"encoding/json"
	"testing"

	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The tier a sensor's tool gives a job counts against the scan intensity
// at claim: nuclei with custom templates is T2, so an active scan's job is
// withheld from the sensor; without them it fits (RFC-071).
func TestIntensityRefusal_ContractTier(t *testing.T) {
	g := &dispatchGate{}
	job := func(payload string, intensity string) *commanddom.Command {
		return &commanddom.Command{ID: shared.NewID(), Type: commanddom.CommandTypeScan, Payload: json.RawMessage(payload),
			DispatchGate: &commanddom.DispatchGate{Tier: 1, Intensity: intensity}}
	}
	plain := `{"scanner":"nuclei","targets":["a.example.com"]}`
	custom := `{"scanner":"nuclei","targets":["a.example.com"],"custom_templates":[{"id":"x"}]}`

	if r := g.intensityRefusal(job(plain, "active")); r != nil {
		t.Fatalf("plain nuclei at active: %+v", r)
	}
	r := g.intensityRefusal(job(custom, "active"))
	if r == nil || r.Rule != RuleIntensity {
		t.Fatalf("custom templates at active: %+v, want an intensity refusal", r)
	}
	if r := g.intensityRefusal(job(custom, "intrusive")); r != nil {
		t.Fatalf("custom templates at intrusive: %+v", r)
	}
	if r := g.intensityRefusal(job(custom, "")); r != nil {
		t.Fatalf("a job without an intensity is not capped here: %+v", r)
	}
	if r := g.intensityRefusal(job(`{"scanner":"subfinder","targets":["example.com"]}`, "bogus")); r != nil {
		t.Fatalf("an unknown intensity allows passive: %+v", r)
	}
	if r := g.intensityRefusal(job(plain, "bogus")); r == nil {
		t.Fatal("an unknown intensity must not allow an active job")
	}
}
