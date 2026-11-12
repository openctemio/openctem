package handler

import (
	"testing"
	"time"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The withheld reason reaches the response for a platform task too (whose
// sensors are never listed), never with a sensor identity.
func TestPlacementResponse_Withheld(t *testing.T) {
	at := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	p := &commandapp.Placement{Status: commanddom.CommandStatusPending, Platform: true,
		Withheld: "grant_credentials", WithheldAt: &at,
		Sensors: []commandapp.SensorPlacement{{SensorID: shared.NewID(), Name: "platform-1"}}}
	resp := placementResponse(p, true)
	if resp.Withheld != "grant_credentials" || resp.WithheldAt != "2026-10-28T09:00:00Z" {
		t.Fatalf("withheld %q at %q", resp.Withheld, resp.WithheldAt)
	}
	if len(resp.Sensors) != 0 {
		t.Fatalf("a platform task listed sensors: %+v", resp.Sensors)
	}
	// A task no longer queued says nothing more.
	p.Status = commanddom.CommandStatusFailed
	if resp := placementResponse(p, true); resp.Withheld != "" {
		t.Fatalf("a finished task carried a placement reason: %q", resp.Withheld)
	}
}
