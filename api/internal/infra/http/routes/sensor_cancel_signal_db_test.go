package routes

import (
	"context"
	"net/http"
	"slices"
	"testing"

	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// A canceled command reaches the sensor: the heartbeat that lists it as
// running answers it in cancel_command_ids (with the "cancel" action), on v2
// and on v1, which sdk-go's poller stops and releases. A command the sensor
// still holds is not in the list, and a sensor that reports no running list
// gets none. Before, nothing told the sensor and it ran the canceled scan to
// the end. Requires DATABASE_URL.
func TestSensorHeartbeat_CancelCommandIDs(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "cancel")
	held := h.newCommand(h.tenantID, "")
	canceled := h.newCommand(h.tenantID, "")
	for _, id := range []string{held, canceled} {
		resp, raw := h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/claim", nil)
		h.want(resp, raw, 200, "")
	}
	if _, err := h.cmds.CancelCommand(context.Background(), h.tenantID, canceled); err != nil {
		t.Fatal(err)
	}
	running := map[string]any{"status": "running", "queue": map[string]any{"running": 2}, "running": []string{held, canceled}}

	resp, raw := h.call(s.key, http.MethodPost, "/api/v2/sensor/heartbeat", running)
	h.want(resp, raw, 200, "")
	hb := decodeAs[protov2.HeartbeatResponse](t, raw)
	if !slices.Equal(hb.CancelCommandIDs, []string{canceled}) || !slices.Contains(hb.Actions, protov2.ActionCancel) {
		t.Fatalf("v2 heartbeat: cancel %v actions %v (%s)", hb.CancelCommandIDs, hb.Actions, raw)
	}

	// Nothing to stop: the member is present and empty.
	only := map[string]any{"status": "running", "queue": map[string]any{"running": 1}, "running": []string{held}}
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/heartbeat", only)
	h.want(resp, raw, 200, "")
	if hb := decodeAs[protov2.HeartbeatResponse](t, raw); hb.CancelCommandIDs == nil || len(hb.CancelCommandIDs) != 0 ||
		slices.Contains(hb.Actions, protov2.ActionCancel) {
		t.Fatalf("v2 heartbeat with nothing to cancel: %s", raw)
	}
}
