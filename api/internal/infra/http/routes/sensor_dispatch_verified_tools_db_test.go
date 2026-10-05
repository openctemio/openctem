package routes

// Dispatch sends a sensor a scanner only when the sensor itself verified it:
// its own tool probe (heartbeat tools[] or the RFC-033 manifest) said the
// tool is installed. A tool the administrator merely declared on a sensor
// that never reported is unverified. Live (read-only, 2026-10-02): the
// never-reporting sensor "demo-agent-docker", declared {betterleaks, semgrep,
// trivy}, failed 24 trivy commands with "scanner not found: trivy".

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestDispatch_OnlyToolsTheSensorVerified(t *testing.T) {
	h := newCtlHarness(t)
	ctx := context.Background()
	tid := shared.MustIDFromString(h.tenantID)

	// Never reported (a heartbeat without tools); the administrator
	// declared trivy on it.
	declared := h.newLimitedSensor(h.tenantID, "declared-trivy", []string{"trivy"}, []string{"trivy"}, 0)
	h.heartbeatV2(declared, map[string]any{"status": "running"})
	// Reports trivy, but its probe failed (installed: false).
	probeFailed := h.newLimitedSensor(h.tenantID, "trivy-probe-failed", nil, nil, 0)
	h.heartbeatV2(probeFailed, map[string]any{"status": "running",
		"tools": []map[string]any{{"name": "trivy", "installed": false}}})
	// Reports trivy installed.
	verified := h.newLimitedSensor(h.tenantID, "trivy-verified", nil, nil, 0)
	h.heartbeatV2(verified, map[string]any{"status": "running",
		"tools": []map[string]any{{"name": "trivy", "version": "0.57.0", "installed": true}}})

	cands, err := h.repo.FindAvailableWithCapacity(ctx, tid, nil, "trivy")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{verified.id}; !slices.Equal(ids(cands), want) {
		t.Fatalf("trivy candidates %v, want only the sensor that verified trivy %v", ids(cands), want)
	}
	if got, _ := h.repo.FindAvailableWithTool(ctx, tid, "trivy"); got == nil || got.ID.String() != verified.id {
		t.Fatalf("FindAvailableWithTool(trivy) = %v, want %s", got, verified.id)
	}
	tools, err := h.repo.GetAvailableToolsForTenant(ctx, tid)
	if err != nil || !slices.Equal(tools, []string{"trivy"}) {
		t.Fatalf("available tools %v %v", tools, err)
	}

	// Once the verifying sensor is gone, nothing can run trivy.
	if _, err := h.db.ExecContext(ctx, `UPDATE sensors SET status = 'disabled' WHERE id = $1`, verified.id); err != nil {
		t.Fatal(err)
	}
	if ok, _ := h.repo.HasSensorForTool(ctx, tid, "trivy"); ok {
		t.Fatal("HasSensorForTool(trivy) = true with only an unverified declaration left")
	}
	if got, _ := h.repo.FindAvailableWithTool(ctx, tid, "trivy"); got != nil {
		t.Fatalf("FindAvailableWithTool(trivy) picked %s, which never verified trivy", got.ID)
	}

	// The command poll: an unzoned trivy command is not offered to the
	// declared-only sensor.
	cmd, err := h.cmds.Create(ctx, command.CreateInput{TenantID: h.tenantID, Type: "scan", Priority: "normal",
		Payload: json.RawMessage(`{"scanner":"trivy"}`), ExpiresIn: 3600})
	if err != nil {
		t.Fatal(err)
	}
	resp, raw := h.call(declared.key, http.MethodGet, "/api/v2/sensor/commands", nil)
	h.want(resp, raw, 200, "")
	var polled struct {
		Commands []struct {
			ID string `json:"id"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(raw, &polled); err != nil {
		t.Fatal(err)
	}
	for _, p := range polled.Commands {
		if p.ID == cmd.ID.String() {
			t.Fatal("the trivy command was offered to a sensor that never verified trivy")
		}
	}
}
