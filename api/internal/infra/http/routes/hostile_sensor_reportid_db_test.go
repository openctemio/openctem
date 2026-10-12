package routes

// Hostile sensor suite (see hostile_sensor_db_test.go): report ids.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// F-BOLA-1: a sensor that sends a report under the report id another sensor
// of its tenant uses, with identical bytes, used to collide with it on the
// tenant-wide idempotency index of ingest jobs: the second sensor's segment
// and commit failed. Each report keys its jobs on its own stored id now, so
// both sensors' reports are accepted and committed.
func TestHostileSensor_SameReportIDAcrossSensorsDoesNotCollide(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	ctx := context.Background()
	out, err := h.sensors.CreateSensor(ctx, sensorapp.CreateSensorInput{TenantID: h.tenantID, Name: "v2-sibling",
		Type: "worker", Capabilities: []string{"sast"}, ExecutionMode: "daemon"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.ExecContext(ctx, `UPDATE sensors SET reported_tools = '[{"name":"semgrep","installed":true}]',
		reported_tool_names = ARRAY['semgrep'], reported_at = NOW() WHERE id = $1`, out.Sensor.ID.String()); err != nil {
		t.Fatal(err)
	}

	rid := newReportID()
	base := "/api/v2/sensor/results/" + rid
	body := v2Segment("semgrep", "1.0", "a")
	commit, _ := json.Marshal(protov2.CommitRequest{SegmentCount: 1, SegmentDigests: []string{digestOf(body)}})
	for _, key := range []string{h.key, out.APIKey} {
		h.key = key
		resp, raw := h.do(http.MethodPut, base+"/segments/0", body)
		if resp.StatusCode/100 != 2 {
			t.Fatalf("segment: %d %s", resp.StatusCode, raw)
		}
		resp, raw = h.do(http.MethodPost, base+"/commit", nil, func(r *http.Request) {
			r.Body = io.NopCloser(bytes.NewReader(commit))
			r.ContentLength = int64(len(commit))
			r.Header.Set("Content-Type", "application/json")
		})
		if resp.StatusCode/100 != 2 {
			t.Fatalf("commit: %d %s", resp.StatusCode, raw)
		}
	}
}
