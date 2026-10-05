package routes

// POST /api/v2/sensor/commands/{id}/logs (RFC-029 §4.4.1) over the real route
// registration: the holding sensor stores a batch once, every other sensor
// (same tenant or not) gets the same not-found answer, malformed batches are
// refused, and what is stored was cleaned and redacted by the platform.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

func TestSensorV2Logs_HolderStoresOnceOthersNotFound(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "logs")
	id := h.newCommand(h.tenantID, s.id)
	resp, raw := h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/claim", map[string]any{})
	h.want(resp, raw, 200, "")

	secret := "octs_" + strings.Repeat("Z", 40)
	batch := map[string]any{"seq": 0, "lines": []map[string]any{
		{"ts": "2026-10-05T10:00:00Z", "level": "warn", "msg": "using key " + secret + "\u202e", "source": "nuclei",
			"fields": map[string]any{"target": "https://a.example", "n": 3}},
		{"ts": "2026-10-05T10:00:01Z", "level": "info", "msg": "done"},
	}}
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/logs", batch)
	h.want(resp, raw, 200, "")
	if got := decodeAs[protov2.LogsResponse](t, raw); got.Stored != 2 || got.Truncated {
		t.Fatalf("response %+v", got)
	}
	// A replay (an outbox retry) answers the same, stores nothing new.
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/logs", batch)
	h.want(resp, raw, 200, "")
	var rows, lines int
	var stored string
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT count(*), COALESCE(sum(line_count), 0), COALESCE(string_agg(lines::text, ''), '') FROM command_logs WHERE command_id = $1`, id).
		Scan(&rows, &lines, &stored); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || lines != 2 {
		t.Fatalf("%d rows, %d lines after a replay", rows, lines)
	}
	if strings.Contains(stored, secret) || strings.Contains(stored, "\u202e") {
		t.Fatalf("stored without platform redaction or cleaning: %s", stored)
	}

	// Another sensor of the tenant, another tenant's sensor, an unknown id:
	// the same not-found answer.
	other := h.newSensor(h.tenantID, "other")
	resp, raw = h.call(other.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/logs", batch)
	h.want(resp, raw, 404, ingestProblem("command-not-found"))
	stranger := h.newSensor(h.newTenant(), "stranger")
	resp, raw = h.call(stranger.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/logs", batch)
	h.want(resp, raw, 404, ingestProblem("command-not-found"))
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/0192f5a0-0000-7000-8000-000000000000/logs", batch)
	h.want(resp, raw, 404, ingestProblem("command-not-found"))
}

func TestSensorV2Logs_RefusesMalformedBatches(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "logs-bad")
	id := h.newCommand(h.tenantID, s.id)
	resp, raw := h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/"+id+"/claim", map[string]any{})
	h.want(resp, raw, 200, "")
	path := "/api/v2/sensor/commands/" + id + "/logs"
	line := map[string]any{"msg": "m"}

	resp, raw = h.call(s.key, http.MethodPost, path, map[string]any{"seq": -1, "lines": []any{line}})
	h.want(resp, raw, 400, ingestProblem("invalid-request"))
	resp, raw = h.call(s.key, http.MethodPost, path, map[string]any{"seq": protov2.MaxLogSeq, "lines": []any{line}})
	h.want(resp, raw, 400, ingestProblem("invalid-request"))
	resp, raw = h.call(s.key, http.MethodPost, path, map[string]any{"seq": 0, "lines": []any{}})
	h.want(resp, raw, 400, ingestProblem("invalid-request"))
	many := make([]any, protov2.MaxLogLinesPerBatch+1)
	for i := range many {
		many[i] = line
	}
	resp, raw = h.call(s.key, http.MethodPost, path, map[string]any{"seq": 0, "lines": many})
	h.want(resp, raw, 422, sensorProblem("too-many-items"))
	resp, raw = h.call(s.key, http.MethodPost, path, []byte(`{"seq":0,"lines":[{"msg":"`+strings.Repeat("x", protov2.MaxLogsBodyBytes)+`"}]}`))
	h.want(resp, raw, 413, ingestProblem("content-too-large"))
	resp, raw = h.call(s.key, http.MethodPost, "/api/v2/sensor/commands/not-a-uuid/logs", map[string]any{"seq": 0, "lines": []any{line}})
	h.want(resp, raw, 400, ingestProblem("invalid-id"))
}
