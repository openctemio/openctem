package routes

// POST /api/v2/sensor/commands/{id}/logs (RFC-029 §4.4.1) over the real route
// registration: the holding sensor stores a batch once, every other sensor
// (same tenant or not) gets the same not-found answer, malformed batches are
// refused, and what is stored was cleaned and redacted by the platform.

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
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

// A command released and claimed again by the same sensor starts a new
// attempt whose batches are numbered from 0 again: both attempts' batches
// are kept. A batch that states the lost lease epoch is refused.
func TestSensorV2Logs_ReclaimKeepsEveryAttempt(t *testing.T) {
	h := newCtlHarness(t)
	s := h.newSensor(h.tenantID, "logs")
	id := h.newCommand(h.tenantID, s.id)
	base := "/api/v2/sensor/commands/" + id
	batch := func(seq int, msg string) map[string]any {
		return map[string]any{"seq": seq, "lines": []map[string]any{{"ts": "2026-10-13T12:00:00Z", "level": "info", "msg": msg}}}
	}

	resp, raw := h.call(s.key, http.MethodPost, base+"/claim", map[string]any{})
	h.want(resp, raw, 200, "")
	for seq := 0; seq < 2; seq++ {
		resp, raw = h.call(s.key, http.MethodPost, base+"/logs", batch(seq, "first"))
		h.want(resp, raw, 200, "")
	}
	resp, raw = h.call(s.key, http.MethodPost, base+"/release", map[string]any{"reason": "restart"})
	h.want(resp, raw, 200, "")
	resp, raw = h.call(s.key, http.MethodPost, base+"/claim", map[string]any{})
	h.want(resp, raw, 200, "")
	var epoch int
	if err := h.db.QueryRowContext(context.Background(), `SELECT lease_epoch FROM commands WHERE id = $1`, id).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	for seq := 0; seq < 2; seq++ {
		resp, raw = h.call(s.key, http.MethodPost, base+"/logs", batch(seq, "second"))
		h.want(resp, raw, 200, "")
		if got := decodeAs[protov2.LogsResponse](t, raw); got.Stored != 1 || got.Dropped != 0 {
			t.Fatalf("attempt 2 seq %d: %+v", seq, got)
		}
	}
	// A retried post of the same batch within the attempt is idempotent.
	resp, raw = h.call(s.key, http.MethodPost, base+"/logs", batch(1, "second"))
	h.want(resp, raw, 200, "")
	// A batch stating the previous lease epoch is from the lost lease.
	resp, raw = h.call(s.key, http.MethodPost, base+"/logs", batch(2, "late first"),
		protov2.HeaderLeaseEpoch, strconv.Itoa(epoch-1))
	h.want(resp, raw, 409, sensorProblem("transition-conflict"))
	resp, raw = h.call(s.key, http.MethodPost, base+"/logs", batch(2, "second"),
		protov2.HeaderLeaseEpoch, strconv.Itoa(epoch))
	h.want(resp, raw, 200, "")

	var got string
	if err := h.db.QueryRowContext(context.Background(), `
		SELECT string_agg(lease_epoch::text || ':' || seq::text || ':' || (lines->0->>'msg'), ' ' ORDER BY lease_epoch, seq)
		FROM command_logs WHERE command_id = $1`, id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%[1]d:0:first %[1]d:1:first %[2]d:0:second %[2]d:1:second %[2]d:2:second", epoch-1, epoch)
	if got != want {
		t.Fatalf("stored %q, want %q", got, want)
	}
}
