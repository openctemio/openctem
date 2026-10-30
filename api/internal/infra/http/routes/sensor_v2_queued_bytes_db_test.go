package routes

// Byte limits on queued sensor data (research/339 G8) and queued protocol v1
// jobs sealed at rest: a tenant's queued payload bytes are capped (429 with
// Retry-After, a started report may go to twice the cap), and a v1 job still
// queued in plaintext is sealed by the worker's housekeeping, read by the
// worker sealed, and emptied once applied.

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestSensorV2_QueuedBytesCeiling(t *testing.T) {
	seg := func(name string) []byte { return v2Segment("semgrep", "1.0", name) }
	size := int64(len(seg("s0")))
	// Room for two segments of this size (same-size segments), a started
	// report for four.
	h := newV2Harness(t, v2HarnessOpts{maxQueuedBytes: 2*size + 1})
	base := "/api/v2/sensor/results/" + newReportID()

	for i := range 2 {
		resp, raw := h.do(http.MethodPut, fmt.Sprintf("%s/segments/%d", base, i), seg(fmt.Sprint("s", i)))
		h.expect(resp, raw, 202, "")
	}
	// A new report is refused: its segment would pass the ceiling.
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+newReportID(), seg("ot"))
	h.expect(resp, raw, 429, "queue-full")
	assertRetryAfter(t, resp)
	// The open report goes on up to twice the ceiling (4 segments).
	for i := 2; i < 4; i++ {
		resp, raw := h.do(http.MethodPut, fmt.Sprintf("%s/segments/%d", base, i), seg(fmt.Sprint("s", i)))
		h.expect(resp, raw, 202, "")
	}
	resp, raw = h.do(http.MethodPut, base+"/segments/4", seg("s4"))
	h.expect(resp, raw, 429, "queue-full")
	assertRetryAfter(t, resp)
	// A replay of a stored segment is never refused.
	resp, raw = h.do(http.MethodPut, base+"/segments/0", seg("s0"))
	h.expect(resp, raw, 200, "")

	// Another tenant is not held back by this one's bytes.
	o := newV2Harness(t, v2HarnessOpts{maxQueuedBytes: 2*size + 1})
	resp, raw = o.do(http.MethodPut, "/api/v2/sensor/results/"+newReportID(), seg("ot"))
	o.expect(resp, raw, 202, "")
}

// A queue whose bytes cannot be read refuses (fail closed).
func TestSensorV2_QueuedBytesUnreadableRefuses(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{maxQueuedBytes: 1 << 20, depth: brokenDepth{on: true}})
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+newReportID(), v2Segment("semgrep", "1.0", "a"))
	h.expect(resp, raw, 503, "unavailable")
}

func TestSensorV1_QueuedJobSealedReadAndEmptied(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	ctx := context.Background()
	tenantID, sensorID := shared.MustIDFromString(h.tenantID), shared.MustIDFromString(h.sensorID)
	report := []byte(`{"version":"1.0","metadata":{"id":"v1-sealed","source_type":"scanner"},"tool":{"name":"semgrep"},` +
		`"assets":[{"id":"repo","type":"repository","value":"github.com/acme/v1-sealed"}],` +
		`"findings":[{"type":"vulnerability","title":"` + secretMarker + `","severity":"high","rule_id":"r1","asset_ref":"repo"}]}`)
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM findings WHERE tenant_id = $1`, `DELETE FROM assets WHERE tenant_id = $1`,
			`DELETE FROM audit_logs WHERE tenant_id = $1`, `DELETE FROM ingest_jobs WHERE tenant_id = $1`} {
			_, _ = h.db.ExecContext(context.Background(), q, h.tenantID)
		}
	})

	// What an older release left queued: a v1 job in plaintext (parked, so
	// another package's worker never claims it).
	job := ingestjob.NewJob(tenantID, &sensorID, "v1-sealed", "scanner", report)
	job.DelayUntil(time.Now().Add(24 * time.Hour))
	stored, _, err := h.jobs.Enqueue(ctx, job)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`UPDATE ingest_jobs SET created_at = NOW() - interval '1 hour' WHERE id = $1`, stored.ID().String()); err != nil {
		t.Fatal(err)
	}

	p := ingest.NewJobProcessor(h.ingest)
	p.SetPayloadSealer(testSegmentSealer(t), h.jobs, logger.NewNop())
	p.Housekeep(ctx)

	var (
		payload []byte
		keyID   *string
		size    *int64
	)
	read := func() {
		if err := h.db.QueryRow(`SELECT payload, payload_key_id, payload_bytes FROM ingest_jobs WHERE id = $1`, stored.ID().String()).
			Scan(&payload, &keyID, &size); err != nil {
			t.Fatal(err)
		}
	}
	read()
	if keyID == nil || size == nil || *size != int64(len(report)) || string(payload) == string(report) ||
		len(payload) == 0 || bytes.Contains(payload, []byte(secretMarker)) {
		t.Fatalf("v1 job not sealed: key=%v size=%v", keyID, size)
	}

	// The worker reads it sealed, and the payload is gone once applied.
	sealedJob, err := h.jobs.GetByID(ctx, tenantID, stored.ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Process(ctx, sealedJob); err != nil {
		t.Fatalf("process sealed v1 job: %v", err)
	}
	var titles int
	_ = h.db.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND title = $2`, h.tenantID, secretMarker).Scan(&titles)
	if titles != 1 {
		t.Fatalf("findings applied from the sealed v1 job: %d", titles)
	}
	if _, err := h.db.Exec(`UPDATE ingest_jobs SET status = 'processing', attempts = 1 WHERE id = $1`, stored.ID().String()); err != nil {
		t.Fatal(err)
	}
	if err := h.jobs.Complete(ctx, stored.ID(), 1, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	read()
	if len(payload) != 0 {
		t.Fatalf("payload of an applied v1 job kept (%d bytes)", len(payload))
	}
}
