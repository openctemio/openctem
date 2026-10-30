package routes

// Queued protocol v2 segments are sealed at rest (RFC-026 "Queued segments at
// rest"): the payload column never holds the segment in plaintext, a sealed
// row moved to another tenant does not open, the worker still applies it,
// the payload is emptied once applied, and segments stored in plaintext
// before are sealed in place, idempotently, by any number of workers.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/ingestpayload"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// testSegmentSealer is the sealer every v2 test of this package seals and
// opens segments with (one fixed test key, so a segment sealed by one
// harness opens in another).
func testSegmentSealer(t testing.TB) *ingestpayload.Sealer {
	t.Helper()
	s, err := ingestpayload.NewSealer(bytes.Repeat([]byte{0x5e}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// secretMarker is in every finding title of the sealed tests: it must never
// appear in a stored payload.
const secretMarker = "AKIASEALEDTESTMARKER0"

type segRow struct {
	id      string
	payload []byte
	keyID   *string
	bytes   *int64
	sha     []byte
}

func (h *v2Harness) segmentRow(reportID string, seq int) segRow {
	h.t.Helper()
	var r segRow
	if err := h.db.QueryRow(`SELECT j.id, j.payload, j.payload_key_id, j.payload_bytes, j.payload_sha
		FROM ingest_jobs j JOIN ingest_reports r ON r.id = j.ingest_report_id
		WHERE r.report_id = $1 AND r.tenant_id = $2 AND j.segment_seq = $3`, reportID, h.tenantID, seq).
		Scan(&r.id, &r.payload, &r.keyID, &r.bytes, &r.sha); err != nil {
		h.t.Fatalf("segment row: %v", err)
	}
	return r
}

func (h *v2Harness) reportState(reportID string) protov2.Status {
	h.t.Helper()
	resp, raw := h.do(http.MethodGet, "/api/v2/sensor/results/"+reportID, nil)
	h.expect(resp, raw, 200, "")
	return h.status(raw)
}

func sealedSegment() []byte {
	return v2Segment("semgrep", "1.0", secretMarker+"a", secretMarker+"b")
}

func assertSealed(t *testing.T, r segRow, plain []byte) {
	t.Helper()
	if bytes.Contains(r.payload, []byte(secretMarker)) || json.Valid(r.payload) {
		t.Fatal("the queued segment is stored in plaintext")
	}
	if r.keyID == nil || *r.keyID == "" {
		t.Fatal("payload_key_id not set on a sealed segment")
	}
	sum := sha256.Sum256(plain)
	if r.bytes == nil || *r.bytes != int64(len(plain)) || !bytes.Equal(r.sha, sum[:]) {
		t.Fatalf("payload_bytes %v / payload_sha do not describe the decoded segment", r.bytes)
	}
}

func TestSensorV2_QueuedSegmentIsSealedAtRest(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	id := newReportID()
	body := sealedSegment()
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+id, body)
	h.expect(resp, raw, 202, "")

	assertSealed(t, h.segmentRow(id, 0), body)
	// No other column of the queue row carries the segment either.
	var leaks int
	if err := h.db.QueryRow(`SELECT count(*) FROM ingest_jobs j JOIN ingest_reports r ON r.id = j.ingest_report_id
		WHERE r.report_id = $1 AND position(convert_to($2, 'UTF8') IN convert_to(row_to_json(j)::text, 'UTF8')) > 0`,
		id, secretMarker).Scan(&leaks); err != nil || leaks != 0 {
		t.Fatalf("plaintext marker in an ingest_jobs row: %d (%v)", leaks, err)
	}

	// An identical replay is still recognized (digests, not payloads).
	resp, raw = h.do(http.MethodPut, "/api/v2/sensor/results/"+id, body)
	h.expect(resp, raw, 200, "")

	h.work(id)
	if st := h.reportState(id); st.State != protov2.StateCompleted || st.Accepted.Findings != 2 {
		t.Fatalf("sealed segment not applied: %+v", st)
	}
	var titles int
	_ = h.db.QueryRow(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND title LIKE $2`,
		h.tenantID, "%"+secretMarker+"%").Scan(&titles)
	if titles != 2 {
		t.Fatalf("findings applied from the sealed segment: %d", titles)
	}
	// Finished: the payload is gone; its size and hash stay for audit.
	if r := h.segmentRow(id, 0); len(r.payload) != 0 || r.bytes == nil || *r.bytes != int64(len(body)) {
		t.Fatalf("payload of a finished report kept (%d bytes) or its size lost", len(r.payload))
	}
}

// Without a sealer the receiver refuses the segment (503) instead of
// storing it in plaintext.
func TestSensorV2_NoSealerRefusesSegments(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{noSealer: true})
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+newReportID(), sealedSegment())
	h.expect(resp, raw, 503, "unavailable")
	var n int
	_ = h.db.QueryRow(`SELECT count(*) FROM ingest_jobs WHERE tenant_id = $1`, h.tenantID).Scan(&n)
	if n != 0 {
		t.Fatalf("%d jobs stored without a sealer", n)
	}
}

// A sealed segment whose row is moved to another tenant does not open there:
// the worker records the segment as rejected and applies nothing.
func TestSensorV2_SealedSegmentMovedToAnotherTenantDoesNotOpen(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	other := newV2Harness(t, v2HarnessOpts{})
	id := newReportID()
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+id, sealedSegment())
	h.expect(resp, raw, 202, "")
	row := h.segmentRow(id, 0)
	if _, err := h.db.Exec(`UPDATE ingest_jobs SET tenant_id = $2 WHERE id = $1`, row.id, other.tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM ingest_jobs WHERE id = $1`, row.id) })

	h.work(id)
	if st := h.reportState(id); st.Accepted.Findings != 0 {
		t.Fatalf("a moved sealed segment was applied: %+v", st)
	}
	var titles int
	_ = h.db.QueryRow(`SELECT count(*) FROM findings WHERE title LIKE $1 AND tenant_id IN ($2, $3)`,
		"%"+secretMarker+"%", h.tenantID, other.tenantID).Scan(&titles)
	if titles != 0 {
		t.Fatalf("%d findings applied from a segment that should not open", titles)
	}
}

// A worker that dies mid-import (the attempt fails, the lease is lost) keeps
// the sealed payload for the retry; once an attempt completes the payload is
// emptied, while payload_sha and payload_bytes stay for the commit check.
func TestSensorV2_SealedSegmentRetryThenEmptiedOnComplete(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	id := newReportID()
	base := "/api/v2/sensor/results/" + id
	body := sealedSegment()
	resp, raw := h.do(http.MethodPut, base+"/segments/0", body)
	h.expect(resp, raw, 202, "")
	row := h.segmentRow(id, 0)
	ctx := context.Background()
	jobID := shared.MustIDFromString(row.id)

	claim := func(attempt int) {
		if _, err := h.db.Exec(`UPDATE ingest_jobs SET status = 'processing', attempts = $2, locked_by = 'test',
			locked_at = NOW() WHERE id = $1`, row.id, attempt); err != nil {
			t.Fatal(err)
		}
	}
	claim(1)
	if err := h.jobs.Fail(ctx, jobID, 1, "worker crashed", "", time.Now(), false); err != nil {
		t.Fatal(err)
	}
	if r := h.segmentRow(id, 0); !bytes.Equal(r.payload, row.payload) {
		t.Fatal("a failed attempt changed or dropped the sealed payload")
	}

	claim(2)
	job, err := h.jobs.GetV2Segment(ctx, mustReportRef(t, h, id), 0)
	if err != nil {
		t.Fatal(err)
	}
	result, err := h.proc.Process(ctx, job)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if err := h.jobs.Complete(ctx, jobID, 2, result); err != nil {
		t.Fatal(err)
	}
	r := h.segmentRow(id, 0)
	if len(r.payload) != 0 || r.bytes == nil || *r.bytes != int64(len(body)) || !bytes.Equal(r.sha, row.sha) {
		t.Fatalf("after complete: payload %d bytes, size %v", len(r.payload), r.bytes)
	}
	// The report still commits: the commit compares digests.
	b, _ := json.Marshal(protov2.CommitRequest{SegmentCount: 1, SegmentDigests: []string{digestOf(body)}})
	resp, raw = h.do(http.MethodPost, base+"/commit", b)
	if resp.StatusCode != 202 && resp.StatusCode != 200 {
		t.Fatalf("commit after the payload was emptied: %d %s", resp.StatusCode, raw)
	}
	// Only the commit job is left: a completed segment job never runs again.
	commitJob, err := h.jobs.GetV2Commit(ctx, mustReportRef(t, h, id))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.proc.Process(ctx, commitJob); err != nil {
		t.Fatalf("process commit: %v", err)
	}
	if st := h.reportState(id); st.State != protov2.StateCompleted || st.Accepted.Findings != 2 {
		t.Fatalf("report after retry: %+v", st)
	}
}

func mustReportRef(t *testing.T, h *v2Harness, reportID string) shared.ID {
	t.Helper()
	rep, err := h.reports.Get(context.Background(), shared.MustIDFromString(h.tenantID), shared.MustIDFromString(h.sensorID), reportID)
	if err != nil {
		t.Fatal(err)
	}
	return rep.ID
}

// Segments queued in plaintext before this release are sealed in place:
// several workers at once seal each row exactly once, a second run leaves a
// sealed row alone, a just-queued plaintext row waits for the next run, and
// the sealed rows are applied as before.
func TestSensorV2_PlaintextSegmentsSealedInPlace(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	ctx := context.Background()
	ids := []string{newReportID(), newReportID(), newReportID()}
	bodies := map[string][]byte{}
	for _, id := range ids {
		bodies[id] = sealedSegment()
		resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+id, bodies[id])
		h.expect(resp, raw, 202, "")
		// What the previous release stored: the decoded segment in clear.
		if _, err := h.db.Exec(`UPDATE ingest_jobs SET payload = $2, payload_key_id = NULL,
			created_at = NOW() - interval '1 hour' WHERE id = $1`, h.segmentRow(id, 0).id, bodies[id]); err != nil {
			t.Fatal(err)
		}
	}
	// One more, queued just now: left for the next run.
	fresh := newReportID()
	bodies[fresh] = sealedSegment()
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+fresh, bodies[fresh])
	h.expect(resp, raw, 202, "")
	if _, err := h.db.Exec(`UPDATE ingest_jobs SET payload = $2, payload_key_id = NULL WHERE id = $1`,
		h.segmentRow(fresh, 0).id, bodies[fresh]); err != nil {
		t.Fatal(err)
	}

	// Two workers (replicas) at once.
	procs := []*ingest.V2JobProcessor{h.proc, ingest.NewV2JobProcessor(h.ingest, h.reports, h.jobs,
		protov2.DefaultLimits(), ingest.DefaultBlindingGuard(), logger.NewNop())}
	procs[1].SetPayloadSealer(testSegmentSealer(t))
	cutoff := time.Now().Add(-5 * time.Minute)
	var wg sync.WaitGroup
	errs := make([]error, len(procs))
	for i, p := range procs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = p.SealPlaintextSegments(ctx, h.jobs, cutoff)
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	sealed := map[string][]byte{}
	for _, id := range ids {
		r := h.segmentRow(id, 0)
		assertSealed(t, r, bodies[id])
		sealed[id] = r.payload
	}
	if r := h.segmentRow(fresh, 0); r.keyID != nil || !bytes.Equal(r.payload, bodies[fresh]) {
		t.Fatal("a just-queued plaintext segment was touched")
	}

	// Idempotent: a second run does not re-seal a sealed row.
	if _, err := h.proc.SealPlaintextSegments(ctx, h.jobs, cutoff); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if r := h.segmentRow(id, 0); !bytes.Equal(r.payload, sealed[id]) {
			t.Fatalf("report %s re-sealed by a second run", id)
		}
	}

	// Sealed in place and still plaintext alike are applied.
	for _, id := range append(ids, fresh) {
		h.work(id)
		if st := h.reportState(id); st.State != protov2.StateCompleted || st.Accepted.Findings != 2 {
			t.Fatalf("report %s: %+v", id, st)
		}
	}
}

// A manifest commit measures sealed segments by their decoded size
// (payload_bytes), not by the longer ciphertext stored in payload; segments
// still stored in plaintext (no payload_bytes) are measured by their stored
// length.
func TestSensorV2_ManifestCommitOnSealedAndPlaintextSegments(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	segs := [][]byte{v2Segment("semgrep", "1.0", "a", "b"), v2Segment("semgrep", "1.0", "c")}
	id := newReportID()
	base := "/api/v2/sensor/results/" + id
	for seq, s := range segs {
		resp, raw := h.do(http.MethodPut, fmt.Sprintf("%s/segments/%d", base, seq), s)
		h.expect(resp, raw, 202, "")
	}
	sealedRow := h.segmentRow(id, 0)
	if sealedRow.keyID == nil || int64(len(sealedRow.payload)) == int64(len(segs[0])) {
		t.Fatal("test needs a sealed segment whose stored size differs from its decoded size")
	}
	// Segment 1 as an older release stored it: plaintext, no payload_bytes.
	if _, err := h.db.Exec(`UPDATE ingest_jobs SET payload = $2, payload_key_id = NULL, payload_bytes = NULL WHERE id = $1`,
		h.segmentRow(id, 1).id, segs[1]); err != nil {
		t.Fatal(err)
	}
	resp, raw := h.commit(base, manifestFor(segs, []int{2, 1}))
	h.expect(resp, raw, 202, "")
	if in, _, committed := h.reportIntegrity(id); !committed || in != protov2.IntegrityManifest {
		t.Fatalf("committed=%v integrity=%q, want a manifest commit", committed, in)
	}
}
