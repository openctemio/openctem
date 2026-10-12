package routes

// Hostile sensor suite (see hostile_sensor_db_test.go): staging retention.

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// H4: a sensor that opens a report, fills it and abandons it (or lets it
// expire) used to leave every decoded segment payload in the database
// forever, and an abandoned report frees its open-report slot at once. The
// purge empties expired reports' payloads, and deletes failed and expired
// reports past the retention.
func TestHostileSensor_AbandonedReportsDoNotKeepPayloads(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	ctx := context.Background()

	// Fill a report with one segment, then abandon it.
	rid := newReportID()
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+rid+"/segments/0", v2Segment("semgrep", "1.0", "a", "b"))
	if resp.StatusCode/100 != 2 {
		t.Fatalf("segment: %d %s", resp.StatusCode, raw)
	}
	resp, raw = h.do(http.MethodDelete, "/api/v2/sensor/results/"+rid, nil)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("abandon: %d %s", resp.StatusCode, raw)
	}
	payloadBytes := func(reportID string) int {
		var n int
		if err := h.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(octet_length(j.payload)), 0) FROM ingest_jobs j
			JOIN ingest_reports ir ON ir.id = j.ingest_report_id
			WHERE ir.tenant_id = $1 AND ir.report_id = $2`, h.tenantID, reportID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if payloadBytes(rid) == 0 {
		t.Fatal("setup: the abandoned report kept no payload to purge")
	}

	h.proc.Housekeep(ctx)
	if n := payloadBytes(rid); n != 0 {
		t.Fatalf("an abandoned report still holds %d payload bytes after the purge", n)
	}

	// Past the retention, the report row goes too (its jobs cascade).
	if _, err := h.db.ExecContext(ctx, `UPDATE ingest_reports SET updated_at = NOW() - $3::interval
		WHERE tenant_id = $1 AND report_id = $2`, h.tenantID, rid, (ingest.StagingRetention + time.Hour).String()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.reports.PurgeStaging(ctx, time.Now().Add(-ingest.StagingRetention), 100); err != nil {
		t.Fatal(err)
	}
	if _, err := h.reports.Get(ctx, shared.MustIDFromString(h.tenantID), shared.MustIDFromString(h.sensorID), rid); err == nil {
		t.Fatal("an expired report past the retention was kept")
	}
}

// H4: the report header (tool and metadata) is stored with the report, so
// it is capped: a segment whose metadata alone is huge is report-too-large.
func TestHostileSensor_OversizedHeaderRefused(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	big := strings.Repeat("x", ingest.MaxV2HeaderBytes)
	body := bytes.Replace(v2Segment("semgrep", "1.0", "a"), []byte(`"coverage_type":"full"`),
		[]byte(`"coverage_type":"full","properties":{"pad":"`+big+`"}`), 1)
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+newReportID(), body)
	h.expect(resp, raw, http.StatusRequestEntityTooLarge, "report-too-large")
}
