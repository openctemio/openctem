package integration

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// A sensor run gets a receipt: the baseline run created two findings; the
// next clean run of the same tool and profile reported one of them again
// and the coverage rules closed the other, so its receipt says still
// detected 1, closed 1, full coverage, nothing left untouched. The
// per-finding log names both.
func TestIngestReceipt_SensorRunWithCoverage(t *testing.T) {
	rr := newRepoRun(t)
	receipts := postgres.NewIngestReceiptRepository(&postgres.DB{DB: rr.r.db})
	rr.r.svc.SetReceiptRecorder(receipts)
	p := rr.r.scanProfile(rr.tn, "p-default")
	rr.baseline(p)
	cmd := rr.r.runCommand(rr.tn, "semgrep", p, "completed", 0)
	if st := rr.send(cmd, "a"); st.AutoResolve != protov2.AutoResolveApplied || st.AutoResolved != 1 {
		t.Fatalf("clean run: %+v", st)
	}
	var id string
	if err := rr.r.db.QueryRow(`SELECT id::text FROM ingest_receipts WHERE tenant_id = $1 AND source_kind = 'command' AND source_ref = $2`,
		rr.tn.tenant.String(), cmd.String()).Scan(&id); err != nil {
		t.Fatalf("no receipt for the run: %v", err)
	}
	rec, err := receipts.Get(context.Background(), rr.tn.tenant, shared.MustIDFromString(id))
	if err != nil {
		t.Fatal(err)
	}
	c := rec.Counts
	if c.Created != 0 || c.StillDetected != 1 || c.Closed != 1 || c.Untouched == nil || *c.Untouched != 0 ||
		rec.Coverage != ingestreceipt.CoverageFull || rec.CoverageNote != "resolved" || rec.ToolName != "semgrep" {
		t.Fatalf("run receipt = %+v counts %+v", rec, c)
	}
	var gone, kept string
	if err := rr.r.db.QueryRow(`
		SELECT max(a.action) FILTER (WHERE f.rule_id = 'gone'), max(a.action) FILTER (WHERE f.rule_id = 'a')
		FROM finding_ingest_actions a JOIN findings f ON f.id = a.finding_id
		WHERE a.tenant_id = $1 AND a.receipt_id = $2`, rr.tn.tenant.String(), id).Scan(&gone, &kept); err != nil {
		t.Fatal(err)
	}
	if gone != "closed" || kept != "still_detected" {
		t.Fatalf("actions: gone %q, kept %q", gone, kept)
	}
}
