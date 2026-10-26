package routes

import (
	"context"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Two findings on one host, and the same report with one of them left out.
const (
	receiptNessusFull = `<?xml version="1.0"?>
<NessusClientData_v2><Report name="r"><ReportHost name="192.0.2.77"><HostProperties><tag name="host-ip">192.0.2.77</tag></HostProperties>
<ReportItem port="22" svc_name="ssh" protocol="tcp" severity="3" pluginID="1001" pluginName="OpenSSH issue" pluginFamily="General"><cve>CVE-2024-0001</cve></ReportItem>
<ReportItem port="443" svc_name="www" protocol="tcp" severity="2" pluginID="1002" pluginName="TLS issue" pluginFamily="General"></ReportItem>
</ReportHost></Report></NessusClientData_v2>`
	receiptNessusSubset = `<?xml version="1.0"?>
<NessusClientData_v2><Report name="r"><ReportHost name="192.0.2.77"><HostProperties><tag name="host-ip">192.0.2.77</tag></HostProperties>
<ReportItem port="22" svc_name="ssh" protocol="tcp" severity="3" pluginID="1001" pluginName="OpenSSH issue" pluginFamily="General"><cve>CVE-2024-0001</cve></ReportItem>
</ReportHost></Report></NessusClientData_v2>`
)

// An upload gets one receipt: the first import creates both findings; a
// partial re-upload that leaves one out sees the other again and closes
// nothing (an upload declares no scope, so untouched stays unknown); the
// action log names what each upload did.
func TestFindingImport_ReceiptPartialUploadNeverCloses_DB(t *testing.T) {
	ih := newImportHarness(t, ingest.SourceResolveDryRun)
	ctx := context.Background()
	tenant := shared.MustIDFromString(ih.tenantID)
	repo := postgres.NewIngestReceiptRepository(&postgres.DB{DB: ih.db})

	rec, first := ih.upload(t, ih.tenantID, "", "full.nessus", []byte(receiptNessusFull), true)
	if rec.Code != http.StatusAccepted || first.ReceiptID == "" {
		t.Fatalf("first upload %d: %s", rec.Code, rec.Body.String())
	}
	r1, err := repo.Get(ctx, tenant, shared.MustIDFromString(first.ReceiptID))
	if err != nil {
		t.Fatal(err)
	}
	if r1.Counts.Created != 2 || r1.Counts.StillDetected != 0 || r1.Counts.Closed != 0 || r1.Counts.Untouched != nil {
		t.Fatalf("first receipt counts = %+v", r1.Counts)
	}

	rec, second := ih.upload(t, ih.tenantID, "", "subset.nessus", []byte(receiptNessusSubset), true)
	if rec.Code != http.StatusAccepted || second.ReceiptID == "" || second.ReceiptID == first.ReceiptID {
		t.Fatalf("second upload %d: %s", rec.Code, rec.Body.String())
	}
	r2, err := repo.Get(ctx, tenant, shared.MustIDFromString(second.ReceiptID))
	if err != nil {
		t.Fatal(err)
	}
	if c := r2.Counts; c.Created != 0 || c.StillDetected != 1 || c.Closed != 0 || c.Reopened != 0 || c.Untouched != nil ||
		r2.Coverage != "partial" {
		t.Fatalf("partial re-upload counts = %+v coverage %s", c, r2.Coverage)
	}
	if n := ih.count(t, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND status = 'resolved'`, ih.tenantID); n != 0 {
		t.Fatalf("a partial upload closed %d findings", n)
	}
	if n := ih.count(t, `SELECT count(*) FROM finding_ingest_actions WHERE tenant_id = $1 AND receipt_id = $2 AND action = 'still_detected'`,
		ih.tenantID, second.ReceiptID); n != 1 {
		t.Fatalf("%d still-detected rows on the re-upload, want 1", n)
	}
	if n := ih.count(t, `SELECT count(*) FROM dash_ingest_day WHERE tenant_id = $1 AND source_kind = 'import' AND created = 2 AND still_detected = 1 AND closed = 0`,
		ih.tenantID); n != 1 {
		t.Fatalf("daily ingest fact missing or wrong (%d rows)", n)
	}
}
