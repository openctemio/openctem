package ingest

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/openctemio/ctis/importer"

	evidencedom "github.com/openctemio/openctem/api/pkg/domain/evidence"
)

// A real nuclei 3.11.1 result (wordpress-click2shell against a scratch server
// serving the vulnerable theme.js, run with Authorization and Cookie
// headers), imported through the ctis nuclei importer: the finding carries
// its HTTP exchange and the reproduction as CTIS 1.6 evidence_items, and the
// platform reads them, matched part highlighted, masked values left alone.
func TestFindingEvidenceFromRealNucleiImport(t *testing.T) {
	f, err := os.Open("testdata/nuclei_wordpress_click2shell.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	res, err := importer.Parse(context.Background(), f, importer.Options{Format: importer.FormatNuclei})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Findings) != 1 {
		t.Fatalf("findings = %d", len(res.Report.Findings))
	}
	cf := &res.Report.Findings[0]
	if len(cf.EvidenceItems) == 0 {
		t.Fatal("the importer attached no evidence_items")
	}
	d, ok := findingEvidence("fp", cf, res.Report.Tool)
	if !ok {
		t.Fatal("no evidence read")
	}
	var ex *evidencedom.Item
	for i := range d.Items {
		if d.Items[i].Kind == evidencedom.KindHTTPExchange {
			ex = &d.Items[i]
		}
	}
	if ex == nil || ex.HTTP == nil || ex.HTTP.Request == nil || ex.HTTP.Response == nil {
		t.Fatalf("no http_exchange in %+v", d.Items)
	}
	if !strings.HasSuffix(ex.HTTP.Request.URL, "/wp-admin/js/theme.js") || ex.HTTP.Response.Status != 200 {
		t.Errorf("exchange = %s → %d", ex.HTTP.Request.URL, ex.HTTP.Response.Status)
	}
	norm, ok := evidencedom.Normalize(*ex)
	if !ok {
		t.Fatal("normalize dropped the exchange")
	}
	masked, secrets := evidencedom.Mask(norm)
	if len(secrets) != 0 {
		t.Errorf("nuclei had already masked the auth headers; nothing is revealable, got %+v", secrets)
	}
	if !strings.Contains(masked.HTTP.Response.Body, "trigger( 'click' )") {
		t.Errorf("response body lost: %q", masked.HTTP.Response.Body)
	}
}
