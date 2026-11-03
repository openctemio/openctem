package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// The receiver's report id is never the producer's metadata.id: it comes
// from Input.ReportID, so a document cannot pick the id its findings carry.
// A UUID-shaped document id is refused with no write, a 1.x document is
// refused, and another tenant's ingest of the same document touches nothing
// of tenant A.
func TestCTIS2Receiver_ReportIDAndRefusals(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	ctx := context.Background()
	a, b := r.newTenant("semgrep"), r.newTenant("semgrep")
	agent := func(tn v2Tenant) *sensor.Sensor {
		tid := tn.tenant
		return &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	}
	report := func(tn v2Tenant, metaID, assetID string) *ctis.Report {
		return &ctis.Report{Version: ctis.SchemaVersion, Tool: &ctis.Tool{Name: "semgrep"},
			Metadata: ctis.ReportMetadata{ID: metaID, GeneratedAt: time.Now().UTC(), Channel: ctis.ChannelScanner},
			Assets:   []ctis.Asset{{ID: assetID, Type: ctis.AssetTypeRepository, Value: tn.repo}},
			Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "finding", Severity: ctis.SeverityHigh,
				RuleID: "rule-1", AssetRef: assetID, Location: &ctis.FindingLocation{Path: "a.go", StartLine: 1}}}}
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := r.db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// A value planted as the document id, equal to a scan id tenant A already has.
	planted := ctis.NewReportID()
	first := ingest.Input{Report: report(a, ctis.NewReportID(), "repo"), ReportID: planted}
	if out, err := r.svc.Ingest(ctx, agent(a), first); err != nil || len(out.Errors) > 0 {
		t.Fatalf("first ingest: %v %v", err, out)
	}

	own := ctis.NewReportID()
	rep := report(a, planted, "repo")
	rep.Findings[0].RuleID = "rule-2"
	out, err := r.svc.Ingest(ctx, agent(a), ingest.Input{Report: rep, ReportID: own})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(out.Errors) > 0 {
		t.Fatalf("ingest: %v %v", err, out)
	}
	if out.ReportID != own {
		t.Fatalf("Output.ReportID = %q, want Input.ReportID %q (never metadata.id %q)", out.ReportID, own, planted)
	}
	if n := count(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND rule_id = 'rule-2' AND scan_id = $2`, a.tenant.String(), own); n != 1 {
		t.Fatalf("findings with scan_id = Input.ReportID: %d, want 1", n)
	}
	if n := count(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND rule_id = 'rule-2' AND scan_id = $2`, a.tenant.String(), planted); n != 0 {
		t.Fatalf("a finding took the document's metadata.id as its scan_id: %d", n)
	}

	// No Input.ReportID: a new random id, not the document's.
	none, err := r.svc.Ingest(ctx, agent(a), ingest.Input{Report: report(a, planted, "repo")})
	if err != nil || none.ReportID == "" || none.ReportID == planted {
		t.Fatalf("empty Input.ReportID gave %q (%v)", none.ReportID, err)
	}

	// A UUID-shaped document id is refused, nothing is written.
	before := count(`SELECT count(*) FROM assets WHERE tenant_id = $1`, a.tenant.String())
	bad := report(a, ctis.NewReportID(), "01936f4e-7b8c-7d4e-9f00-0123456789ab")
	if _, err := r.svc.Ingest(ctx, agent(a), ingest.Input{Report: bad, ReportID: ctis.NewReportID()}); err == nil {
		t.Fatal("a report whose asset id is UUID-shaped was accepted")
	}
	if after := count(`SELECT count(*) FROM assets WHERE tenant_id = $1`, a.tenant.String()); after != before {
		t.Fatalf("a refused report wrote assets: %d -> %d", before, after)
	}

	// A 1.x document is refused as a version mismatch.
	old, _ := json.Marshal(map[string]any{"version": "1.6", "metadata": map[string]any{"id": "x", "timestamp": time.Now().UTC(), "source_type": "scanner"},
		"tool": map[string]any{"name": "semgrep"}})
	if _, err := ingest.ParseReport(old); !errors.Is(err, ingest.ErrCTISVersion) {
		t.Fatalf("1.6 document: %v, want ErrCTISVersion", err)
	}

	// Another tenant ingesting the same document creates nothing in tenant A.
	aAssets := count(`SELECT count(*) FROM assets WHERE tenant_id = $1`, a.tenant.String())
	aFindings := count(`SELECT count(*) FROM findings WHERE tenant_id = $1`, a.tenant.String())
	if _, err := r.svc.Ingest(ctx, agent(b), ingest.Input{Report: report(b, planted, "repo"), ReportID: own}); err != nil {
		t.Fatalf("tenant B ingest: %v", err)
	}
	if n := count(`SELECT count(*) FROM assets WHERE tenant_id = $1`, a.tenant.String()); n != aAssets {
		t.Fatalf("tenant B's ingest changed tenant A's assets: %d -> %d", aAssets, n)
	}
	if n := count(`SELECT count(*) FROM findings WHERE tenant_id = $1`, a.tenant.String()); n != aFindings {
		t.Fatalf("tenant B's ingest changed tenant A's findings: %d -> %d", aFindings, n)
	}
	if n := count(`SELECT count(*) FROM findings WHERE tenant_id = $1 AND scan_id = $2`, b.tenant.String(), own); n != 1 {
		t.Fatalf("tenant B findings with the delivery id: %d, want 1", n)
	}
}
