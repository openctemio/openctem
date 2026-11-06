package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/internal/app/ingest"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

var storedAddress = regexp.MustCompile(`[A-Za-z0-9._%+-]+(@|%40)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)

// PRIVACY (research/292): a finding's text keeps no e-mail address on any
// ingest path (direct, and protocol v2 through the worker), whatever tool
// reported it: the local part is masked, the domain kept.
func TestIngest_EmailAddressesNeverStored_DB(t *testing.T) {
	h := newV2Harness(t, v2HarnessOpts{})
	ctx := context.Background()
	t.Cleanup(func() {
		for _, q := range []string{`DELETE FROM findings WHERE tenant_id = $1`, `DELETE FROM assets WHERE tenant_id = $1`,
			`DELETE FROM audit_logs WHERE tenant_id = $1`} {
			_, _ = h.db.ExecContext(context.Background(), q, h.tenantID)
		}
	})
	agt, err := postgres.NewSensorRepository(&postgres.DB{DB: h.db}).GetByTenantAndID(ctx,
		shared.MustIDFromString(h.tenantID), shared.MustIDFromString(h.sensorID))
	if err != nil {
		t.Fatal(err)
	}
	report := &ctis.Report{
		Version:  ctis.SchemaVersion,
		Metadata: ctis.ReportMetadata{ID: ctis.NewReportID(), GeneratedAt: time.Now().UTC(), Channel: ctis.ChannelScanner},
		Tool:     &ctis.Tool{Name: "semgrep", Techniques: []ctis.Technique{ctis.TechniqueSAST}},
		Assets:   []ctis.Asset{{ID: "repo", Type: ctis.AssetTypeRepository, Value: "github.com/acme/email-mask-v1"}},
		Findings: []ctis.Finding{{
			Type: ctis.FindingTypeVulnerability, Severity: ctis.SeverityHigh, RuleID: "email-v1", AssetRef: "repo",
			Title: "Hard-coded address jane.doe@example.com", Description: "Owner: JOHN@example.org",
			Message: "notify ops+alerts@mail.example.net", Tags: []string{"owner-bob@example.com"},
			SourceExtra: map[string]string{"extracted_results": "jane.doe@example.com"},
			Remediation: &ctis.Remediation{Recommendation: "ask admin@example.com"},
			Location:    &ctis.FindingLocation{Path: "src/a.go", StartLine: 3, Snippet: `to := "jane.doe@example.com"`},
		}},
	}
	if _, err := h.ingest.Ingest(ctx, agt, ingest.Input{Report: report}); err != nil {
		t.Fatal(err)
	}
	seg, _ := json.Marshal(map[string]any{
		"version":  "2.0",
		"metadata": map[string]any{"id": ctis.NewReportID(), "generated_at": "2026-10-01T12:00:00Z", "channel": "scanner"},
		"tool":     map[string]any{"name": "semgrep", "techniques": []string{"sast"}},
		"assets":   []any{map[string]any{"id": "repo", "type": "repository", "value": "github.com/acme/email-mask-v2"}},
		"findings": []any{map[string]any{
			"type": "vulnerability", "severity": "high", "rule_id": "email-v2", "asset_ref": "repo",
			"title": "Address jane.doe@example.com", "description": "mailto:jane%40example.com",
			"location": map[string]any{"path": "src/b.go", "start_line": 3},
		}},
	})
	id := newReportID()
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+id, seg)
	h.expect(resp, raw, 202, "")
	h.work(id)

	for _, rule := range []string{"email-v1", "email-v2"} {
		var row string
		if err := h.db.QueryRowContext(ctx, `SELECT row_to_json(f)::text FROM findings f WHERE tenant_id = $1 AND rule_id = $2`,
			h.tenantID, rule).Scan(&row); err != nil {
			t.Fatalf("%s not stored: %v", rule, err)
		}
		if m := storedAddress.FindString(row); m != "" {
			t.Fatalf("%s: stored an e-mail address %q", rule, m)
		}
		var title string
		_ = h.db.QueryRowContext(ctx, `SELECT title FROM findings WHERE tenant_id = $1 AND rule_id = $2`, h.tenantID, rule).Scan(&title)
		if want := map[string]string{"email-v1": "Hard-coded address ***@example.com", "email-v2": "Address ***@example.com"}[rule]; title != want {
			t.Fatalf("%s: title %q, want %q", rule, title, want)
		}
	}
}
