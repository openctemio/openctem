package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Sensor-supplied finding text had no per-field cap (RFC-040 gap S4b): a
// title over the 500-character column failed that finding, and a megabyte
// description was stored and rendered as sent. Every ingest path now cuts
// oversized text with a marker and stores the finding (RFC-040 §5.4).

func hugeText(prefix string, n int) string {
	return prefix + strings.Repeat("é", n) // multi-byte: cuts must be rune-safe
}

func manyStrings(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s-%d", prefix, i)
	}
	return out
}

type storedFindingText struct {
	titleLen, descLen, messageLen, refs int
	title, desc                         string
}

func (h *v2Harness) findingText(ruleID string) storedFindingText {
	h.t.Helper()
	var f storedFindingText
	err := h.db.QueryRow(`SELECT char_length(title), COALESCE(char_length(description), 0), char_length(message),
		COALESCE(jsonb_array_length(remediation->'references'), 0),
		title, COALESCE(description, '')
		FROM findings WHERE tenant_id = $1 AND rule_id = $2`, h.tenantID, ruleID).
		Scan(&f.titleLen, &f.descLen, &f.messageLen, &f.refs, &f.title, &f.desc)
	if err != nil {
		h.t.Fatalf("finding %s not stored: %v", ruleID, err)
	}
	return f
}

// requireCapped checks the stored finding; tag-list caps are covered by the
// unit tests (text_caps_test.go).
func requireCapped(t *testing.T, path string, f storedFindingText, wantRefs bool) {
	t.Helper()
	if f.titleLen > ingest.MaxFindingTitleLen || !strings.HasSuffix(f.title, ingest.TruncationMarker) {
		t.Fatalf("%s: title %d chars, want <= %d ending with the marker", path, f.titleLen, ingest.MaxFindingTitleLen)
	}
	if f.descLen > ingest.MaxFindingDescriptionLen || !strings.HasSuffix(f.desc, ingest.TruncationMarker) {
		t.Fatalf("%s: description %d chars, want <= %d ending with the marker", path, f.descLen, ingest.MaxFindingDescriptionLen)
	}
	if f.messageLen > ingest.MaxFindingDescriptionLen {
		t.Fatalf("%s: message %d chars", path, f.messageLen)
	}
	if wantRefs && (f.refs == 0 || f.refs > ingest.MaxFindingReferences) {
		t.Fatalf("%s: %d references stored, want 1..%d", path, f.refs, ingest.MaxFindingReferences)
	}
}

func TestIngest_OversizedFindingTextIsCappedOnEveryPath_DB(t *testing.T) {
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

	// Direct ingest (the async worker and server-side uploads run this).
	title, desc := hugeText("v1 title ", 100_000), hugeText("v1 description ", 1_000_000)
	report := &ctis.Report{
		Version:  "1.0",
		Metadata: ctis.ReportMetadata{ID: "caps-v1", SourceType: "scanner"},
		Tool:     &ctis.Tool{Name: "semgrep"},
		Assets:   []ctis.Asset{{ID: "repo", Type: ctis.AssetTypeRepository, Value: "github.com/acme/caps-v1"}},
		Findings: []ctis.Finding{{
			Type: ctis.FindingTypeVulnerability, Severity: ctis.SeverityHigh, RuleID: "caps-v1", AssetRef: "repo",
			Title: title, Description: desc, Message: desc,
			Tags:        manyStrings("tag", 500),
			Remediation: &ctis.Remediation{Recommendation: desc, References: manyStrings("https://example.com/ref", 5000)},
			Location:    &ctis.FindingLocation{Path: "src/a.go", StartLine: 3, Snippet: desc},
		}},
	}
	out, err := h.ingest.Ingest(ctx, agt, ingest.Input{Report: report})
	if err != nil {
		t.Fatalf("v1: oversized text failed the report: %v", err)
	}
	if out.FindingsCreated != 1 || len(out.FailedFindings) != 0 {
		t.Fatalf("v1: %d created, %d failed, want the finding stored", out.FindingsCreated, len(out.FailedFindings))
	}
	requireCapped(t, "v1", h.findingText("caps-v1"), true)

	// Protocol v2 (PUT /api/v2/sensor/results/{id}, then the worker).
	seg, _ := json.Marshal(map[string]any{
		"version":  "1.0",
		"metadata": map[string]any{"timestamp": "2026-10-01T12:00:00Z"},
		"tool":     map[string]any{"name": "semgrep"},
		"assets":   []any{map[string]any{"id": "repo", "type": "repository", "value": "github.com/acme/caps-v2"}},
		"findings": []any{map[string]any{
			"type": "vulnerability", "severity": "high", "rule_id": "caps-v2", "asset_ref": "repo",
			"title": hugeText("v2 title ", 20_000), "description": hugeText("v2 description ", 200_000),
			"tags":     manyStrings("tag", 500),
			"location": map[string]any{"path": "src/b.go", "start_line": 3},
		}},
	})
	id := newReportID()
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+id, seg)
	h.expect(resp, raw, 202, "")
	h.work(id)
	requireCapped(t, "v2", h.findingText("caps-v2"), false)
}
