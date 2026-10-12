package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/lib/pq"
	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Tags a report sent with a new finding were dropped: the finding INSERT
// had no tags column, so findings.tags stayed '{}' on every ingest path.
// A re-sighting merges tags (stored first, new appended, capped).

func (h *v2Harness) findingTags(ruleID string) []string {
	h.t.Helper()
	var tags []string
	if err := h.db.QueryRow(`SELECT tags FROM findings WHERE tenant_id = $1 AND rule_id = $2`,
		h.tenantID, ruleID).Scan(pq.Array(&tags)); err != nil {
		h.t.Fatalf("finding %s not stored: %v", ruleID, err)
	}
	return tags
}

func tagReport(ruleID string, tags []string) *ctis.Report {
	return &ctis.Report{
		Version:  "1.0",
		Metadata: ctis.ReportMetadata{ID: "tags-" + ruleID, SourceType: "scanner"},
		Tool:     &ctis.Tool{Name: "semgrep"},
		Assets:   []ctis.Asset{{ID: "repo", Type: ctis.AssetTypeRepository, Value: "github.com/acme/" + ruleID}},
		Findings: []ctis.Finding{{
			Type: ctis.FindingTypeVulnerability, Severity: ctis.SeverityHigh, RuleID: ruleID, AssetRef: "repo",
			Title: "tagged finding", Message: "tagged finding", Tags: tags,
			Location: &ctis.FindingLocation{Path: "src/a.go", StartLine: 3},
		}},
	}
}

func TestIngest_FindingTagsPersistAndMerge_DB(t *testing.T) {
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
	ingestV1 := func(report *ctis.Report) {
		t.Helper()
		if _, err := h.ingest.Ingest(ctx, agt, ingest.Input{Report: report}); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}

	// v1 CTIS: a new finding keeps its tags; empty and repeated ones go.
	ingestV1(tagReport("tags-v1", []string{"owasp", "sqli", "", "sqli"}))
	if got, want := h.findingTags("tags-v1"), []string{"owasp", "sqli"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("v1 new finding: tags %v, want %v", got, want)
	}

	// A user tag, then a re-sighting with different tags: merge, not replace.
	if _, err := h.db.ExecContext(ctx, `UPDATE findings SET tags = tags || '{triaged}'::text[]
		WHERE tenant_id = $1 AND rule_id = 'tags-v1'`, h.tenantID); err != nil {
		t.Fatal(err)
	}
	ingestV1(tagReport("tags-v1", []string{"sqli", "new"}))
	if got, want := h.findingTags("tags-v1"), []string{"owasp", "sqli", "triaged", "new"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("v1 re-ingest: tags %v, want %v (stored tags kept, new appended)", got, want)
	}

	// The cap: 80 tags in, MaxFindingTags stored.
	many := make([]string, 80)
	for i := range many {
		many[i] = fmt.Sprintf("t%02d", i)
	}
	ingestV1(tagReport("tags-cap", many))
	if got := h.findingTags("tags-cap"); len(got) != vulnerability.MaxFindingTags || got[0] != "t00" {
		t.Fatalf("cap: %d tags stored (first %v), want the first %d", len(got), got[:1], vulnerability.MaxFindingTags)
	}

	// Protocol v2 (PUT /api/v2/sensor/results/{id}, then the worker).
	seg, _ := json.Marshal(map[string]any{
		"version":  "1.0",
		"metadata": map[string]any{"timestamp": "2026-10-01T12:00:00Z"},
		"tool":     map[string]any{"name": "semgrep"},
		"assets":   []any{map[string]any{"id": "repo", "type": "repository", "value": "github.com/acme/tags-v2"}},
		"findings": []any{map[string]any{
			"type": "vulnerability", "severity": "high", "rule_id": "tags-v2", "asset_ref": "repo",
			"title": "v2 tagged", "tags": []string{"pci", "external"},
			"location": map[string]any{"path": "src/b.go", "start_line": 3},
		}},
	})
	id := newReportID()
	resp, raw := h.do(http.MethodPut, "/api/v2/sensor/results/"+id, seg)
	h.expect(resp, raw, 202, "")
	h.work(id)
	if got, want := h.findingTags("tags-v2"), []string{"pci", "external"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("v2 new finding: tags %v, want %v", got, want)
	}
}
