package ingest

import (
	"encoding/json"
	"testing"

	"github.com/openctemio/ctis"
)

// RFC-031: a sensor stamps the scanner content a scan used on the report's
// tool (tool.properties.content). The v2 header keeps the tool verbatim, and
// the header is stored on the report (ingest_reports.header), so every v2
// scan records its content version with no schema change.
func TestV2HeaderKeepsToolContent(t *testing.T) {
	content := []any{map[string]any{"name": "trivy-db", "version": "2026-10-02T01:05:41Z", "digest": "sha256:3b16", "managed": true}}
	r := &ctis.Report{Tool: &ctis.Tool{Name: "trivy", Version: "0.69.3", Properties: ctis.Properties{"content": content}}}
	raw, _, err := V2HeaderOf(r)
	if err != nil {
		t.Fatal(err)
	}
	var h struct {
		Tool struct {
			Properties struct {
				Content []map[string]any `json:"content"`
			} `json:"properties"`
		} `json:"tool"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	if got := h.Tool.Properties.Content; len(got) != 1 || got[0]["digest"] != "sha256:3b16" || got[0]["version"] != "2026-10-02T01:05:41Z" {
		t.Fatalf("header lost the content: %s", raw)
	}
}
