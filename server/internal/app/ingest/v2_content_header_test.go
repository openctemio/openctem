package ingest

import (
	"encoding/json"
	"testing"

	"github.com/openctemio/ctis/v2"
)

// RFC-031: a sensor stamps the scanner content a scan used on the report's
// tool (tool.content). The v2 header keeps the tool verbatim, and the header
// is stored on the report (ingest_reports.header), so every v2 scan records
// its content version with no schema change.
func TestV2HeaderKeepsToolContent(t *testing.T) {
	r := &ctis.Report{Tool: &ctis.Tool{Name: "trivy", Version: "0.69.3", Content: []ctis.ToolContent{
		{Name: "trivy-db", Version: "2026-10-02T01:05:41Z", SHA256: hexDigest("3")}}}}
	raw, _, err := V2HeaderOf(r)
	if err != nil {
		t.Fatal(err)
	}
	var h struct {
		Tool struct {
			Content []map[string]any `json:"content"`
		} `json:"tool"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	if got := h.Tool.Content; len(got) != 1 || got[0]["sha256"] != hexDigest("3") || got[0]["version"] != "2026-10-02T01:05:41Z" {
		t.Fatalf("header lost the content: %s", raw)
	}
}
