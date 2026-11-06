package handler

// Preview never shows a finding the caller may not read:
//   - a draft step that names a fixed finding outside the caller's scope
//     (action_config.finding_id) is refused like an unknown one, instead of
//     returning that finding's title and severity in the would-send payload;
//   - the sampled subjects follow the pentest member-visibility rule.

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestWorkflowPreview_HiddenFindings_DB(t *testing.T) {
	f := newWFDB(t)
	wf := f.create(tagFlow("pv"))
	wfParam := map[string]string{"id": wf}
	f.exec(`UPDATE findings SET title = 'secret-title-out' WHERE id = $1`, f.fOut)

	t.Run("a step naming an out-of-scope finding is refused", func(t *testing.T) {
		draft := `{"limit":5,"nodes":[
			{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"finding_created"}},
			{"node_key":"k","node_type":"action","name":"k","config":{"action_type":"create_ticket","action_config":{"finding_id":"` + f.fOut + `","project_key":"SEC"}}}],
			"edges":[{"source_node_key":"t","target_node_key":"k"}]}`
		s, b := f.call(f.h.Preview, f.as(f.operator, http.MethodPost, draft, wfParam))
		if s != http.StatusNotFound || strings.Contains(b, "secret-title-out") {
			t.Fatalf("preview naming an out-of-scope finding = %d %s, want 404 without its data", s, b)
		}
	})

	t.Run("samples leave out pentest findings of other campaigns", func(t *testing.T) {
		pentest := shared.NewID().String()
		f.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, severity, message, fingerprint)
		      VALUES ($1, $2, $3, 'pentest', 'wfd', 'high', 'wfd', $4)`, pentest, f.tenantA, f.assetIn, "wfd-"+pentest)
		s, b := f.call(f.h.Preview, f.as(f.editor, http.MethodPost, `{"limit":100}`, wfParam))
		if s != http.StatusOK {
			t.Fatalf("editor preview = %d %s", s, b)
		}
		var resp WorkflowPreviewResponse
		_ = json.Unmarshal([]byte(b), &resp)
		if slices.Contains(resp.SampleIDs, pentest) || !slices.Contains(resp.SampleIDs, f.fIn) {
			t.Fatalf("editor samples %v: the pentest finding of a campaign they are not in must not appear", resp.SampleIDs)
		}
		s, b = f.call(f.h.Preview, f.as(f.admin, http.MethodPost, `{"limit":100}`, wfParam))
		_ = json.Unmarshal([]byte(b), &resp)
		if s != http.StatusOK || !slices.Contains(resp.SampleIDs, pentest) {
			t.Fatalf("admin preview = %d samples %v, want the pentest finding", s, resp.SampleIDs)
		}
	})
}
