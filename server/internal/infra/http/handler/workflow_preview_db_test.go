package handler

// Preview and validate against real Postgres (RFC-125 §6):
//   - a restricted member's preview counts and samples only findings in
//     their scope; the admin's sees both; nothing is stored or changed;
//   - limit above 100 is refused, a second preview within 10 s is 429;
//   - validate reports an unsupported type, a missing setting, a missing
//     integration, an invalid condition and a permission the caller lacks.

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
)

func TestWorkflowPreviewValidate_DB(t *testing.T) {
	f := newWFDB(t)
	nodes := `[{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"finding_created"}},
		{"node_key":"a","node_type":"action","name":"a","config":{"action_type":"add_tags","action_config":{"tags":["pv"]}}}]`
	wf := f.create(nodes, `[{"source_node_key":"t","target_node_key":"a"}]`)
	wfParam := map[string]string{"id": wf}

	preview := func(user, body string) (int, WorkflowPreviewResponse) {
		s, b := f.call(f.h.Preview, f.as(user, http.MethodPost, body, wfParam))
		var resp WorkflowPreviewResponse
		_ = json.Unmarshal([]byte(b), &resp)
		return s, resp
	}

	t.Run("preview follows the caller's scope and stores nothing", func(t *testing.T) {
		var runsBefore int
		_ = f.raw.QueryRow(`SELECT count(*) FROM automation_runs WHERE automation_id = $1`, wf).Scan(&runsBefore)
		s, op := preview(f.operator, `{"limit":100}`)
		if s != http.StatusOK {
			t.Fatalf("operator preview = %d", s)
		}
		if op.Subjects != 1 || !slices.Contains(op.SampleIDs, f.fIn) || slices.Contains(op.SampleIDs, f.fOut) || slices.Contains(op.SampleIDs, f.fB) {
			t.Fatalf("operator preview subjects %d samples %v: only the in-scope finding may be counted", op.Subjects, op.SampleIDs)
		}
		for _, st := range op.Steps {
			if st.NodeKey == "a" && (st.In != 1 || st.Out != 1) {
				t.Fatalf("operator preview tag step = %+v", st)
			}
		}
		s, ad := preview(f.admin, `{"limit":100}`)
		if s != http.StatusOK || ad.Subjects != 2 || slices.Contains(ad.SampleIDs, f.fB) {
			t.Fatalf("admin preview = %d subjects %d samples %v (tenant B's finding must never appear)", s, ad.Subjects, ad.SampleIDs)
		}
		var runsAfter int
		_ = f.raw.QueryRow(`SELECT count(*) FROM automation_runs WHERE automation_id = $1`, wf).Scan(&runsAfter)
		if runsAfter != runsBefore || len(f.tagsOf(f.fIn)) != 0 {
			t.Fatalf("preview stored runs (%d -> %d) or changed the finding (%v)", runsBefore, runsAfter, f.tagsOf(f.fIn))
		}
	})

	t.Run("limit and rate", func(t *testing.T) {
		if s, _ := preview(f.editor, `{"limit":101}`); s != http.StatusBadRequest {
			t.Errorf("limit 101 = %d, want 400", s)
		}
		if s, _ := preview(f.editor, `{"limit":5}`); s != http.StatusOK {
			t.Fatalf("first preview = %d", s)
		}
		if s, _ := preview(f.editor, `{"limit":5}`); s != http.StatusTooManyRequests {
			t.Errorf("second preview within 10 s = %d, want 429", s)
		}
	})

	t.Run("validate", func(t *testing.T) {
		draft := `{"nodes":[
			{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"finding_created"}},
			{"node_key":"c","node_type":"condition","name":"c","config":{"condition_expr":"trigger.finding.severity == high"}},
			{"node_key":"s","node_type":"action","name":"s","config":{"action_type":"update_status","action_config":{}}},
			{"node_key":"x","node_type":"action","name":"x","config":{"action_type":"http_request"}},
			{"node_key":"n","node_type":"notification","name":"n","config":{"notification_type":"slack","notification_config":{"integration_id":"` + f.fB + `"}}}],
			"edges":[{"source_node_key":"t","target_node_key":"c"},{"source_node_key":"c","target_node_key":"s","source_handle":"yes"},
			{"source_node_key":"t","target_node_key":"x"},{"source_node_key":"t","target_node_key":"n"}]}`
		s, b := f.call(f.h.Validate, f.as(f.editor, http.MethodPost, draft, wfParam))
		if s != http.StatusOK {
			t.Fatalf("validate = %d %s", s, b)
		}
		var resp WorkflowValidationResponse
		_ = json.Unmarshal([]byte(b), &resp)
		has := func(code, node string) bool {
			for _, p := range resp.Problems {
				if p.Code == code && (node == "" || p.NodeKey == node) {
					return true
				}
			}
			return false
		}
		for _, want := range [][2]string{
			{"UNSUPPORTED_TYPE", "x"}, {"CONFIG_MISSING", "s"}, {"INTEGRATION_MISSING", "n"}, {"OWNER_LACKS_PERMISSION", "s"},
		} {
			if !has(want[0], want[1]) {
				t.Errorf("validate misses %s on %s: %+v", want[0], want[1], resp.Problems)
			}
		}
		bad := `{"nodes":[{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"manual"}},
			{"node_key":"c","node_type":"condition","name":"c","config":{"condition_expr":"` + longExpr() + `"}}],
			"edges":[{"source_node_key":"t","target_node_key":"c"}]}`
		_, b = f.call(f.h.Validate, f.as(f.admin, http.MethodPost, bad, wfParam))
		_ = json.Unmarshal([]byte(b), &resp)
		if !has("CONDITION_INVALID", "c") {
			t.Errorf("validate misses an invalid condition: %s", b)
		}
	})
}

func longExpr() string {
	b := make([]byte, 600)
	for i := range b {
		b[i] = 'a'
	}
	return "trigger." + string(b) + " == x"
}
