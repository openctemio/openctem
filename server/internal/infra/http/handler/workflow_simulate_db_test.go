package handler

// Simulate runs and the trace against real Postgres (RFC-125 §5, D8):
//   - a simulate run changes no finding (row and updated_at untouched) and
//     records what it would send as a delivery in mode simulate;
//   - a run about a finding outside the caller's scope is not listed and
//     answers 404; the trace counts only runs the caller may see;
//   - another tenant's run answers 404.

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestWorkflowSimulate_DB(t *testing.T) {
	f := newWFDB(t)
	nodes := `[{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"finding_created"}},
		{"node_key":"a","node_type":"action","name":"a","config":{"action_type":"add_tags","action_config":{"tags":["sim"]}}},
		{"node_key":"n","node_type":"notification","name":"n","config":{"notification_type":"email","notification_config":{"title":"New finding","body":"details"}}}]`
	edges := `[{"source_node_key":"t","target_node_key":"a"},{"source_node_key":"t","target_node_key":"n"}]`
	wf := f.create(nodes, edges)

	updatedAt := func(id string) time.Time {
		var at time.Time
		if err := f.raw.QueryRowContext(f.ctx, `SELECT updated_at FROM findings WHERE id = $1`, id).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	before := updatedAt(f.fIn)
	runIn := f.eventRun(wf, f.fIn)
	if st := f.execute(runIn.ID); st != "completed" {
		t.Fatalf("simulate run = %s", st)
	}
	runOut := f.eventRun(wf, f.fOut)
	f.execute(runOut.ID)

	t.Run("a simulate run changes nothing and records what it would send", func(t *testing.T) {
		if len(f.tagsOf(f.fIn)) != 0 || !updatedAt(f.fIn).Equal(before) {
			t.Fatalf("simulate run changed the finding: tags %v", f.tagsOf(f.fIn))
		}
		s, b := f.call(f.h.GetRun, f.as(f.admin, http.MethodGet, "", map[string]string{"id": runIn.ID.String()}))
		if s != http.StatusOK {
			t.Fatalf("get run = %d %s", s, b)
		}
		var run WorkflowRunResponse
		_ = json.Unmarshal([]byte(b), &run)
		if run.Mode != "simulate" || run.RetainedUntil == nil || len(run.Deliveries) != 1 {
			t.Fatalf("run = mode %s retained %v deliveries %d", run.Mode, run.RetainedUntil, len(run.Deliveries))
		}
		d := run.Deliveries[0]
		if d.Mode != "simulate" || d.Status != "simulated" || d.Channel != "email" || d.Payload["title"] != "New finding" || d.Payload["body"] != nil {
			t.Fatalf("delivery = %+v", d)
		}
		for _, nr := range run.NodeRuns {
			if nr.NodeKey == "a" && (nr.InCount != 1 || nr.OutCount != 1) {
				t.Fatalf("tag step trace = %d/%d", nr.InCount, nr.OutCount)
			}
		}
		until, _ := time.Parse(time.RFC3339, *run.RetainedUntil)
		if d := time.Until(until); d < 29*24*time.Hour || d > 31*24*time.Hour {
			t.Fatalf("retained until %s, want about 30 days", *run.RetainedUntil)
		}
	})

	t.Run("run reads and the trace follow the caller's scope", func(t *testing.T) {
		wfParam := map[string]string{"id": wf}
		if s, _ := f.call(f.h.GetRun, f.as(f.operator, http.MethodGet, "", map[string]string{"id": runOut.ID.String()})); s != http.StatusNotFound {
			t.Errorf("operator reads a run about an out-of-scope finding = %d, want 404", s)
		}
		if s, _ := f.call(f.h.GetRun, f.as(f.operator, http.MethodGet, "", map[string]string{"id": runIn.ID.String()})); s != http.StatusOK {
			t.Errorf("operator reads a run in scope = %d", s)
		}
		listed := func(user string) int {
			r := f.as(user, http.MethodGet, "", nil)
			q := r.URL.Query()
			q.Set("workflow_id", wf)
			q.Set("mode", "simulate")
			r.URL.RawQuery = q.Encode()
			s, b := f.call(f.h.ListRuns, r)
			if s != http.StatusOK {
				t.Fatalf("list = %d %s", s, b)
			}
			var resp struct {
				Total int `json:"total"`
			}
			_ = json.Unmarshal([]byte(b), &resp)
			return resp.Total
		}
		if n := listed(f.operator); n != 1 {
			t.Errorf("operator lists %d runs, want 1 (the out-of-scope one is hidden)", n)
		}
		if n := listed(f.admin); n != 2 {
			t.Errorf("admin lists %d runs, want 2", n)
		}
		trace := func(user string) WorkflowTraceResponse {
			s, b := f.call(f.h.GetTrace, f.as(user, http.MethodGet, "", wfParam))
			if s != http.StatusOK {
				t.Fatalf("trace = %d %s", s, b)
			}
			var tr WorkflowTraceResponse
			_ = json.Unmarshal([]byte(b), &tr)
			return tr
		}
		op, ad := trace(f.operator), trace(f.admin)
		if op.Runs != 1 || ad.Runs != 2 {
			t.Fatalf("trace runs operator=%d admin=%d, want 1 and 2", op.Runs, ad.Runs)
		}
		for _, st := range op.Steps {
			if st.NodeKey == "a" && st.In != 1 {
				t.Errorf("operator's tag step in=%d, want 1 (counts only runs in scope)", st.In)
			}
		}
		if op.DeliveriesByChannel["email"] != 1 || ad.DeliveriesByChannel["email"] != 2 {
			t.Errorf("deliveries operator=%v admin=%v", op.DeliveriesByChannel, ad.DeliveriesByChannel)
		}
	})

	t.Run("another tenant's run is not found", func(t *testing.T) {
		f.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'admin')`, f.admin, f.tenantB)
		if s, _ := f.call(f.h.GetRun, f.as(f.admin, http.MethodGet, "", map[string]string{"id": runIn.ID.String()}, f.tenantB)); s != http.StatusNotFound {
			t.Errorf("cross-tenant run = %d, want 404", s)
		}
		if s, _ := f.call(f.h.GetTrace, f.as(f.admin, http.MethodGet, "", map[string]string{"id": wf}, f.tenantB)); s != http.StatusNotFound {
			t.Errorf("cross-tenant trace = %d, want 404", s)
		}
	})
}
