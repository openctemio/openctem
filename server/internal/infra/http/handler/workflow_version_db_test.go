package handler

// Versions and modes against real Postgres (RFC-125 §5):
//   - a new automation is in simulate: its runs execute the draft and change
//     nothing;
//   - publishing makes version 1 live; a run pins its version, so editing
//     and republishing never changes a run already created;
//   - an unpublished draft edit never changes what a live automation runs
//     or what starts it;
//   - rollback publishes an older definition as a new version;
//   - live is reached only by publishing; simulate is one call back;
//   - versions of another tenant or automation answer 404.

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestWorkflowVersions_DB(t *testing.T) {
	f := newWFDB(t)
	nodes, edges := tagFlow("v1")
	wf := f.create(nodes, edges)
	wfParam := map[string]string{"id": wf}
	clearTags := func() { f.exec(`UPDATE findings SET tags = '{}' WHERE tenant_id = $1`, f.tenantA) }

	detail := func() WorkflowResponse {
		t.Helper()
		s, b := f.call(f.h.GetWorkflow, f.as(f.admin, http.MethodGet, "", wfParam))
		if s != http.StatusOK {
			t.Fatalf("get = %d %s", s, b)
		}
		var resp WorkflowResponse
		_ = json.Unmarshal([]byte(b), &resp)
		return resp
	}

	t.Run("a new automation simulates and changes nothing", func(t *testing.T) {
		d := detail()
		if d.Mode != "simulate" || d.PublishedVersion != nil || !d.DraftChanged || d.RiskClass != "low" {
			t.Fatalf("new automation = mode %s published %v changed %v risk %s", d.Mode, d.PublishedVersion, d.DraftChanged, d.RiskClass)
		}
		run := f.eventRun(wf, f.fIn)
		if run.Mode != automationdom.ModeSimulate || run.VersionID != nil {
			t.Fatalf("run = mode %s version %v, want a simulate run of the draft", run.Mode, run.VersionID)
		}
		if st := f.execute(run.ID); st != "completed" {
			t.Fatalf("simulate run = %s", st)
		}
		if len(f.tagsOf(f.fIn)) != 0 {
			t.Fatal("a simulate run changed the finding")
		}
	})

	var v1 string
	t.Run("publish makes version 1 live", func(t *testing.T) {
		if s, b := f.call(f.h.Publish, f.as(f.admin, http.MethodPost, `{}`, wfParam)); s != http.StatusOK {
			t.Fatalf("publish = %d %s", s, b)
		}
		d := detail()
		if d.Mode != "live" || d.PublishedVersion == nil || d.PublishedVersion.Version != 1 || d.DraftChanged {
			t.Fatalf("after publish = mode %s published %+v changed %v", d.Mode, d.PublishedVersion, d.DraftChanged)
		}
		v1 = d.PublishedVersion.ID
		clearTags()
		run := f.eventRun(wf, f.fIn)
		if run.Mode != automationdom.ModeLive || run.VersionID == nil || run.VersionID.String() != v1 {
			t.Fatalf("run = mode %s version %v, want live on v1", run.Mode, run.VersionID)
		}
		if st := f.execute(run.ID); st != "completed" || !slices.Contains(f.tagsOf(f.fIn), "v1") {
			t.Fatalf("live run = %s, tags %v", st, f.tagsOf(f.fIn))
		}
	})

	t.Run("a run pins its version; draft edits do not reach live runs", func(t *testing.T) {
		clearTags()
		pinned := f.eventRun(wf, f.fIn) // created on v1, not yet executed

		n2, e2 := tagFlow("v2")
		if s, b := f.call(f.h.UpdateWorkflowGraph, f.as(f.admin, http.MethodPut, `{"nodes":`+n2+`,"edges":`+e2+`}`, wfParam)); s != http.StatusOK {
			t.Fatalf("edit draft = %d %s", s, b)
		}
		if !detail().DraftChanged {
			t.Fatal("draft_changed is false after an edit")
		}
		// Unpublished: a new run still runs v1.
		if st := f.execute(f.eventRun(wf, f.fIn).ID); st != "completed" || !slices.Contains(f.tagsOf(f.fIn), "v1") || slices.Contains(f.tagsOf(f.fIn), "v2") {
			t.Fatalf("run after an unpublished edit = %s, tags %v, want v1 only", st, f.tagsOf(f.fIn))
		}
		// Publish v2: the run created on v1 still executes v1.
		if s, b := f.call(f.h.Publish, f.as(f.admin, http.MethodPost, `{}`, wfParam)); s != http.StatusOK {
			t.Fatalf("publish v2 = %d %s", s, b)
		}
		clearTags()
		if st := f.execute(pinned.ID); st != "completed" || !slices.Equal(f.tagsOf(f.fIn), []string{"v1"}) {
			t.Fatalf("pinned run = %s, tags %v, want v1", st, f.tagsOf(f.fIn))
		}
		clearTags()
		if st := f.execute(f.eventRun(wf, f.fIn).ID); st != "completed" || !slices.Equal(f.tagsOf(f.fIn), []string{"v2"}) {
			t.Fatalf("run after publishing v2 = %s, tags %v", st, f.tagsOf(f.fIn))
		}
	})

	t.Run("an unpublished trigger change does not change what starts a live automation", func(t *testing.T) {
		repo := postgres.NewAutomationRepository(&postgres.DB{DB: f.raw})
		n3 := `[{"node_key":"t","node_type":"trigger","name":"t","config":{"trigger_type":"scan_completed"}},
			{"node_key":"a","node_type":"action","name":"a","config":{"action_type":"add_tags","action_config":{"tags":["v3"]}}}]`
		_, e3 := tagFlow("")
		if s, b := f.call(f.h.UpdateWorkflowGraph, f.as(f.admin, http.MethodPut, `{"nodes":`+n3+`,"edges":`+e3+`}`, wfParam)); s != http.StatusOK {
			t.Fatalf("edit draft = %d %s", s, b)
		}
		matched := func(tt automationdom.TriggerType) bool {
			list, err := repo.ListActiveWithTriggerType(f.ctx, shared.MustIDFromString(f.tenantA), tt)
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range list {
				if w.ID.String() == wf {
					return true
				}
			}
			return false
		}
		if !matched(automationdom.TriggerTypeFindingCreated) || matched(automationdom.TriggerTypeScanCompleted) {
			t.Fatal("a live automation is matched on its unpublished draft trigger")
		}
	})

	t.Run("rollback publishes the old definition as a new version", func(t *testing.T) {
		if s, b := f.call(f.h.Rollback, f.as(f.admin, http.MethodPost, `{}`, map[string]string{"id": wf, "version_id": v1})); s != http.StatusOK {
			t.Fatalf("rollback = %d %s", s, b)
		}
		d := detail()
		if d.PublishedVersion == nil || d.PublishedVersion.Version != 3 {
			t.Fatalf("after rollback published = %+v, want version 3", d.PublishedVersion)
		}
		clearTags()
		if st := f.execute(f.eventRun(wf, f.fIn).ID); st != "completed" || !slices.Equal(f.tagsOf(f.fIn), []string{"v1"}) {
			t.Fatalf("run after rollback = %s, tags %v, want v1", st, f.tagsOf(f.fIn))
		}
		s, b := f.call(f.h.ListVersions, f.as(f.admin, http.MethodGet, "", wfParam))
		var list struct {
			Items []WorkflowVersionResponse `json:"items"`
		}
		_ = json.Unmarshal([]byte(b), &list)
		if s != http.StatusOK || len(list.Items) != 3 || list.Items[0].Status != "published" || list.Items[1].Status != "superseded" || list.Items[2].Status != "superseded" {
			t.Fatalf("versions = %d %+v", s, list.Items)
		}
	})

	t.Run("live only by publishing, simulate in one call", func(t *testing.T) {
		if s, _ := f.call(f.h.SetMode, f.as(f.admin, http.MethodPut, `{"mode":"live"}`, wfParam)); s != http.StatusBadRequest {
			t.Fatalf("mode live = %d, want 400", s)
		}
		if s, b := f.call(f.h.SetMode, f.as(f.admin, http.MethodPut, `{"mode":"simulate"}`, wfParam)); s != http.StatusOK {
			t.Fatalf("mode simulate = %d %s", s, b)
		}
		d := detail()
		if d.Mode != "simulate" || d.PublishedVersion == nil {
			t.Fatalf("after simulate = mode %s published %v (the published version stays)", d.Mode, d.PublishedVersion)
		}
		clearTags()
		if st := f.execute(f.eventRun(wf, f.fIn).ID); st != "completed" || len(f.tagsOf(f.fIn)) != 0 {
			t.Fatalf("simulate run after switching back = %s, tags %v", st, f.tagsOf(f.fIn))
		}
	})

	t.Run("versions of another tenant or automation are not found", func(t *testing.T) {
		if s, _ := f.call(f.h.GetVersion, f.as(f.admin, http.MethodGet, "", map[string]string{"id": wf, "version_id": v1})); s != http.StatusOK {
			t.Fatalf("own version = %d", s)
		}
		other := f.create(tagFlow("x"))
		if s, _ := f.call(f.h.GetVersion, f.as(f.admin, http.MethodGet, "", map[string]string{"id": other, "version_id": v1})); s != http.StatusNotFound {
			t.Errorf("version through another automation = %d, want 404", s)
		}
		if s, _ := f.call(f.h.Rollback, f.as(f.admin, http.MethodPost, `{}`, map[string]string{"id": other, "version_id": v1})); s != http.StatusNotFound {
			t.Errorf("rollback to another automation's version = %d, want 404", s)
		}
		f.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'admin')`, f.admin, f.tenantB)
		for _, call := range []http.HandlerFunc{f.h.GetVersion, f.h.ListVersions} {
			if s, _ := f.call(call, f.as(f.admin, http.MethodGet, "", map[string]string{"id": wf, "version_id": v1}, f.tenantB)); s != http.StatusNotFound {
				t.Errorf("cross-tenant read = %d, want 404", s)
			}
		}
		if s, _ := f.call(f.h.Publish, f.as(f.admin, http.MethodPost, `{}`, wfParam, f.tenantB)); s != http.StatusNotFound {
			t.Errorf("cross-tenant publish = %d, want 404", s)
		}
	})
}
