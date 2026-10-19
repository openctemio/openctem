package routes

// A remediation campaign holds tasks, never findings. What a restricted
// member sees of it follows their data scope over its tasks: they see a
// campaign they created or own, or one with a task that has a finding in
// their scope (out of scope tasks are a count only); they change a campaign
// only when every task of it is in their scope, and add only tasks they may
// change. A task in another campaign moves only on request.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/exposure"
	appremediation "github.com/openctemio/openctem/api/internal/app/remediation"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type campaignTasksHarness struct {
	*dsHarness
	srv    *httptest.Server
	perms  []string
	taskA  shared.ID // holds findingA (memberA's scope)
	taskB  shared.ID // holds findingB (outside it)
	taskA2 shared.ID // another task on findingA's asset, in no campaign
}

func newCampaignTasksHarness(t *testing.T) *campaignTasksHarness {
	t.Helper()
	ds := newDSHarness(t)
	db := &postgres.DB{DB: ds.db}
	log := logger.NewNop()
	tenantRepo := postgres.NewTenantRepository(db)
	enforcer := datascope.New(postgres.NewDataScopeRepository(db),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, log)
	enforcer.SetAdminLookup(func(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
		m, err := tenantRepo.GetMembership(ctx, userID, tenantID)
		if err != nil {
			return false, err
		}
		return m.IsOwner() || m.IsAdmin(), nil
	})
	tasks := appremediation.NewTaskService(postgres.NewRemediationTaskRepository(db), log)
	tasks.SetDataScope(enforcer)
	tasks.SetAssigneeChecker(postgres.NewAccessControlRepository(db))
	svc := exposure.NewRemediationCampaignService(postgres.NewRemediationCampaignRepository(db), log)
	svc.SetDataScope(enforcer)
	svc.SetTasks(tasks.CampaignTasks())
	tasks.SetCampaignGate(svc)
	router := infrahttp.NewChiRouter()
	registerRemediationCampaignRoutes(router, handler.NewRemediationCampaignHandler(svc, log), Middleware(ds.dsAuth), nil, passthrough)
	registerRemediationTaskRoutes(router, handler.NewRemediationTaskHandler(tasks, log), nil, Middleware(ds.dsAuth), nil, passthrough)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)

	h := &campaignTasksHarness{dsHarness: ds, srv: srv,
		perms: append(append([]string{}, dsMemberPerms...), permission.RemediationRead.String(), permission.RemediationWrite.String())}
	h.taskA, h.taskB, h.taskA2 = h.task("ct-task-a", h.findingA), h.task("ct-task-b", h.findingB), h.task("ct-task-a2", h.finding(h.assetA))
	return h
}

// finding adds an open finding on the asset.
func (h *campaignTasksHarness) finding(asset shared.ID) shared.ID {
	id := shared.NewID()
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'sast', 'ct-tool', 'ct finding', 'high', $1::text, 'new')`,
		id.String(), h.tenant.String(), asset.String())
	return id
}

func (h *campaignTasksHarness) task(title string, finding shared.ID) shared.ID {
	id := shared.NewID()
	h.exec(`INSERT INTO remediation_actions (id, tenant_id, action_key, kind, title, origin)
		VALUES ($1::uuid, $2, 'manual:'||$1::text, 'manual', $3, 'manual')`, id.String(), h.tenant.String(), title)
	h.exec(`INSERT INTO remediation_tasks (id, tenant_id, action_id, title, member_count, open_count)
		VALUES ($1, $2, $1, $3, 1, 1)`, id.String(), h.tenant.String(), title)
	h.exec(`INSERT INTO remediation_task_members (tenant_id, task_id, finding_id, role, join_source)
		VALUES ($1, $2, $3, 'primary', 'manual')`, h.tenant.String(), id.String(), finding.String())
	return id
}

// campaign inserts a campaign holding the tasks.
func (h *campaignTasksHarness) campaign(name string, createdBy, assignedTo *shared.ID, tasks ...shared.ID) shared.ID {
	id := shared.NewID()
	h.exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, status, created_by, assigned_to)
		VALUES ($1, $2, $3, 'active', $4, $5)`, id.String(), h.tenant.String(), name, idOrNil(createdBy), idOrNil(assignedTo))
	for _, tk := range tasks {
		h.exec(`UPDATE remediation_tasks SET campaign_id = $1 WHERE id = $2`, id.String(), tk.String())
	}
	return id
}

func idOrNil(id *shared.ID) any {
	if id == nil {
		return nil
	}
	return id.String()
}

func (h *campaignTasksHarness) call(user shared.ID, admin bool, method, path string, body any) (int, map[string]any) {
	h.t.Helper()
	var rd io.Reader = strings.NewReader("")
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Test-User", user.String())
	if admin {
		r.Header.Set("X-Test-Admin", "1")
	}
	r.Header.Set("X-Test-Perms", strings.Join(h.perms, ","))
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (h *campaignTasksHarness) campaignOf(task shared.ID) string {
	h.t.Helper()
	var c *string
	if err := h.db.QueryRowContext(context.Background(), `SELECT campaign_id::text FROM remediation_tasks WHERE id = $1`, task.String()).Scan(&c); err != nil {
		h.t.Fatal(err)
	}
	if c == nil {
		return ""
	}
	return *c
}

func summaryOf(t *testing.T, c map[string]any) map[string]float64 {
	t.Helper()
	raw, ok := c["summary"].(map[string]any)
	if !ok {
		t.Fatalf("no summary in %v", c)
	}
	out := map[string]float64{}
	for k, v := range raw {
		if f, ok := v.(float64); ok {
			out[k] = f
		}
	}
	return out
}

func TestRemediationCampaignTasks_RestrictedMemberSeesThroughTheirTasks_DB(t *testing.T) {
	h := newCampaignTasksHarness(t)
	owner, member := h.owner, h.memberA
	taskB2 := h.task("ct-task-b2", h.finding(h.assetB))
	mixed := h.campaign("ct-mixed", &owner, nil, h.taskA, taskB2)
	other := h.campaign("ct-other", &owner, nil, h.taskB)
	ownEmpty := h.campaign("ct-own-empty", &member, nil)
	// Owned by the member: visible whatever its tasks.
	assigned := h.campaign("ct-assigned", &owner, &member)

	code, list := h.call(member, false, http.MethodGet, "/api/v1/remediation/campaigns/?per_page=100", nil)
	if code != http.StatusOK {
		t.Fatalf("list: %d %v", code, list)
	}
	seen := map[string]map[string]any{}
	for _, raw := range list["data"].([]any) {
		c := raw.(map[string]any)
		seen[c["id"].(string)] = c
	}
	if _, ok := seen[other.String()]; ok {
		t.Error("a campaign with no task in the member's scope was listed")
	}
	for _, id := range []shared.ID{mixed, ownEmpty, assigned} {
		if _, ok := seen[id.String()]; !ok {
			t.Errorf("campaign %s not listed", id)
		}
	}
	if s := summaryOf(t, seen[mixed.String()]); s["tasks"] != 1 || s["hidden_tasks"] != 1 || s["findings"] != 1 {
		t.Errorf("mixed summary = %v, want 1 visible task, 1 hidden, 1 finding", s)
	}
	if seen[mixed.String()]["can_edit"] != false {
		t.Error("the member may edit a campaign with a task outside their scope")
	}
	if seen[ownEmpty.String()]["can_edit"] != true {
		t.Error("the member may not edit the empty campaign they created")
	}
	if sc, _ := list["status_counts"].(map[string]any); sc["active"] != float64(3) {
		t.Errorf("status counts = %v, want 3 active visible campaigns", list["status_counts"])
	}
	if _, l := h.call(member, false, http.MethodGet, "/api/v1/remediation/campaigns/?search=ct-own", nil); l["status_counts"].(map[string]any)["active"] != float64(1) {
		t.Errorf("status counts with a search = %v, want 1", l["status_counts"])
	}
	// The owner field clears with null.
	h.exec(`UPDATE remediation_campaigns SET assigned_to = $1 WHERE id = $2`, owner.String(), ownEmpty.String())
	if code, body := h.call(member, false, http.MethodPatch, "/api/v1/remediation/campaigns/"+ownEmpty.String(), map[string]any{"assigned_to": nil}); code != http.StatusOK || body["assigned_to"] != nil {
		t.Errorf("clear the owner: %d %v", code, body)
	}

	// Every route on the other team's campaign answers 404.
	base := "/api/v1/remediation/campaigns/" + other.String()
	for _, req := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, base, nil},
		{http.MethodPatch, base, map[string]any{"name": "grab"}},
		{http.MethodPatch, base + "/status", map[string]any{"status": "canceled"}},
		{http.MethodPost, base + "/tasks", map[string]any{"task_ids": []string{h.taskA.String()}}},
		{http.MethodDelete, base + "/tasks/" + h.taskB.String(), nil},
		{http.MethodDelete, base, nil},
	} {
		if code, body := h.call(member, false, req.method, req.path, req.body); code != http.StatusNotFound {
			t.Errorf("%s %s: %d %v, want 404", req.method, req.path, code, body)
		}
	}
	// Seeing a campaign through one task is not changing it.
	if code, _ := h.call(member, false, http.MethodPatch, "/api/v1/remediation/campaigns/"+mixed.String(), map[string]any{"name": "grab"}); code != http.StatusForbidden {
		t.Errorf("edit mixed campaign: %d, want 403", code)
	}
	var name string
	if err := h.db.QueryRowContext(context.Background(), `SELECT name FROM remediation_campaigns WHERE id = $1`, mixed.String()).Scan(&name); err != nil || name != "ct-mixed" {
		t.Fatalf("mixed campaign name = %q %v", name, err)
	}
	// The member cannot pull another team's task into their own campaign.
	if code, _ := h.call(member, false, http.MethodPost, "/api/v1/remediation/campaigns/"+ownEmpty.String()+"/tasks",
		map[string]any{"task_ids": []string{taskB2.String()}}); code != http.StatusNotFound {
		t.Errorf("add an out-of-scope task: %d, want 404", code)
	}
	if h.campaignOf(taskB2) != mixed.String() {
		t.Fatal("an out-of-scope task moved")
	}

	// The organization sees everything with whole counts.
	code, got := h.call(owner, true, http.MethodGet, "/api/v1/remediation/campaigns/"+mixed.String(), nil)
	if s := summaryOf(t, got); code != http.StatusOK || s["tasks"] != 2 || s["hidden_tasks"] != 0 || got["can_edit"] != true {
		t.Errorf("owner view: %d %v", code, got)
	}
}

func TestRemediationCampaignTasks_MoveBetweenCampaigns_DB(t *testing.T) {
	h := newCampaignTasksHarness(t)
	member := h.memberA
	first := h.campaign("ct-first", &member, nil, h.taskA)
	second := h.campaign("ct-second", &member, nil)

	path := "/api/v1/remediation/campaigns/" + second.String() + "/tasks"
	code, body := h.call(member, false, http.MethodPost, path, map[string]any{"task_ids": []string{h.taskA.String()}})
	if code != http.StatusConflict || body["code"] != "TASKS_IN_OTHER_CAMPAIGN" {
		t.Fatalf("add a task of another campaign: %d %v", code, body)
	}
	details, _ := body["details"].(map[string]any)
	conflicts, _ := details["tasks"].([]any)
	if len(conflicts) != 1 || conflicts[0].(map[string]any)["can_move"] != true || conflicts[0].(map[string]any)["campaign_name"] != "ct-first" {
		t.Fatalf("conflicts = %v", details)
	}
	if h.campaignOf(h.taskA) != first.String() {
		t.Fatal("the task moved without move")
	}
	if code, body := h.call(member, false, http.MethodPost, path, map[string]any{"task_ids": []string{h.taskA.String()}, "move": true}); code != http.StatusOK {
		t.Fatalf("move: %d %v", code, body)
	}
	if h.campaignOf(h.taskA) != second.String() {
		t.Fatal("the task did not move")
	}
	var events int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM remediation_task_events
		WHERE task_id = $1 AND kind = 'updated' AND data->>'campaign_id' = $2`, h.taskA.String(), second.String()).Scan(&events); err != nil || events != 1 {
		t.Fatalf("task timeline entries = %d %v", events, err)
	}

	// Through the task itself: into a campaign the member cannot see is refused.
	other := h.campaign("ct-other", &h.owner, nil, h.taskB)
	code, body = h.call(member, false, http.MethodGet, "/api/v1/remediation/tasks/"+h.taskA2.String(), nil)
	if code != http.StatusOK {
		t.Fatalf("get task: %d %v", code, body)
	}
	if code, body := h.call(member, false, http.MethodPatch, "/api/v1/remediation/tasks/"+h.taskA2.String(),
		map[string]any{"version": body["version"], "campaign_id": other.String()}); code != http.StatusBadRequest {
		t.Fatalf("task into an invisible campaign: %d %v", code, body)
	}
	if h.campaignOf(h.taskA2) != "" {
		t.Fatal("the task joined a campaign the member cannot see")
	}
	// Tasks in no campaign (the add-tasks picker).
	code, list := h.call(member, false, http.MethodGet, "/api/v1/remediation/tasks/?no_campaign=true", nil)
	if code != http.StatusOK {
		t.Fatalf("no_campaign list: %d", code)
	}
	for _, raw := range list["data"].([]any) {
		if c, _ := raw.(map[string]any)["campaign_id"].(string); c != "" {
			t.Errorf("no_campaign listed a task of campaign %s", c)
		}
	}

	// Remove the task again; it stays a task.
	if code, _ := h.call(member, false, http.MethodDelete, path+"/"+h.taskA.String(), nil); code != http.StatusOK {
		t.Fatalf("remove: %d", code)
	}
	if h.campaignOf(h.taskA) != "" {
		t.Fatal("the task is still in the campaign")
	}
}

func TestRemediationCampaignTasks_CompletionNeedsDoneTasks_DB(t *testing.T) {
	h := newCampaignTasksHarness(t)
	owner := h.owner
	c := h.campaign("ct-done", &owner, nil, h.taskA)
	path := "/api/v1/remediation/campaigns/" + c.String() + "/status"
	if code, body := h.call(owner, true, http.MethodPatch, path, map[string]any{"status": "completed"}); code != http.StatusBadRequest {
		t.Fatalf("complete with a live task: %d %v", code, body)
	}
	h.exec(`UPDATE remediation_tasks SET state = 'done' WHERE id = $1`, h.taskA.String())
	if code, body := h.call(owner, true, http.MethodPatch, path, map[string]any{"status": "completed"}); code != http.StatusOK || body["status"] != "completed" {
		t.Fatalf("complete when done: %d %v", code, body)
	}
	// A completed campaign takes no tasks.
	if code, _ := h.call(owner, true, http.MethodPost, "/api/v1/remediation/campaigns/"+c.String()+"/tasks",
		map[string]any{"task_ids": []string{h.taskA2.String()}}); code != http.StatusBadRequest {
		t.Fatalf("add to a completed campaign: %d", code)
	}
	// Removed routes stay removed.
	for _, p := range []string{"/findings", "/resolve", "/refresh"} {
		method := http.MethodPost
		if p == "/findings" {
			method = http.MethodGet
		}
		if code, _ := h.call(owner, true, method, "/api/v1/remediation/campaigns/"+c.String()+p, nil); code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s answers %d", method, p, code)
		}
	}
}

func TestRemediationCampaignTasks_OtherTenantIsNotFound_DB(t *testing.T) {
	h := newCampaignTasksHarness(t)
	other := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'ct-other', $2)`, other.String(), "ct-other-"+other.String()[28:])
	t.Cleanup(func() { h.exec(`DELETE FROM tenants WHERE id = $1`, other.String()) })
	foreign := shared.NewID()
	h.exec(`INSERT INTO remediation_campaigns (id, tenant_id, name, status) VALUES ($1, $2, 'ct-foreign', 'active')`, foreign.String(), other.String())
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		if code, _ := h.call(h.owner, true, method, "/api/v1/remediation/campaigns/"+foreign.String(), nil); code != http.StatusNotFound {
			t.Errorf("%s another tenant's campaign: %d", method, code)
		}
	}
	// Another tenant's task cannot be added.
	mine := h.campaign("ct-mine", &h.owner, nil)
	if code, _ := h.call(h.owner, true, http.MethodPost, "/api/v1/remediation/campaigns/"+mine.String()+"/tasks",
		map[string]any{"task_ids": []string{shared.NewID().String()}}); code != http.StatusNotFound {
		t.Errorf("unknown task: %d", code)
	}
}
