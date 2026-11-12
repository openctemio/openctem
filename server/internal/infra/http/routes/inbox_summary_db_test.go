package routes

// GET /api/v1/me/inbox/summary over the real routes, handlers, services and a
// migrated database: every count equals the total of the list its queue
// opens for the same caller, a scoped member never counts a row outside
// their data scope, no caller counts another organization's rows, a queue the
// caller has no permission for is absent (never 0), and a caller with no
// person gets 400.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/finding"
	inboxapp "github.com/openctemio/openctem/server/internal/app/inbox"
	appremediation "github.com/openctemio/openctem/server/internal/app/remediation"
	infrahttp "github.com/openctemio/openctem/server/internal/infra/http"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/validator"
)

// inboxHarness serves the Inbox summary beside the lists it counts:
// findings (and their quick views), approvals, closure proposals and
// remediation tasks.
type inboxHarness struct {
	*dsHarness
}

func newInboxHarness(t *testing.T) *inboxHarness {
	t.Helper()
	ds := newDSHarness(t)
	db := &postgres.DB{DB: ds.db}
	log := logger.NewNop()

	vulnSvc := finding.NewVulnerabilityService(postgres.NewVulnerabilityRepository(db), postgres.NewFindingRepository(db), log)
	vulnSvc.SetAccessControlRepository(postgres.NewAccessControlRepository(db))
	vulnSvc.SetDataScope(ds.enforcer)
	vulnSvc.SetApprovalRepository(postgres.NewFindingApprovalRepository(db))
	tasks := appremediation.NewTaskService(postgres.NewRemediationTaskRepository(db), log)
	tasks.SetDataScope(ds.enforcer)

	auth := Middleware(ds.dsAuth)
	router := infrahttp.NewChiRouter()
	registerVulnerabilityRoutes(router, handler.NewVulnerabilityHandler(vulnSvc, validator.New(), log), nil, nil, nil, auth, nil)
	registerRemediationTaskRoutes(router, handler.NewRemediationTaskHandler(tasks, log), nil, auth, nil, passthrough, log)
	registerInboxRoutes(router, handler.NewInboxHandler(inboxapp.NewService(vulnSvc, tasks, nil), log), auth, nil)

	ds.srv.Close()
	ds.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(ds.srv.Close)
	return &inboxHarness{dsHarness: ds}
}

// inboxCaller is a caller with an explicit permission set (nil: the
// harness's generous member set; an administrator holds every permission).
type inboxCaller struct {
	name  string
	user  shared.ID
	admin bool
	perms []string
}

func (h *inboxHarness) get(t *testing.T, c inboxCaller, path string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Test-User", c.user.String())
	if c.admin {
		req.Header.Set("X-Test-Admin", "1")
	}
	if c.perms != nil {
		req.Header.Set("X-Test-Perms", strings.Join(c.perms, ","))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(body)
}

// total reads a list's total (every list here answers {"total": n}).
func (h *inboxHarness) total(t *testing.T, c inboxCaller, path string) int64 {
	t.Helper()
	status, _, body := h.get(t, c, path)
	if status != http.StatusOK {
		t.Fatalf("%s GET %s = %d: %.300s", c.name, path, status, body)
	}
	var out struct {
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return out.Total
}

type inboxSummary struct {
	Queues map[string]int64 `json:"queues"`
	Total  int64            `json:"total"`
}

func (h *inboxHarness) summary(t *testing.T, c inboxCaller) inboxSummary {
	t.Helper()
	status, hdr, body := h.get(t, c, "/api/v1/me/inbox/summary")
	if status != http.StatusOK {
		t.Fatalf("%s GET /me/inbox/summary = %d: %.300s", c.name, status, body)
	}
	if cc := hdr.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("%s Cache-Control = %q, want no-store", c.name, cc)
	}
	var out inboxSummary
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// quickViewParams is the params of each quick view for the caller.
func (h *inboxHarness) quickViewParams(t *testing.T, c inboxCaller) map[string]string {
	t.Helper()
	status, _, body := h.get(t, c, "/api/v1/findings/quick-views")
	if status != http.StatusOK {
		t.Fatalf("%s GET /findings/quick-views = %d: %.300s", c.name, status, body)
	}
	var qv qvResponse
	if err := json.Unmarshal([]byte(body), &qv); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, v := range qv.Views {
		out[v.Key] = v.Params
	}
	return out
}

// seedInbox adds, in this tenant, rows for every queue on A1 (memberA's
// scope) and B1 (out of it), and in another tenant rows that name memberA
// (assigned, requested by, task owner) that no caller here may count.
func (h *inboxHarness) seedInbox(t *testing.T) {
	t.Helper()
	tid := h.tenant.String()
	memberA := h.memberA.String()
	finding := func(tenant, asset, status, assignee string) string {
		id := shared.NewID().String()
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, assigned_to)
			VALUES ($1::uuid, $2, $3, 'sast', 'inbox-tool', 'inbox finding', 'high', $1::text, $4, NULLIF($5, '')::uuid)`,
			id, tenant, asset, status, assignee)
		return id
	}
	request := func(tenant, findingID, by string) {
		h.exec(`INSERT INTO finding_status_approvals (id, tenant_id, finding_id, requested_status, justification, status, requested_by)
			VALUES ($1, $2, $3, 'false_positive', 'inbox', 'pending', NULLIF($4, '')::uuid)`, shared.NewID().String(), tenant, findingID, by)
	}
	task := func(tenant, findingID, assignee, state string) {
		id := shared.NewID().String()
		h.exec(`INSERT INTO remediation_actions (id, tenant_id, action_key, kind, title, origin)
			VALUES ($1::uuid, $2, 'manual:'||$1::text, 'manual', 'inbox task', 'manual')`, id, tenant)
		h.exec(`INSERT INTO remediation_tasks (id, tenant_id, action_id, title, member_count, open_count, assignee_user_id, state)
			VALUES ($1, $2, $1, 'inbox task', 1, 1, $3, $4)`, id, tenant, assignee, state)
		h.exec(`INSERT INTO remediation_task_members (tenant_id, task_id, finding_id, role, join_source)
			VALUES ($1, $2, $3, 'primary', 'manual')`, tenant, id, findingID)
	}
	propose := func(tenant, findingID string) {
		h.exec(`INSERT INTO finding_closure_proposals (tenant_id, finding_id, method, evidence_at) VALUES ($1, $2, 'covered_scan', now() + interval '1 day')`,
			tenant, findingID)
	}
	a, b := h.assetA.String(), h.assetB.String()

	// Assigned to memberA: one on A1, one on B1 (the assignee sees it).
	finding(tid, a, "confirmed", memberA)
	finding(tid, b, "in_progress", memberA)
	// memberA's requests: A1 counts, B1 is out of their scope.
	request(tid, finding(tid, a, "confirmed", ""), memberA)
	request(tid, finding(tid, b, "confirmed", ""), memberA)
	// The owner's requests, for memberA to review: A1 only in their scope.
	request(tid, finding(tid, a, "confirmed", ""), h.owner.String())
	request(tid, finding(tid, b, "confirmed", ""), h.owner.String())
	// memberA's tasks: open on A1, in progress on B1 (the owner of a task
	// sees it and its findings, though B1 is outside their asset scope), done
	// on A1 (not open work).
	task(tid, finding(tid, a, "confirmed", ""), memberA, "open")
	task(tid, finding(tid, b, "confirmed", ""), memberA, "in_progress")
	task(tid, finding(tid, a, "confirmed", ""), memberA, "done")
	// Ready to close: one on A1, one on B1.
	propose(tid, finding(tid, a, "confirmed", ""))
	propose(tid, finding(tid, b, "confirmed", ""))

	// Another organization where memberA is also a member, with rows of
	// every queue naming them.
	other, otherAsset := shared.NewID().String(), shared.NewID().String()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other, "inbox-"+other)
	t.Cleanup(func() { _, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, other) })
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, memberA, other)
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'inbox-other.example', 'domain')`, otherAsset, other)
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`, memberA, other, otherAsset)
	finding(other, otherAsset, "confirmed", memberA)
	request(other, finding(other, otherAsset, "confirmed", ""), memberA)
	request(other, finding(other, otherAsset, "confirmed", ""), "")
	task(other, finding(other, otherAsset, "confirmed", ""), memberA, "open")
	propose(other, finding(other, otherAsset, "confirmed", ""))
}

var inboxTaskList = "/api/v1/remediation/tasks?assignee=me&state=open,in_progress,verifying,on_hold&per_page=1"

// Every count is its list's total for the same caller, and total is the sum
// the Inbox shows.
func TestInboxSummary_CountsEqualTheirLists(t *testing.T) {
	h := newInboxHarness(t)
	h.seedInbox(t)

	full := append(append([]string{}, dsMemberPerms...), permission.FindingsApprove.String(), permission.RemediationRead.String())
	owner := inboxCaller{"owner", h.owner, true, nil}
	memberA := inboxCaller{"memberA", h.memberA, false, full}
	for _, c := range []inboxCaller{owner, memberA} {
		sum := h.summary(t, c)
		params := h.quickViewParams(t, c)
		lists := map[string]string{
			"assigned":       "/api/v1/findings?per_page=1&" + params["my_queue"],
			"team":           "/api/v1/findings?per_page=1&" + params["my_team"],
			"due_soon":       "/api/v1/findings?per_page=1&" + params["my_due_soon"],
			"expiring":       "/api/v1/findings?per_page=1&" + params["my_accepted_expiring"],
			"review":         "/api/v1/approvals/?queue=review&per_page=1",
			"requested":      "/api/v1/approvals/?queue=requested&status=pending&per_page=1",
			"tasks":          inboxTaskList,
			"ready_to_close": "/api/v1/findings/closure/proposals?per_page=1",
		}
		if len(sum.Queues) != len(lists) {
			t.Errorf("%s queues = %v, want every one of %d", c.name, sum.Queues, len(lists))
		}
		for key, path := range lists {
			got, ok := sum.Queues[key]
			if !ok {
				t.Errorf("%s: queue %s missing", c.name, key)
				continue
			}
			if want := h.total(t, c, path); got != want {
				t.Errorf("%s %s = %d, list %s total = %d", c.name, key, got, path, want)
			}
		}
		q := sum.Queues
		if want := q["assigned"] + q["review"] + q["requested"] + q["expiring"] + q["tasks"] + q["ready_to_close"]; sum.Total != want {
			t.Errorf("%s total = %d, want %d (%v)", c.name, sum.Total, want, q)
		}
	}

	// Data scope and tenant: memberA counts only A1's requests and proposals
	// here, their two open tasks, and nothing of the other organization.
	q := h.summary(t, memberA).Queues
	for key, want := range map[string]int64{"requested": 1, "review": 1, "tasks": 2, "ready_to_close": 1} {
		if q[key] != want {
			t.Errorf("memberA %s = %d, want %d (in scope, this organization only)", key, q[key], want)
		}
	}
	// The owner sees both assets: both proposals and both of their own
	// requests.
	if q := h.summary(t, owner).Queues; q["ready_to_close"] != 2 || q["requested"] != 2 {
		t.Errorf("owner ready_to_close = %d requested = %d, want 2 and 2", q["ready_to_close"], q["requested"])
	}
}

// A queue the caller cannot use is absent, never 0, and the call still
// answers.
func TestInboxSummary_QueuesFollowPermissions(t *testing.T) {
	h := newInboxHarness(t)
	h.seedInbox(t)

	read := permission.FindingsRead.String()
	cases := []struct {
		name    string
		perms   []string
		present []string
	}{
		// The harness member: findings:read and verify, no approve, no
		// remediation read.
		{"member", dsMemberPerms, []string{"assigned", "team", "due_soon", "requested", "expiring", "ready_to_close"}},
		{"reader", []string{read}, []string{"assigned", "team", "due_soon", "requested", "expiring"}},
		{"approver", []string{read, permission.FindingsApprove.String()}, []string{"assigned", "team", "due_soon", "review", "requested", "expiring"}},
		{"tasks only", []string{permission.RemediationRead.String()}, []string{"tasks"}},
		{"approve without read", []string{permission.FindingsApprove.String(), permission.FindingsVerify.String()}, []string{}},
	}
	for _, tc := range cases {
		status, _, body := h.get(t, inboxCaller{tc.name, h.memberA, false, tc.perms}, "/api/v1/me/inbox/summary")
		if status != http.StatusOK {
			t.Fatalf("%s = %d: %.300s", tc.name, status, body)
		}
		var raw struct {
			Queues map[string]json.RawMessage `json:"queues"`
		}
		if err := json.Unmarshal([]byte(body), &raw); err != nil {
			t.Fatal(err)
		}
		if len(raw.Queues) != len(tc.present) {
			t.Errorf("%s queues = %s, want only %v", tc.name, body, tc.present)
		}
		for _, k := range tc.present {
			if _, ok := raw.Queues[k]; !ok {
				t.Errorf("%s: %s missing in %s", tc.name, k, body)
			}
		}
		// The key "review" never appears for a caller without approve.
		if !strings.Contains(strings.Join(tc.present, ","), "review") && strings.Contains(body, `"review"`) {
			t.Errorf("%s: review count leaked: %s", tc.name, body)
		}
	}
}

// My team counts only active memberships: a teammate whose membership ended
// adds nothing, and the count equals the list.
func TestInboxSummary_TeamIgnoresEndedMembership(t *testing.T) {
	h := newInboxHarness(t)
	tid := h.tenant.String()
	user := func() string {
		id := shared.NewID().String()
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'mate')`, id, id+"@inbox.test")
		h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, id, tid)
		t.Cleanup(func() { _, _ = h.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id) })
		return id
	}
	mate, gone := user(), user()
	group := shared.NewID().String()
	h.exec(`INSERT INTO groups (id, tenant_id, name, slug, is_active) VALUES ($1, $2, $3, $3, TRUE)`, group, tid, "inbox-"+group[len(group)-12:])
	h.exec(`INSERT INTO group_members (group_id, user_id, expires_at) VALUES ($1, $2, NULL), ($1, $3, NULL), ($1, $4, NOW() - INTERVAL '1 day')`,
		group, h.memberA.String(), mate, gone)
	for _, assignee := range []string{mate, gone} {
		id := shared.NewID().String()
		h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, assigned_to)
			VALUES ($1::uuid, $2, $3, 'sast', 'team-tool', 'team finding', 'medium', $1::text, 'confirmed', $4)`, id, tid, h.assetA.String(), assignee)
	}
	memberA := inboxCaller{"memberA", h.memberA, false, nil}
	team := h.summary(t, memberA).Queues["team"]
	if want := h.total(t, memberA, "/api/v1/findings?per_page=1&"+h.quickViewParams(t, memberA)["my_team"]); team != 1 || team != want {
		t.Errorf("memberA team = %d (list %d), want 1: the ended membership must not count", team, want)
	}
}

// An organization API key (no person) gets 400 and no count.
func TestInboxSummary_NeedsAPerson(t *testing.T) {
	h := newInboxHarness(t)
	status, _, body := h.get(t, inboxCaller{"api key", shared.ID{}, false, dsMemberPerms}, "/api/v1/me/inbox/summary")
	if status != http.StatusBadRequest || strings.Contains(body, "queues") {
		t.Errorf("API key = %d %s, want 400 with no counts", status, body)
	}
}
