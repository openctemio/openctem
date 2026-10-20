package routes

// Watchers of findings and remediation tasks (RFC-120) over real Postgres and
// the real routes: who may watch, who may add whom, what a watcher list shows
// to whom, and that watching never grants access.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	participationapp "github.com/openctemio/openctem/api/internal/app/participation"
	appremediation "github.com/openctemio/openctem/api/internal/app/remediation"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	participationdom "github.com/openctemio/openctem/api/pkg/domain/participation"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type watchHarness struct {
	*dsHarness
	srv   *httptest.Server
	svc   *participationapp.Service
	repo  *postgres.WorkItemSubscriptionRepository
	taskA shared.ID // holds findingA (asset A)
	taskB shared.ID // holds findingB (asset B)
}

var (
	watchReadPerms  = []string{permission.FindingsRead.String(), permission.RemediationRead.String()}
	watchAdminPerms = []string{permission.FindingsRead.String(), permission.RemediationRead.String(), permission.FindingsAssign.String(),
		permission.RemediationWrite.String(), permission.MembersRead.String()}
)

func newWatchHarness(t *testing.T) *watchHarness {
	t.Helper()
	ds := newDSHarness(t)
	db := &postgres.DB{DB: ds.db}
	log := logger.NewNop()
	vuln := finding.NewVulnerabilityService(nil, postgres.NewFindingRepository(db), log)
	vuln.SetDataScope(ds.enforcer)
	tasks := appremediation.NewTaskService(postgres.NewRemediationTaskRepository(db), log)
	tasks.SetDataScope(ds.enforcer)
	repo := postgres.NewWorkItemSubscriptionRepository(db)
	svc := participationapp.NewService(repo, postgres.NewAccessControlRepository(db), log)
	svc.SetItemAccess(participationdom.ItemFinding, vuln.ParticipationAccess())
	svc.SetItemAccess(participationdom.ItemTask, tasks.ParticipationAccess())
	svc.SetAuditLogger(auditapp.NewAuditService(postgres.NewAuditRepository(db), log))
	svc.SetAutoWatchPreference(postgres.NewNotificationRepository(db))

	router := infrahttp.NewChiRouter()
	registerParticipationRoutes(router, handler.NewParticipationHandler(svc, log), Middleware(ds.dsAuth), nil, passthrough, log)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)

	h := &watchHarness{dsHarness: ds, srv: srv, svc: svc, repo: repo}
	ct := &campaignTasksHarness{dsHarness: ds}
	h.taskA, h.taskB = ct.task("watch-task-a", ds.findingA), ct.task("watch-task-b", ds.findingB)
	return h
}

func (h *watchHarness) call(user shared.ID, admin bool, perms []string, method, path string, body any) (int, map[string]any) {
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
	r.Header.Set("X-Test-Perms", strings.Join(perms, ","))
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	out["_raw"] = string(raw)
	return resp.StatusCode, out
}

func (h *watchHarness) rows(q string, args ...any) int { return h.countRows(q, args...) }

func watcherIDs(out map[string]any) []string {
	var ids []string
	ws, _ := out["watchers"].([]any)
	for _, w := range ws {
		ids = append(ids, w.(map[string]any)["user_id"].(string))
	}
	return ids
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestFindingWatchers_DB(t *testing.T) {
	h := newWatchHarness(t)
	fa, fb := h.findingA.String(), h.findingB.String()
	base := "/api/v1/findings/" + fa

	// The list: a member with no member-list permission gets the count only.
	code, out := h.call(h.memberA, false, watchReadPerms, http.MethodGet, base+"/participants", nil)
	if code != http.StatusOK || out["watcher_count"].(float64) != 0 || out["names_visible"].(bool) {
		t.Fatalf("empty list: %d %v", code, out["_raw"])
	}
	// A finding outside the caller's scope is not found, in every route.
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/findings/" + fb + "/participants"},
		{http.MethodPut, "/api/v1/findings/" + fb + "/subscription"},
		{http.MethodPost, "/api/v1/findings/" + fb + "/watchers"},
		{http.MethodDelete, "/api/v1/findings/" + fb + "/watchers/" + h.memberA.String()},
	} {
		code, _ := h.call(h.memberA, false, watchAdminPerms, c.method, c.path, map[string]any{"state": "subscribed", "user_ids": []string{h.memberA.String()}})
		if code != http.StatusNotFound {
			t.Errorf("%s %s out of scope = %d, want 404", c.method, c.path, code)
		}
	}

	// The bell: reading the finding is enough; unsubscribe is remembered.
	code, out = h.call(h.memberA, false, watchReadPerms, http.MethodPut, base+"/subscription", map[string]any{"state": "subscribed"})
	if code != http.StatusOK || out["watcher_count"].(float64) != 1 || out["me"].(map[string]any)["state"] != "subscribed" {
		t.Fatalf("subscribe: %d %v", code, out["_raw"])
	}
	if code, _ := h.call(h.memberA, false, watchReadPerms, http.MethodPut, base+"/subscription", map[string]any{"state": "maybe"}); code != http.StatusBadRequest {
		t.Errorf("bad state = %d, want 400", code)
	}
	code, out = h.call(h.memberA, false, watchReadPerms, http.MethodPut, base+"/subscription", map[string]any{"state": "unsubscribed"})
	if code != http.StatusOK || out["watcher_count"].(float64) != 0 || out["me"].(map[string]any)["state"] != "unsubscribed" {
		t.Fatalf("unsubscribe: %d %v", code, out["_raw"])
	}
	// Taking part never overrides the stop; the person's own bell does.
	h.svc.AutoWatch(context.Background(), h.tenant, participationdom.Item{Kind: participationdom.ItemFinding, ID: h.findingA}, h.memberA, participationdom.ReasonCommented)
	if n := h.rows(`SELECT COUNT(*) FROM work_item_subscriptions WHERE tenant_id = $1 AND finding_id = $2 AND user_id = $3 AND state = 'unsubscribed'`,
		h.tenant.String(), fa, h.memberA.String()); n != 1 {
		t.Fatalf("auto watch overrode an unsubscribe (%d unsubscribed rows)", n)
	}
	// A person with no row is added by taking part (never for a scanner or system: no user id).
	h.svc.AutoWatch(context.Background(), h.tenant, participationdom.Item{Kind: participationdom.ItemFinding, ID: h.findingA}, h.memberFull, participationdom.ReasonCommented)
	h.svc.AutoWatch(context.Background(), h.tenant, participationdom.Item{Kind: participationdom.ItemFinding, ID: h.findingA}, shared.ID{}, participationdom.ReasonCommented)
	if n := h.rows(`SELECT COUNT(*) FROM work_item_subscriptions WHERE tenant_id = $1 AND finding_id = $2`, h.tenant.String(), fa); n != 2 {
		t.Fatalf("rows after auto watch = %d, want 2 (memberA unsubscribed, memberFull commented)", n)
	}

	// Adding people: needs findings:assign.
	add := func(user shared.ID, admin bool, perms []string, ids ...shared.ID) (int, map[string]any) {
		s := make([]string, len(ids))
		for i, id := range ids {
			s[i] = id.String()
		}
		return h.call(user, admin, perms, http.MethodPost, base+"/watchers", map[string]any{"user_ids": s})
	}
	if code, _ := add(h.memberA, false, watchReadPerms, h.memberA); code != http.StatusForbidden {
		t.Errorf("adding without findings:assign = %d, want 403", code)
	}
	code, out = add(h.owner, true, watchAdminPerms, h.memberA)
	if code != http.StatusOK || !contains(watcherIDs(out), h.memberA.String()) || out["names_visible"] != true {
		t.Fatalf("owner adds memberA: %d %v", code, out["_raw"])
	}
	if n := h.rows(`SELECT COUNT(*) FROM work_item_subscriptions WHERE tenant_id = $1 AND finding_id = $2 AND user_id = $3
		AND state = 'subscribed' AND reason = 'added' AND added_by = $4`, h.tenant.String(), fa, h.memberA.String(), h.owner.String()); n != 1 {
		t.Fatalf("an explicit add did not turn the stop back on")
	}
	if n := h.rows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'work_item.watcher_added' AND resource_id = $2
		AND metadata->>'target_user_id' = $3`, h.tenant.String(), fa, h.memberA.String()); n != 1 {
		t.Errorf("audit rows for the add = %d, want 1", n)
	}
	// Names go to those who may read the member list, with the reason, and no email.
	if strings.Contains(out["_raw"].(string), "@ds.test") {
		t.Errorf("the list discloses an email: %v", out["_raw"])
	}
	code, out = h.call(h.memberA, false, watchReadPerms, http.MethodGet, base+"/participants", nil)
	if code != http.StatusOK || out["names_visible"] == true || len(watcherIDs(out)) != 0 || out["watcher_count"].(float64) < 2 {
		t.Fatalf("a caller without the member list sees names: %d %v", code, out["_raw"])
	}

	// Refused with one generic answer: no scope row, another tenant's user, an
	// unknown id, a malformed id; nothing is written. All or none.
	other := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'wb', $2)`, other.String(), "wb-"+other.String())
	otherUser := shared.NewID()
	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Other Org')`, otherUser.String(), otherUser.String()+"@other.test")
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, otherUser.String(), other.String())
	t.Cleanup(func() {
		_, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, other.String())
		_, _ = h.db.Exec(`DELETE FROM users WHERE id = $1`, otherUser.String())
	})
	var first string
	for name, id := range map[string]shared.ID{"no scope": h.memberFree, "other tenant": otherUser, "unknown": shared.NewID()} {
		code, out := add(h.owner, true, watchAdminPerms, h.memberA, id) // all or none: memberA alone would be fine
		msg := fmt.Sprint(out["message"], out["error"], out["_raw"])
		if code != http.StatusBadRequest || !strings.Contains(msg, "cannot be added") {
			t.Errorf("%s: %d %s, want 400 with the generic message", name, code, msg)
		}
		if first == "" {
			first = msg
		} else if msg != first {
			t.Errorf("%s answered differently: %q vs %q", name, msg, first)
		}
	}
	if code, _ := h.call(h.owner, true, watchAdminPerms, http.MethodPost, base+"/watchers", map[string]any{"user_ids": []string{"not-an-id"}}); code != http.StatusBadRequest {
		t.Errorf("malformed id = %d, want 400", code)
	}
	if code, _ := add(h.owner, true, watchAdminPerms, make([]shared.ID, 11)...); code != http.StatusBadRequest {
		t.Errorf("11 people = %d, want 400", code)
	}
	if n := h.rows(`SELECT COUNT(*) FROM work_item_subscriptions WHERE tenant_id = $1 AND user_id IN ($2, $3, $4)`, h.tenant.String(),
		h.memberFree.String(), h.memberStrict.String(), otherUser.String()); n != 0 {
		t.Fatalf("a refused request wrote %d rows", n)
	}
	// Full-data and owner roles can read: they can be added.
	if code, _ := add(h.owner, true, watchAdminPerms, h.memberFull); code != http.StatusOK {
		t.Errorf("adding a full-data member = %d, want 200", code)
	}

	// Remove: yourself with read access; someone else needs the write permission.
	if code, _ := h.call(h.memberA, false, watchReadPerms, http.MethodDelete, base+"/watchers/"+h.memberFull.String(), nil); code != http.StatusForbidden {
		t.Errorf("removing another without findings:assign = %d, want 403", code)
	}
	if code, _ := h.call(h.owner, true, watchAdminPerms, http.MethodDelete, base+"/watchers/"+h.memberFull.String(), nil); code != http.StatusOK {
		t.Errorf("owner removes memberFull = %d, want 200", code)
	}
	if n := h.rows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'work_item.watcher_removed' AND resource_id = $2`, h.tenant.String(), fa); n != 1 {
		t.Errorf("audit rows for the removal = %d, want 1", n)
	}
	if code, _ := h.call(h.memberA, false, watchReadPerms, http.MethodDelete, base+"/watchers/"+h.memberA.String(), nil); code != http.StatusOK {
		t.Errorf("removing yourself = %d, want 200", code)
	}
	if n := h.rows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'work_item.watcher_removed' AND resource_id = $2`, h.tenant.String(), fa); n != 1 {
		t.Errorf("removing yourself was audited (%d rows)", n)
	}

	// Losing the data scope hides the watcher (fail closed) and keeps the row,
	// so restored access restores watching.
	h.call(h.owner, true, watchAdminPerms, http.MethodPost, base+"/watchers", map[string]any{"user_ids": []string{h.memberA.String()}})
	h.exec(`DELETE FROM user_accessible_assets WHERE tenant_id = $1 AND user_id = $2`, h.tenant.String(), h.memberA.String())
	_, out = h.call(h.owner, true, watchAdminPerms, http.MethodGet, base+"/participants", nil)
	if contains(watcherIDs(out), h.memberA.String()) {
		t.Errorf("a watcher who lost data scope is still listed: %v", out["_raw"])
	}
	if n := h.rows(`SELECT COUNT(*) FROM work_item_subscriptions WHERE tenant_id = $1 AND finding_id = $2 AND user_id = $3`, h.tenant.String(), fa, h.memberA.String()); n != 1 {
		t.Errorf("the row of a watcher who lost scope was deleted")
	}
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`, h.memberA.String(), h.tenant.String(), h.assetA.String())
	_, out = h.call(h.owner, true, watchAdminPerms, http.MethodGet, base+"/participants", nil)
	if !contains(watcherIDs(out), h.memberA.String()) {
		t.Errorf("restored access did not restore the watcher: %v", out["_raw"])
	}

	// The database refuses a row that points across tenants.
	if _, err := h.db.Exec(`INSERT INTO work_item_subscriptions (tenant_id, finding_id, user_id, reason) VALUES ($1, $2, $3, 'manual')`,
		other.String(), fa, otherUser.String()); err == nil {
		t.Error("a subscription of tenant B on tenant A's finding was accepted")
	}
	if _, err := h.db.Exec(`INSERT INTO work_item_subscriptions (tenant_id, user_id, reason) VALUES ($1, $2, 'manual')`, h.tenant.String(), h.memberA.String()); err == nil {
		t.Error("a subscription naming no item was accepted")
	}
}

func TestFindingWatchers_Limit_DB(t *testing.T) {
	h := newWatchHarness(t)
	fa := h.findingA.String()
	// Fill the finding to the limit with scoped members.
	for i := 0; i < participationdom.MaxWatchersPerItem; i++ {
		u := shared.NewID()
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'Cap')`, u.String(), u.String()+"@cap.test")
		h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, u.String(), h.tenant.String())
		h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`, u.String(), h.tenant.String(), h.assetA.String())
		h.exec(`INSERT INTO work_item_subscriptions (tenant_id, finding_id, user_id, reason) VALUES ($1, $2, $3, 'manual')`, h.tenant.String(), fa, u.String())
		t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM users WHERE id = $1`, u.String()) })
	}
	code, out := h.call(h.owner, true, watchAdminPerms, http.MethodPost, "/api/v1/findings/"+fa+"/watchers", map[string]any{"user_ids": []string{h.memberA.String()}})
	if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(out["_raw"]), "maximum") {
		t.Fatalf("adding past the limit = %d %v", code, out["_raw"])
	}
	// Taking part adds nobody past the limit, and the bell is refused too.
	h.svc.AutoWatch(context.Background(), h.tenant, participationdom.Item{Kind: participationdom.ItemFinding, ID: h.findingA}, h.memberA, participationdom.ReasonCommented)
	if n := h.rows(`SELECT COUNT(*) FROM work_item_subscriptions WHERE tenant_id = $1 AND finding_id = $2`, h.tenant.String(), fa); n != participationdom.MaxWatchersPerItem {
		t.Fatalf("rows past the limit: %d", n)
	}
	if code, _ := h.call(h.memberA, false, watchReadPerms, http.MethodPut, "/api/v1/findings/"+fa+"/subscription", map[string]any{"state": "subscribed"}); code != http.StatusBadRequest {
		t.Errorf("bell past the limit = %d, want 400", code)
	}
	// Stopping is always allowed.
	if code, _ := h.call(h.memberA, false, watchReadPerms, http.MethodPut, "/api/v1/findings/"+fa+"/subscription", map[string]any{"state": "unsubscribed"}); code != http.StatusOK {
		t.Errorf("unsubscribe past the limit = %d, want 200", code)
	}
}

func TestTaskWatchers_DB(t *testing.T) {
	h := newWatchHarness(t)
	ta, tb := h.taskA.String(), h.taskB.String()
	base := "/api/v1/remediation/tasks/" + ta

	// A task is read through its findings: memberA sees taskA, not taskB.
	if code, _ := h.call(h.memberA, false, watchReadPerms, http.MethodGet, base+"/participants", nil); code != http.StatusOK {
		t.Fatalf("participants of an in-scope task = %d", code)
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/remediation/tasks/" + tb + "/participants"},
		{http.MethodPut, "/api/v1/remediation/tasks/" + tb + "/subscription"},
		{http.MethodPost, "/api/v1/remediation/tasks/" + tb + "/watchers"},
	} {
		if code, _ := h.call(h.memberA, false, watchAdminPerms, c.method, c.path, map[string]any{"state": "subscribed", "user_ids": []string{h.memberA.String()}}); code != http.StatusNotFound {
			t.Errorf("%s %s out of scope = %d, want 404", c.method, c.path, code)
		}
	}
	// The bell and the owner's adds.
	code, out := h.call(h.memberA, false, watchReadPerms, http.MethodPut, base+"/subscription", map[string]any{"state": "subscribed"})
	if code != http.StatusOK || out["me"].(map[string]any)["state"] != "subscribed" {
		t.Fatalf("task bell: %d %v", code, out["_raw"])
	}
	if code, _ := h.call(h.owner, true, watchAdminPerms, http.MethodPost, base+"/watchers", map[string]any{"user_ids": []string{h.memberFull.String()}}); code != http.StatusOK {
		t.Errorf("adding a reader to a task = %d, want 200", code)
	}
	// Someone who cannot read the task (none of its findings in scope) cannot be added.
	code, out = h.call(h.owner, true, watchAdminPerms, http.MethodPost, "/api/v1/remediation/tasks/"+tb+"/watchers", map[string]any{"user_ids": []string{h.memberA.String()}})
	if code != http.StatusBadRequest || !strings.Contains(fmt.Sprint(out["_raw"]), "cannot be added") {
		t.Errorf("adding someone who cannot read the task = %d %v", code, out["_raw"])
	}
	if code, _ := h.call(h.memberA, false, watchReadPerms, http.MethodPost, base+"/watchers", map[string]any{"user_ids": []string{h.memberFull.String()}}); code != http.StatusForbidden {
		t.Errorf("adding to a task without remediation:write = %d, want 403", code)
	}
	// Removal: others need the write permission, yourself does not.
	if code, _ := h.call(h.memberA, false, watchReadPerms, http.MethodDelete, base+"/watchers/"+h.memberFull.String(), nil); code != http.StatusForbidden {
		t.Errorf("removing another watcher = %d, want 403", code)
	}
	if code, _ := h.call(h.memberA, false, watchReadPerms, http.MethodDelete, base+"/watchers/"+h.memberA.String(), nil); code != http.StatusOK {
		t.Errorf("removing yourself = %d, want 200", code)
	}
	// Deleting the task removes its rows (the composite foreign key cascades).
	h.exec(`DELETE FROM remediation_tasks WHERE tenant_id = $1 AND id = $2`, h.tenant.String(), ta)
	if n := h.rows(`SELECT COUNT(*) FROM work_item_subscriptions WHERE task_id = $1`, ta); n != 0 {
		t.Errorf("%d subscription rows left on a deleted task", n)
	}
}
