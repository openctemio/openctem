package routes

// Group-level exceptions on remediation tasks
// (api/docs/rfcs/RFC-111-approval-policy.md §7) through the real routes and
// database: one request over the task's open findings, the group tier is the
// highest member tier, each member ends at its own cap, member requests are
// decided only with the group, the last approval applies every member,
// rejection and cancellation close the members, asset owners of any member
// are excluded, and another organization reaches nothing.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	remediationapp "github.com/openctemio/openctem/api/internal/app/remediation"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

type groupExceptionHarness struct {
	*approvalPolicyHarness
	tasks *remediationapp.TaskService
}

func newGroupExceptionHarness(t *testing.T) *groupExceptionHarness {
	gate := &approverStepUp{}
	out := &groupExceptionHarness{approvalPolicyHarness: &approvalPolicyHarness{findingApprovalHarness: &findingApprovalHarness{}, stepUp: gate}}
	changeAuditExtraHandlers = func(hs *Handlers, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		svc := finding.NewVulnerabilityService(postgres.NewVulnerabilityRepository(db), postgres.NewFindingRepository(db), log)
		svc.SetApprovalRepository(postgres.NewFindingApprovalRepository(db))
		actors := postgres.NewScopeActorRepository(db)
		svc.SetSoloApproval(actors, nil, ts)
		svc.SetApprovalNotifier(actors, nil, nil, "")
		svc.SetStepUpGate(gate)
		vh := handler.NewVulnerabilityHandler(svc, validator.New(), log)
		vh.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log))
		vh.SetFindingApprovalSettings(ts)
		hs.Vulnerability = vh
		tasks := remediationapp.NewTaskService(postgres.NewRemediationTaskRepository(db), log)
		tasks.SetExceptionRequester(svc)
		tasks.SetAuditLogger(auditapp.NewAuditService(postgres.NewAuditRepository(db), log))
		hs.RemediationTask = handler.NewRemediationTaskHandler(tasks, log)
		out.svc, out.tasks = svc, tasks
	}
	t.Cleanup(func() { changeAuditExtraHandlers = nil })
	out.authzPolicyHarness = newChangeAuditHarness(t)
	return out
}

func (h *groupExceptionHarness) org() string {
	id := h.tenantWithFindings()
	h.t.Cleanup(func() {
		for _, q := range []string{
			`DELETE FROM approval_batches WHERE tenant_id = $1`,
			`DELETE FROM remediation_task_members WHERE tenant_id = $1`,
			`DELETE FROM remediation_task_events WHERE tenant_id = $1`,
			`DELETE FROM remediation_tasks WHERE tenant_id = $1`,
			`DELETE FROM remediation_actions WHERE tenant_id = $1`,
		} {
			_, _ = h.db.ExecContext(context.Background(), q, id)
		}
	})
	return id
}

// task creates a task over the findings (as the platform, unrestricted).
func (h *groupExceptionHarness) task(tenantID string, findings ...string) string {
	h.t.Helper()
	tid := shared.MustIDFromString(tenantID)
	ids := make([]shared.ID, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, shared.MustIDFromString(f))
	}
	t, err := h.tasks.CreateTask(context.Background(), remediationapp.CreateTaskInput{
		TenantID: tid, Title: "No window until December " + uuid.NewString()[:6], FindingIDs: ids,
	}, auditapp.AuditContext{})
	if err != nil {
		h.t.Fatalf("create task: %v", err)
	}
	return t.ID.String()
}

type previewOut struct {
	Evaluation struct {
		Tier     string `json:"tier"`
		Required int    `json:"approvals_required"`
	} `json:"evaluation"`
	Members []struct {
		FindingID string  `json:"finding_id"`
		Tier      string  `json:"tier"`
		End       *string `json:"end"`
		Shortened bool    `json:"shortened"`
		Skipped   string  `json:"skipped"`
	} `json:"members"`
	Included int `json:"included"`
	Skipped  int `json:"skipped"`
}

type batchOut struct {
	ID        string   `json:"id"`
	Status    string   `json:"status"`
	Tier      string   `json:"tier"`
	Required  int      `json:"approvals_required"`
	Collected int      `json:"approvals_collected"`
	Members   int      `json:"member_count"`
	Applied   *int     `json:"applied"`
	Canceled  []string `json:"canceled"`
	Shortened *int     `json:"shortened"`
}

func acceptBody(days int) string {
	end := time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour).Format(time.RFC3339)
	return `{"requested_status":"accepted","closure_reason":"risk_accepted","justification":"no maintenance window until 1 December for this fleet","expires_at":"` + end + `"}`
}

func TestGroupException_RequestApproveCaps_DB(t *testing.T) {
	h := newGroupExceptionHarness(t)
	org, other := h.org(), h.org()
	requester, a1, a2 := h.member(org, "admin"), h.member(org, "admin"), h.member(org, "admin")
	outsider := h.member(other, "owner")

	low, _ := h.findingOnAsset(org, "low")
	medium, _ := h.findingOnAsset(org, "medium")
	kev, _ := h.findingOnAsset(org, "low")
	h.exec(`UPDATE findings SET is_in_kev = true WHERE id = $1`, kev)
	pendingAlready, _ := h.findingOnAsset(org, "low")
	task := h.task(org, low, medium, kev, pendingAlready)
	h.requestAccept(requester, pendingAlready) // a pending request of its own

	var p previewOut
	_ = json.Unmarshal([]byte(h.expect(requester, http.MethodPost, "/api/v1/remediation/tasks/"+task+"/exception/preview", acceptBody(120), http.StatusOK)), &p)
	if p.Evaluation.Tier != "dual" || p.Evaluation.Required != 2 || p.Included != 3 || p.Skipped != 1 {
		t.Fatalf("preview: %+v", p)
	}
	for _, m := range p.Members {
		switch m.FindingID {
		case kev:
			// KEV: 30-day cap, the requested 120 days is cut for this member.
			if !m.Shortened || m.End == nil {
				t.Fatalf("KEV member not shortened: %+v", m)
			}
		case low:
			if m.Shortened {
				t.Fatalf("low member shortened: %+v", m)
			}
		case pendingAlready:
			if m.Skipped != "pending_request" {
				t.Fatalf("member with a pending request: %+v", m)
			}
		}
	}
	h.expect(outsider, http.MethodPost, "/api/v1/remediation/tasks/"+task+"/exception/preview", acceptBody(120), http.StatusNotFound)

	var b batchOut
	_ = json.Unmarshal([]byte(h.expect(requester, http.MethodPost, "/api/v1/remediation/tasks/"+task+"/exception", acceptBody(120), http.StatusCreated)), &b)
	if b.Status != "pending" || b.Tier != "dual" || b.Members != 3 {
		t.Fatalf("batch: %+v", b)
	}
	// One pending exception per task.
	h.expect(requester, http.MethodPost, "/api/v1/remediation/tasks/"+task+"/exception", acceptBody(120), http.StatusConflict)

	// A member request cannot be decided alone.
	var memberID string
	if err := h.db.QueryRowContext(context.Background(), `SELECT id FROM finding_status_approvals WHERE batch_id = $1 LIMIT 1`, b.ID).Scan(&memberID); err != nil {
		t.Fatal(err)
	}
	_, body := h.approve(a1, memberID, http.StatusConflict)
	if code, _ := refusalReason(t, body); code != "BATCH_MEMBER" {
		t.Fatalf("member decided alone: %s", body)
	}
	// Another organization reaches nothing.
	h.expect(outsider, http.MethodGet, "/api/v1/approvals/batches/"+b.ID, "", http.StatusNotFound)
	h.expect(outsider, http.MethodPost, "/api/v1/approvals/batches/"+b.ID+"/approve", "", http.StatusNotFound)
	// The requester never approves.
	h.expect(requester, http.MethodPost, "/api/v1/approvals/batches/"+b.ID+"/approve", "", http.StatusBadRequest)

	var first batchOut
	_ = json.Unmarshal([]byte(h.expect(a1, http.MethodPost, "/api/v1/approvals/batches/"+b.ID+"/approve", "", http.StatusOK)), &first)
	if first.Status != "pending" || first.Collected != 1 {
		t.Fatalf("first approval: %+v", first)
	}
	if findingStatusOf(h.findingApprovalHarness, low) != "confirmed" {
		t.Fatal("one approval applied a dual group")
	}
	var done batchOut
	_ = json.Unmarshal([]byte(h.expect(a2, http.MethodPost, "/api/v1/approvals/batches/"+b.ID+"/approve", "", http.StatusOK)), &done)
	if done.Status != "approved" || done.Applied == nil || *done.Applied != 3 || done.Shortened == nil || *done.Shortened != 1 {
		t.Fatalf("second approval: %+v", done)
	}
	for _, f := range []string{low, medium, kev} {
		if st := findingStatusOf(h.findingApprovalHarness, f); st != "accepted" {
			t.Fatalf("member %s: %s", f, st)
		}
	}
	// Each member ends at its own cap: KEV within 30 days, low at the requested 120.
	var kevDays, lowDays float64
	_ = h.db.QueryRowContext(context.Background(), `SELECT EXTRACT(EPOCH FROM acceptance_expires_at - now())/86400 FROM findings WHERE id = $1`, kev).Scan(&kevDays)
	_ = h.db.QueryRowContext(context.Background(), `SELECT EXTRACT(EPOCH FROM acceptance_expires_at - now())/86400 FROM findings WHERE id = $1`, low).Scan(&lowDays)
	if kevDays > 30.1 || lowDays < 119 {
		t.Fatalf("member ends: KEV %.1f days, low %.1f days", kevDays, lowDays)
	}
	if findingStatusOf(h.findingApprovalHarness, pendingAlready) != "confirmed" {
		t.Fatal("the skipped member changed")
	}
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.batch_approved'`, org); n != 1 {
		t.Fatalf("group approval audited %d times", n)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'remediation_task.exception_requested'`, org); n != 1 {
		t.Fatalf("exception request audited %d times", n)
	}
}

func TestGroupException_RejectCancelOwnersAndMoves_DB(t *testing.T) {
	h := newGroupExceptionHarness(t)
	org := h.org()
	requester, owner, a1, a2 := h.member(org, "admin"), h.member(org, "admin"), h.member(org, "admin"), h.member(org, "admin")

	// Reject closes every member.
	f1, _ := h.findingOnAsset(org, "low")
	f2, _ := h.findingOnAsset(org, "medium")
	task := h.task(org, f1, f2)
	var b batchOut
	_ = json.Unmarshal([]byte(h.expect(requester, http.MethodPost, "/api/v1/remediation/tasks/"+task+"/exception", acceptBody(30), http.StatusCreated)), &b)
	if b.Tier != "peer" {
		t.Fatalf("low/medium group tier %s", b.Tier)
	}
	h.expect(a1, http.MethodPost, "/api/v1/approvals/batches/"+b.ID+"/reject", `{"reason":""}`, http.StatusBadRequest)
	h.expect(a1, http.MethodPost, "/api/v1/approvals/batches/"+b.ID+"/reject", `{"reason":"patch is scheduled this week"}`, http.StatusOK)
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE batch_id = $1 AND status = 'rejected'`, b.ID); n != 2 {
		t.Fatalf("rejected members: %d", n)
	}
	h.expect(a2, http.MethodPost, "/api/v1/approvals/batches/"+b.ID+"/approve", "", http.StatusConflict)

	// Cancel: only the requester.
	_ = json.Unmarshal([]byte(h.expect(requester, http.MethodPost, "/api/v1/remediation/tasks/"+task+"/exception", acceptBody(30), http.StatusCreated)), &b)
	h.expect(a1, http.MethodPost, "/api/v1/approvals/batches/"+b.ID+"/cancel", "", http.StatusForbidden)
	h.expect(requester, http.MethodPost, "/api/v1/approvals/batches/"+b.ID+"/cancel", "", http.StatusOK)

	// The owner of any member's asset is excluded from the whole group; a
	// member that moved before the decision is canceled, the others apply.
	g1, asset := h.findingOnAsset(org, "low")
	g2, _ := h.findingOnAsset(org, "low")
	h.exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type) VALUES ($1, $2, 'primary')`, asset, owner.id)
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM asset_owners WHERE asset_id = $1`, asset)
	})
	task2 := h.task(org, g1, g2)
	_ = json.Unmarshal([]byte(h.expect(requester, http.MethodPost, "/api/v1/remediation/tasks/"+task2+"/exception", acceptBody(30), http.StatusCreated)), &b)
	_, body := h.do(owner, http.MethodPost, "/api/v1/approvals/batches/"+b.ID+"/approve", "")
	if code, reason := refusalReason(t, body); code != "APPROVER_NOT_ELIGIBLE" || reason != "asset_owner" {
		t.Fatalf("owner of one member's asset: %s", body)
	}
	h.exec(`UPDATE findings SET status = 'resolved', closure_reason = 'fixed' WHERE id = $1`, g2)
	var done batchOut
	_ = json.Unmarshal([]byte(h.expect(a1, http.MethodPost, "/api/v1/approvals/batches/"+b.ID+"/approve", "", http.StatusOK)), &done)
	if done.Status != "approved" || done.Applied == nil || *done.Applied != 1 || len(done.Canceled) != 1 || done.Canceled[0] != g2 {
		t.Fatalf("group with a moved member: %+v", done)
	}
	if findingStatusOf(h.findingApprovalHarness, g1) != "accepted" || findingStatusOf(h.findingApprovalHarness, g2) != "resolved" {
		t.Fatal("members after the decision")
	}

	// The list shows the organization's groups.
	var list struct {
		Data  []batchOut `json:"data"`
		Total int        `json:"total"`
	}
	_ = json.Unmarshal([]byte(h.expect(a1, http.MethodGet, "/api/v1/approvals/batches?status=approved", "", http.StatusOK)), &list)
	if list.Total != 1 || len(list.Data) != 1 {
		t.Fatalf("approved groups listed: %+v", list)
	}
}

// A finding that left the task after the exception was requested is not
// decided by it: approving the group cancels that member (with a timeline
// entry) and leaves the finding as it was.
func TestGroupException_FindingThatLeftTheTaskIsNotDecided_DB(t *testing.T) {
	h := newGroupExceptionHarness(t)
	org := h.org()
	requester, a1 := h.member(org, "admin"), h.member(org, "admin")
	stays, _ := h.findingOnAsset(org, "low")
	leaves, _ := h.findingOnAsset(org, "low")
	task := h.task(org, stays, leaves)
	var b batchOut
	_ = json.Unmarshal([]byte(h.expect(requester, http.MethodPost, "/api/v1/remediation/tasks/"+task+"/exception", acceptBody(30), http.StatusCreated)), &b)
	if b.Members != 2 || b.Required != 1 {
		t.Fatalf("batch: %+v", b)
	}
	h.exec(`UPDATE remediation_task_members SET left_at = now(), left_reason = 'moved' WHERE task_id = $1 AND finding_id = $2`, task, leaves)

	var done batchOut
	_ = json.Unmarshal([]byte(h.expect(a1, http.MethodPost, "/api/v1/approvals/batches/"+b.ID+"/approve", "", http.StatusOK)), &done)
	if done.Status != "approved" || done.Applied == nil || *done.Applied != 1 || len(done.Canceled) != 1 || done.Canceled[0] != leaves {
		t.Fatalf("approval: %+v", done)
	}
	if st := findingStatusOf(h.findingApprovalHarness, stays); st != "accepted" {
		t.Fatalf("the member on the task is %s", st)
	}
	if st := findingStatusOf(h.findingApprovalHarness, leaves); st != "confirmed" {
		t.Fatalf("the finding that left the task was decided: %s", st)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE batch_id = $1 AND finding_id = $2 AND status = 'canceled'`, b.ID, leaves); n != 1 {
		t.Fatal("its member request was not canceled")
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND activity_type = 'approval_canceled' AND changes->>'reason' = 'finding_left_task'`, leaves); n != 1 {
		t.Fatal("no timeline entry for the canceled member")
	}
}

// The batches list filters by source (the task), so a task's page reads its
// own exceptions only; a malformed source id is refused.
func TestGroupException_ListFiltersBySource_DB(t *testing.T) {
	h := newGroupExceptionHarness(t)
	org := h.org()
	requester := h.member(org, "admin")
	f1, _ := h.findingOnAsset(org, "low")
	f2, _ := h.findingOnAsset(org, "low")
	t1, t2 := h.task(org, f1), h.task(org, f2)
	for _, task := range []string{t1, t2} {
		h.expect(requester, http.MethodPost, "/api/v1/remediation/tasks/"+task+"/exception", acceptBody(30), http.StatusCreated)
	}
	var list struct {
		Data []struct {
			SourceID string `json:"source_id"`
		} `json:"data"`
		Total int `json:"total"`
	}
	_ = json.Unmarshal([]byte(h.expect(requester, http.MethodGet, "/api/v1/approvals/batches?source_id="+t1, "", http.StatusOK)), &list)
	if list.Total != 1 || len(list.Data) != 1 || list.Data[0].SourceID != t1 {
		t.Fatalf("filtered list: %+v", list)
	}
	_ = json.Unmarshal([]byte(h.expect(requester, http.MethodGet, "/api/v1/approvals/batches", "", http.StatusOK)), &list)
	if list.Total != 2 {
		t.Fatalf("unfiltered list: %+v", list)
	}
	h.expect(requester, http.MethodGet, "/api/v1/approvals/batches?source_id=not-an-id", "", http.StatusBadRequest)
}
