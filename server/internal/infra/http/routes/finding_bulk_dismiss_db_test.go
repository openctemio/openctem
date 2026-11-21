package routes

// Bulk "Dismiss" of findings over the real routes, services and a migrated
// database (docs/architecture/findings-bulk-by-filter.md, "Bulk dismiss"):
// each finding is decided by the single-request policy (alone, in the group,
// or skipped), automation, AI agents and asset owners never decide alone, out
// of scope reads as not found, the size cap, the selection check, replays,
// the daily budget, step-up, the race with a raised level, undo, and the note
// rule (D4) on single requests and bulk.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/openctem/server/internal/app/activity"
	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/app/datascope"
	"github.com/openctemio/openctem/server/internal/app/finding"
	tenantapp "github.com/openctemio/openctem/server/internal/app/tenant"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type bulkDismissHarness struct {
	*findingApprovalHarness
	stepUp *approverStepUp
}

func newBulkDismissHarness(t *testing.T) *bulkDismissHarness {
	gate := &approverStepUp{}
	h := newFindingApprovalHarness(t, func(svc *finding.VulnerabilityService, vh *handler.VulnerabilityHandler, db *postgres.DB) {
		log := logger.NewNop()
		tenants := postgres.NewTenantRepository(db)
		ts := tenantapp.NewTenantService(tenants, log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		actors := postgres.NewScopeActorRepository(db)
		svc.SetSoloApproval(actors, nil, ts)
		svc.SetApprovalNotifier(actors, nil, nil, "")
		svc.SetStepUpGate(gate)
		svc.SetAIAgentChecker(postgres.NewAIAnalysisRepository(db))
		svc.SetBulkDismissStore(postgres.NewFindingBulkDismissRepository(db))
		svc.SetActivityService(activity.NewFindingActivityService(postgres.NewFindingActivityRepository(db), postgres.NewFindingRepository(db), log))
		enforcer := datascope.New(postgres.NewDataScopeRepository(db), func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, log)
		enforcer.SetAdminLookup(func(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
			m, err := tenants.GetMembership(ctx, userID, tenantID)
			if err != nil {
				return false, err
			}
			return m.IsOwner() || m.IsAdmin(), nil
		})
		svc.SetDataScope(enforcer)
		vh.SetFindingApprovalSettings(ts)
	})
	return &bulkDismissHarness{findingApprovalHarness: h, stepUp: gate}
}

// org is a tenant whose groups and bulk rows are removed with it.
func (h *bulkDismissHarness) org() string {
	id := h.tenantWithFindings()
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, q := range []string{
			`DELETE FROM approval_signoffs WHERE tenant_id = $1`,
			`DELETE FROM finding_status_approvals WHERE tenant_id = $1`,
			`DELETE FROM approval_batches WHERE tenant_id = $1`,
			`DELETE FROM finding_bulk_dismissals WHERE tenant_id = $1`,
			`DELETE FROM finding_activities WHERE tenant_id = $1`,
			`DELETE FROM findings WHERE tenant_id = $1`,
			`DELETE FROM asset_owners WHERE asset_id IN (SELECT id FROM assets WHERE tenant_id = $1)`,
			`DELETE FROM user_accessible_assets WHERE tenant_id = $1`,
			`DELETE FROM assets WHERE tenant_id = $1`,
		} {
			_, _ = h.db.ExecContext(ctx, q, id)
		}
	})
	return id
}

// findings inserts n confirmed findings of severity (no asset).
func (h *bulkDismissHarness) findings(tenantID, severity string, n int) []string {
	h.t.Helper()
	out := make([]string, n)
	for i := range out {
		out[i] = h.newFinding(tenantID, severity)
	}
	return out
}

// onAsset inserts a confirmed finding of severity on a new asset.
func (h *bulkDismissHarness) onAsset(tenantID, severity string) (findingID, assetID string) {
	h.t.Helper()
	findingID, assetID = h.scopedFinding(tenantID)
	h.exec(`UPDATE findings SET severity = $2, status = 'confirmed' WHERE id = $1`, findingID, severity)
	return findingID, assetID
}

type bdResult struct {
	finding.BulkDismissResult
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details"`
}

func (h *bulkDismissHarness) call(u policyUser, path string, body map[string]any, want int) bdResult {
	h.t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		h.t.Fatal(err)
	}
	raw := h.expect(u, http.MethodPost, "/api/v1/findings/bulk-dismissals"+path, string(b), want)
	var out bdResult
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		h.t.Fatalf("%s: %v", raw, err)
	}
	return out
}

func dismissBody(ids []string, extra map[string]any) map[string]any {
	b := map[string]any{"finding_ids": ids, "closure_reason": "detection_error", "idempotency_key": uuid.NewString()}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func idSet(ids []string) map[string]bool {
	m := map[string]bool{}
	for _, id := range ids {
		m[id] = true
	}
	return m
}

func skipReasons(r bdResult) map[string]string {
	m := map[string]string{}
	for _, s := range r.Skipped {
		m[s.ID] = s.Reason
	}
	return m
}

// Each level splits the same selection as single requests would: all sends
// everything to one group, high_and_above decides medium and low alone and
// groups critical, high and a material medium (KEV), off decides every
// finding alone. The apply moves exactly the decided findings, makes one
// group of source "selection" for the rest, and writes one activity entry
// with the bulk id and one audit row per finding decided alone, plus one
// bulk audit event.
func TestBulkDismiss_PartitionByLevel_DB(t *testing.T) {
	h := newBulkDismissHarness(t)
	org := h.org()
	admin := h.member(org, "admin")
	mk := func() (ids []string, serious map[string]bool) {
		crit, high := h.newFinding(org, "critical"), h.newFinding(org, "high")
		med, low, kev := h.newFinding(org, "medium"), h.newFinding(org, "low"), h.newFinding(org, "medium")
		h.exec(`UPDATE findings SET is_in_kev = true WHERE id = $1`, kev)
		return []string{crit, high, med, low, kev}, map[string]bool{crit: true, high: true, kev: true}
	}
	for _, c := range []struct {
		level   string
		decided func(serious bool) bool
	}{
		{`{"fp_approval":"all"}`, func(bool) bool { return false }},
		{`{"fp_approval":"high_and_above"}`, func(s bool) bool { return !s }},
		{`{"fp_approval":"off"}`, func(bool) bool { return true }},
	} {
		setFPLevel(h.findingApprovalHarness, org, c.level)
		ids, serious := mk()
		p := h.call(admin, "/preview", dismissBody(ids, map[string]any{"note": "checked by hand"}), http.StatusOK)
		wantDecided := 0
		for _, id := range ids {
			if c.decided(serious[id]) {
				wantDecided++
			}
		}
		if p.Counts.Decided != wantDecided || p.Counts.Grouped != len(ids)-wantDecided || p.Counts.Skipped != 0 {
			t.Fatalf("%s preview: %+v, want %d decided", c.level, p.Counts, wantDecided)
		}
		for _, it := range p.DecideNow {
			if !c.decided(serious[it.ID]) || it.Severity == "" {
				t.Fatalf("%s: %s listed as decided now", c.level, it.ID)
			}
		}
		if wantDecided < len(ids) && (!p.NoteRequired || p.Grouped == nil || p.Grouped.Tier == "") {
			t.Fatalf("%s: a group is planned but the preview says no note: %+v", c.level, p.BulkDismissResult)
		}
		for _, id := range ids {
			if got := findingStatusOf(h.findingApprovalHarness, id); got != "confirmed" {
				t.Fatalf("a preview changed %s to %s", id, got)
			}
		}
		if c.level != `{"fp_approval":"high_and_above"}` {
			continue
		}
		out := h.call(admin, "", dismissBody(ids, map[string]any{"note": "checked by hand"}), http.StatusOK)
		if out.BulkID == "" || len(out.Decided) != wantDecided || out.Grouped == nil || out.Grouped.Count != 3 || out.Grouped.BatchID == "" {
			t.Fatalf("apply: %+v", out.BulkDismissResult)
		}
		decided := idSet(out.Decided)
		for _, id := range ids {
			want := "confirmed"
			if decided[id] {
				want = "false_positive"
			}
			if got := findingStatusOf(h.findingApprovalHarness, id); got != want {
				t.Fatalf("%s: %s, want %s", id, got, want)
			}
		}
		if n := h.countRows(`SELECT COUNT(*) FROM approval_batches WHERE tenant_id = $1 AND id = $2 AND source_type = 'selection'
			AND source_id = $3 AND status = 'pending' AND member_count = 3`, org, out.Grouped.BatchID, out.BulkID); n != 1 {
			t.Fatal("no pending selection group with the three serious findings")
		}
		for id := range decided {
			if n := h.countRows(`SELECT COUNT(*) FROM finding_activities WHERE tenant_id = $1 AND finding_id = $2
				AND activity_type = 'approval_approved' AND changes->>'bulk_id' = $3`, org, id, out.BulkID); n != 1 {
				t.Fatalf("finding %s: %d activity entries with the bulk id, want 1", id, n)
			}
		}
		if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.single_person_decided'`, org); n != wantDecided {
			t.Fatalf("per-decision audit rows %d, want %d", n, wantDecided)
		}
		if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding.bulk_dismissed' AND resource_id = $2`, org, out.BulkID); n != 1 {
			t.Fatalf("bulk audit events %d, want 1", n)
		}
	}
}

// Nobody decides alone where a single request would not: the asset's owner,
// a member without findings:approve, an API key (a delegated credential:
// the service gets ByAutomation from the handler, TestParseBulkDismiss_*),
// and an AI agent, all under level off. Their findings go to the group.
func TestBulkDismiss_NeverAloneWhereARequestWouldNot_DB(t *testing.T) {
	h := newBulkDismissHarness(t)
	org := h.org()
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"off","accept_approval":"off"}`)
	admin := h.member(org, "admin")
	h.member(org, "owner")

	owned, asset := h.onAsset(org, "low")
	h.exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type) VALUES ($1, $2, 'primary')`, asset, admin.id)
	other := h.newFinding(org, "low")
	out := h.call(admin, "", dismissBody([]string{owned, other}, map[string]any{"note": "checked"}), http.StatusOK)
	if !idSet(out.Decided)[other] || idSet(out.Decided)[owned] || out.Grouped == nil || out.Grouped.Count != 1 {
		t.Fatalf("asset owner: %+v", out.BulkDismissResult)
	}

	writer := h.member(org, "member")
	h.customRoleMember(writer, org, permission.FindingsRead, permission.FindingsWrite, permission.FindingsBulkUpdate)
	h.mintToken(&writer, org)
	f := h.newFinding(org, "low")
	h.exec(`UPDATE findings SET asset_id = NULL WHERE id = $1`, f)
	// A member without findings:approve and without scope reads it as not found.
	out = h.call(writer, "/preview", dismissBody([]string{f}, nil), http.StatusOK)
	if out.Counts.Decided != 0 || skipReasons(out)[f] != finding.BulkSkipNotFound {
		t.Fatalf("writer without scope: %+v", out.BulkDismissResult)
	}
	wf, wa := h.onAsset(org, "low")
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`, writer.id, org, wa)
	out = h.call(writer, "/preview", dismissBody([]string{wf}, nil), http.StatusOK)
	if out.Counts.Decided != 0 || out.Counts.Grouped != 1 {
		t.Fatalf("writer without findings:approve: %+v", out.BulkDismissResult)
	}

	ctx := context.Background()
	tid, aid := shared.MustIDFromString(org), shared.MustIDFromString(admin.id)
	ids := []shared.ID{shared.MustIDFromString(h.newFinding(org, "low")), shared.MustIDFromString(h.newFinding(org, "medium"))}
	res, err := h.svc.BulkDismiss(ctx, finding.BulkDismissInput{TenantID: tid, UserID: aid, FindingIDs: ids,
		ClosureReason: "detection_error", Note: "from an automation", IdempotencyKey: uuid.NewString(), RequestHash: "h1",
		CanApprove: false, ByAutomation: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Counts.Decided != 0 || res.Counts.Grouped != 2 {
		t.Fatalf("delegated credential: %+v", res.Counts)
	}

	aiAgent := shared.NewID().String()
	h.exec(`INSERT INTO users (id, email, name, kind, service_tenant_id) VALUES ($1, $2, 'AI', 'service', $3)`,
		aiAgent, "svc-"+aiAgent+"@service-accounts.invalid", org)
	t.Cleanup(func() { _, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, aiAgent) })
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'viewer')`, aiAgent, org)
	h.exec(`DELETE FROM user_roles WHERE user_id = $1`, aiAgent)
	h.exec(`INSERT INTO ai_agents (user_id, tenant_id, preset, attest_due_at) VALUES ($1, $2, 'triage', now() + interval '90 days')`, aiAgent, org)
	t.Cleanup(func() { _, _ = h.db.ExecContext(ctx, `DELETE FROM ai_agents WHERE user_id = $1`, aiAgent) })
	ids = []shared.ID{shared.MustIDFromString(h.newFinding(org, "low"))}
	res, err = h.svc.BulkDismiss(ctx, finding.BulkDismissInput{TenantID: tid, UserID: shared.MustIDFromString(aiAgent), FindingIDs: ids,
		ClosureReason: "detection_error", Note: "the AI thinks this is test code", IdempotencyKey: uuid.NewString(), RequestHash: "h2",
		CanApprove: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Counts.Decided != 0 || res.Counts.Grouped != 1 {
		t.Fatalf("AI agent: %+v", res.Counts)
	}
}

// Skips: a finding with a pending request, one that cannot make the move
// (already a false positive), an unknown id, another organization's finding
// and a finding outside the caller's scope all read as skipped; the last
// three are not_found exactly alike and the preview names none of them.
// Without findings:bulk_update the route is 403.
func TestBulkDismiss_SkipsAndIsolation_DB(t *testing.T) {
	h := newBulkDismissHarness(t)
	org, other := h.org(), h.org()
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"off"}`)
	admin, approver := h.member(org, "admin"), h.member(org, "owner")
	_ = approver

	pending := h.newFinding(org, "low")
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"all"}`)
	if st, _, _ := requestFP(h.findingApprovalHarness, admin, pending); st != "pending" {
		t.Fatal("fixture: request not pending")
	}
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"off"}`)
	done := h.newFinding(org, "low")
	h.exec(`UPDATE findings SET status = 'false_positive' WHERE id = $1`, done)
	foreign := h.newFinding(other, "low")
	h.exec(`UPDATE findings SET title = 'secret foreign title' WHERE id = $1`, foreign)
	missing := uuid.NewString()
	ok := h.newFinding(org, "low")

	p := h.call(admin, "/preview", dismissBody([]string{pending, done, foreign, missing, ok}, nil), http.StatusOK)
	want := map[string]string{pending: finding.BulkSkipPendingRequest, done: finding.BulkSkipCannotMove,
		foreign: finding.BulkSkipNotFound, missing: finding.BulkSkipNotFound}
	got := skipReasons(p)
	for id, r := range want {
		if got[id] != r {
			t.Fatalf("%s: skip %q, want %q (%v)", id, got[id], r, got)
		}
	}
	if p.Counts.Decided != 1 || len(p.SkipList) != 4 {
		t.Fatalf("preview: %+v", p.BulkDismissResult)
	}
	for _, it := range p.SkipList {
		if (it.ID == foreign || it.ID == missing) && (it.Title != "" || it.Severity != "") {
			t.Fatalf("a not-found finding is named: %+v", it)
		}
	}

	// Out of scope reads like missing: a restricted member with
	// findings:approve sees only the finding on their asset.
	member := h.member(org, "member")
	h.customRoleMember(member, org, permission.FindingsRead, permission.FindingsWrite, permission.FindingsBulkUpdate, permission.FindingsApprove)
	h.mintToken(&member, org)
	in, inAsset := h.onAsset(org, "low")
	out, _ := h.onAsset(org, "low")
	h.exec(`UPDATE findings SET title = 'secret out of scope title' WHERE id = $1`, out)
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`, member.id, org, inAsset)
	p = h.call(member, "/preview", dismissBody([]string{in, out}, nil), http.StatusOK)
	if skipReasons(p)[out] != finding.BulkSkipNotFound || p.Counts.Decided != 1 {
		t.Fatalf("out of scope: %+v", p.BulkDismissResult)
	}
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), "secret") {
		t.Fatal("the preview names a finding the caller cannot see")
	}
	res := h.call(member, "", dismissBody([]string{in, out}, nil), http.StatusOK)
	if len(res.Decided) != 1 || res.Decided[0] != in || findingStatusOf(h.findingApprovalHarness, out) != "confirmed" {
		t.Fatalf("out-of-scope apply: %+v", res.BulkDismissResult)
	}

	// Permission gate: findings:write without findings:bulk_update.
	nobulk := h.member(org, "member")
	h.customRoleMember(nobulk, org, permission.FindingsRead, permission.FindingsWrite, permission.FindingsApprove)
	h.mintToken(&nobulk, org)
	h.call(nobulk, "/preview", dismissBody([]string{ok}, nil), http.StatusForbidden)
	h.call(nobulk, "", dismissBody([]string{ok}, nil), http.StatusForbidden)
	if findingStatusOf(h.findingApprovalHarness, ok) != "confirmed" {
		t.Fatal("a refused call changed a finding")
	}
}

// Size and selection: 501 ids, or a filter selecting 501, answer 400
// BULK_DISMISS_TOO_LARGE with the count; a filter whose count changed answers
// 409 SELECTION_CHANGED with the new count; a filter of 3 previews them.
func TestBulkDismiss_SizeAndSelection_DB(t *testing.T) {
	h := newBulkDismissHarness(t)
	org := h.org()
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"off"}`)
	admin := h.member(org, "admin")
	ids := make([]string, 501)
	for i := range ids {
		ids[i] = uuid.NewString()
	}
	e := h.call(admin, "/preview", dismissBody(ids, nil), http.StatusBadRequest)
	if e.Code != "BULK_DISMISS_TOO_LARGE" || e.Details["count"] != float64(501) || e.Details["max"] != float64(500) {
		t.Fatalf("501 ids: %+v", e)
	}
	tool := "bulk-" + uuid.NewString()[:8]
	h.exec(`INSERT INTO findings (id, tenant_id, source, tool_name, message, severity, fingerprint, status)
		SELECT gen_random_uuid(), $1, 'sast', $2::text, 'm', 'low', 'bd-' || $2::text || '-' || g, 'confirmed' FROM generate_series(1, 501) g`, org, tool)
	filter := map[string]any{"tool_name": tool}
	e = h.call(admin, "/preview", map[string]any{"filter": filter, "expected_count": 501, "closure_reason": "detection_error"}, http.StatusBadRequest)
	if e.Code != "BULK_DISMISS_TOO_LARGE" || e.Details["count"] != float64(501) {
		t.Fatalf("filter of 501: %+v", e)
	}
	small := "bulk-" + uuid.NewString()[:8]
	for range 3 {
		f := h.newFinding(org, "low")
		h.exec(`UPDATE findings SET tool_name = $2, rule_id = 'rule-1' WHERE id = $1`, f, small)
	}
	e = h.call(admin, "/preview", map[string]any{"filter": map[string]any{"tool_name": small}, "expected_count": 4, "closure_reason": "detection_error"}, http.StatusConflict)
	if e.Code != "SELECTION_CHANGED" || e.Details["count"] != float64(3) {
		t.Fatalf("changed selection: %+v", e)
	}
	p := h.call(admin, "/preview", map[string]any{"filter": map[string]any{"tool_name": small}, "expected_count": 3, "closure_reason": "detection_error"}, http.StatusOK)
	if p.Counts.Decided != 3 || p.SameRule == nil || p.SameRule.Count != 3 || p.SameRule.Suggest {
		t.Fatalf("filter of 3: %+v", p.BulkDismissResult)
	}
	out := h.call(admin, "", map[string]any{"filter": map[string]any{"tool_name": small}, "expected_count": 3,
		"closure_reason": "detection_error", "idempotency_key": uuid.NewString()}, http.StatusOK)
	if len(out.Decided) != 3 {
		t.Fatalf("filter apply: %+v", out.BulkDismissResult)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_bulk_dismissals WHERE id = $1 AND filter_hash IS NOT NULL AND source_label LIKE '3 findings, filter: tool_name=%'`, out.BulkID); n != 1 {
		t.Fatal("the bulk row lacks the filter hash or label")
	}
}

// A retry with the same key returns the stored result (replay) and changes
// nothing more; the same key with another request is 409
// IDEMPOTENCY_KEY_REUSED; a key is required to apply.
func TestBulkDismiss_Idempotency_DB(t *testing.T) {
	h := newBulkDismissHarness(t)
	org := h.org()
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"off"}`)
	admin := h.member(org, "admin")
	ids := h.findings(org, "low", 2)
	body := dismissBody(ids, map[string]any{"note": "same"})
	first := h.call(admin, "", body, http.StatusOK)
	again := h.call(admin, "", body, http.StatusOK)
	if !again.Replay || again.BulkID != first.BulkID || len(again.Decided) != 2 || first.Replay {
		t.Fatalf("replay: %+v / %+v", first.BulkDismissResult, again.BulkDismissResult)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE tenant_id = $1`, org); n != 2 {
		t.Fatalf("a replay decided again: %d requests", n)
	}
	body["note"] = "different"
	if e := h.call(admin, "", body, http.StatusUnprocessableEntity); e.Code != "IDEMPOTENCY_KEY_REUSED" {
		t.Fatalf("mismatch: %+v", e)
	}
	delete(body, "idempotency_key")
	h.call(admin, "", body, http.StatusBadRequest)
}

// Budget and step-up: more than 25 decided alone without a recent
// re-authentication is refused before anything changes (no finding moved,
// no bulk row); with it they apply. A person with 990 decided alone in the
// last 24 hours decides 10 more; the rest goes to the group, counted as
// budget_overflow.
func TestBulkDismiss_StepUpAndBudget_DB(t *testing.T) {
	h := newBulkDismissHarness(t)
	org := h.org()
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"off"}`)
	admin := h.member(org, "admin")
	h.member(org, "owner")
	ids := h.findings(org, "low", 26)

	p := h.call(admin, "/preview", dismissBody(ids, nil), http.StatusOK)
	if !p.StepUpRequired || p.NoteRequired {
		t.Fatalf("preview of 26 alone: %+v", p.BulkDismissResult)
	}
	h.stepUp.refuse.Store(true)
	if e := h.call(admin, "", dismissBody(ids, nil), http.StatusForbidden); e.Code != "STEP_UP_REQUIRED" {
		t.Fatalf("no step-up: %+v", e)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND status <> 'confirmed'`, org); n != 0 {
		t.Fatalf("%d findings moved without step-up", n)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_bulk_dismissals WHERE tenant_id = $1`, org); n != 0 {
		t.Fatal("a refused call left a bulk row")
	}
	h.stepUp.refuse.Store(false)
	if out := h.call(admin, "", dismissBody(ids, nil), http.StatusOK); len(out.Decided) != 26 {
		t.Fatalf("with step-up: %+v", out.Counts)
	}

	h.exec(`INSERT INTO finding_bulk_dismissals (tenant_id, created_by, request_hash, requested_status, closure_reason, decided_count)
		VALUES ($1, $2, 'x', 'false_positive', 'detection_error', 964)`, org, admin.id)
	more := h.findings(org, "low", 20)
	p = h.call(admin, "/preview", dismissBody(more, nil), http.StatusOK)
	if p.Counts.Decided != 10 || p.Counts.Grouped != 10 || p.Counts.BudgetOverflow != 10 || !p.NoteRequired {
		t.Fatalf("budget preview: %+v", p.BulkDismissResult)
	}
	h.call(admin, "", dismissBody(more, nil), http.StatusBadRequest) // the overflow group needs a note
	out := h.call(admin, "", dismissBody(more, map[string]any{"note": "over the daily budget"}), http.StatusOK)
	if len(out.Decided) != 10 || out.Grouped == nil || out.Grouped.Count != 10 || out.Counts.BudgetOverflow != 10 {
		t.Fatalf("budget apply: %+v", out.BulkDismissResult)
	}
	if n := h.countRows(`SELECT COALESCE(SUM(decided_count), 0) FROM finding_bulk_dismissals WHERE tenant_id = $1 AND created_by = $2`, org, admin.id); n != 1000 {
		t.Fatalf("budget used %d, want 1000", n)
	}
}

// A level raised between the plan and the apply (here by a trigger that
// fires when the bulk row is inserted, the moment between them) sends the
// findings to the group: never decided alone. Without a note they are
// reported note_required instead of grouped without one.
func TestBulkDismiss_RaisedLevelRaceGoesToGroup_DB(t *testing.T) {
	h := newBulkDismissHarness(t)
	org := h.org()
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"off"}`)
	admin := h.member(org, "admin")
	h.member(org, "owner")
	fn := "bd_raise_" + strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	// DDL: the least-privilege app role may not run it, the schema owner does.
	ddl := testdb.OpenMigrator(t)
	mustDDL := func(q string) {
		t.Helper()
		if _, err := ddl.ExecContext(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
	mustDDL(fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $f$
		BEGIN
			UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{finding_approvals}', '{"fp_approval":"all"}'::jsonb)
			WHERE id = NEW.tenant_id;
			RETURN NEW;
		END $f$`, fn))
	mustDDL(fmt.Sprintf(`CREATE TRIGGER %s AFTER INSERT ON finding_bulk_dismissals FOR EACH ROW
		WHEN (NEW.tenant_id = '%s'::uuid) EXECUTE FUNCTION %s()`, fn, org, fn))
	t.Cleanup(func() {
		_, _ = ddl.ExecContext(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON finding_bulk_dismissals`, fn))
		_, _ = ddl.ExecContext(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, fn))
	})

	ids := h.findings(org, "low", 2)
	if p := h.call(admin, "/preview", dismissBody(ids, nil), http.StatusOK); p.Counts.Decided != 2 {
		t.Fatalf("plan under off: %+v", p.Counts)
	}
	out := h.call(admin, "", dismissBody(ids, map[string]any{"note": "raced"}), http.StatusOK)
	if len(out.Decided) != 0 || out.Grouped == nil || out.Grouped.Count != 2 {
		t.Fatalf("raced with a note: %+v", out.BulkDismissResult)
	}
	for _, id := range ids {
		if findingStatusOf(h.findingApprovalHarness, id) != "confirmed" {
			t.Fatal("a raced finding was decided alone")
		}
	}
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"off"}`)
	ids = h.findings(org, "low", 2)
	out = h.call(admin, "", dismissBody(ids, nil), http.StatusOK)
	if len(out.Decided) != 0 || out.Grouped != nil || len(out.Skipped) != 2 || out.Skipped[0].Reason != finding.BulkSkipNoteRequired {
		t.Fatalf("raced without a note: %+v", out.BulkDismissResult)
	}
}

// Undo: only the creator (another member, or another organization's owner,
// gets 404), within 24 hours, once.
// It reopens the findings decided alone that are still false positives (a
// finding moved since is left as it is and reported), and cancels the
// bulk's pending group. Nothing is deleted.
func TestBulkDismiss_Undo_DB(t *testing.T) {
	h := newBulkDismissHarness(t)
	org, otherOrg := h.org(), h.org()
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"high_and_above"}`)
	admin, owner := h.member(org, "admin"), h.member(org, "owner")
	foreignOwner := h.member(otherOrg, "owner")
	low := h.findings(org, "low", 3)
	high := h.newFinding(org, "high")
	out := h.call(admin, "", dismissBody(append(append([]string{}, low...), high), map[string]any{"note": "checked"}), http.StatusOK)
	if len(out.Decided) != 3 || out.Grouped == nil {
		t.Fatalf("apply: %+v", out.BulkDismissResult)
	}
	h.exec(`UPDATE findings SET status = 'confirmed' WHERE id = $1`, low[0])
	h.exec(`UPDATE findings SET status = 'in_progress' WHERE id = $1`, low[0])

	undo := "/" + out.BulkID + "/reopen"
	h.call(owner, undo, map[string]any{}, http.StatusNotFound)
	h.call(foreignOwner, undo, map[string]any{}, http.StatusNotFound)
	h.call(admin, "/"+uuid.NewString()+"/reopen", map[string]any{}, http.StatusNotFound)
	var u finding.UndoBulkDismissResult
	if err := json.Unmarshal([]byte(h.expect(admin, http.MethodPost, "/api/v1/findings/bulk-dismissals"+undo, "{}", http.StatusOK)), &u); err != nil {
		t.Fatal(err)
	}
	if len(u.Reopened) != 2 || len(u.Skipped) != 1 || u.Skipped[0].ID != low[0] || u.Skipped[0].Reason != finding.BulkSkipChanged || !u.GroupCanceled {
		t.Fatalf("undo: %+v", u)
	}
	for _, id := range low[1:] {
		if findingStatusOf(h.findingApprovalHarness, id) != "confirmed" {
			t.Fatal("undo did not reopen")
		}
		if n := h.countRows(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND changes::text LIKE '%Undo of bulk dismissal%'`, id); n == 0 {
			t.Fatal("the reopen has no timeline entry with the undo note")
		}
	}
	if findingStatusOf(h.findingApprovalHarness, low[0]) != "in_progress" {
		t.Fatal("undo touched a finding that moved since")
	}
	if n := h.countRows(`SELECT COUNT(*) FROM approval_batches WHERE id = $1 AND status = 'canceled'`, out.Grouped.BatchID); n != 1 {
		t.Fatal("the bulk's group was not canceled")
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE tenant_id = $1`, org); n < 4 {
		t.Fatal("undo deleted decision records")
	}
	h.call(admin, undo, map[string]any{}, http.StatusConflict)

	old := h.call(admin, "", dismissBody(h.findings(org, "low", 1), nil), http.StatusOK)
	h.exec(`UPDATE finding_bulk_dismissals SET created_at = now() - interval '25 hours' WHERE id = $1`, old.BulkID)
	h.call(admin, "/"+old.BulkID+"/reopen", map[string]any{}, http.StatusConflict)
}

// D4 on a single request: the note is optional when the requester decides
// alone on a finding that is not serious; required (validation error) on a
// serious finding decided alone, and whenever the request waits for a second
// person. The same rule holds in bulk: the preview says note_required.
func TestBulkDismiss_NoteRule_D4_DB(t *testing.T) {
	h := newBulkDismissHarness(t)
	org := h.org()
	admin := h.member(org, "admin")
	h.member(org, "owner")
	req := func(fid string, want int) {
		h.t.Helper()
		h.expect(admin, http.MethodPost, "/api/v1/findings/"+fid+"/approvals/",
			`{"requested_status":"false_positive","closure_reason":"detection_error","justification":""}`, want)
	}
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"off"}`)
	low := h.newFinding(org, "low")
	req(low, http.StatusCreated)
	if findingStatusOf(h.findingApprovalHarness, low) != "false_positive" {
		t.Fatal("a non-serious finding decided alone without a note was not applied")
	}
	high := h.newFinding(org, "high")
	req(high, http.StatusBadRequest)
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"all"}`)
	waits := h.newFinding(org, "low")
	req(waits, http.StatusBadRequest)
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE finding_id IN ($1, $2)`, high, waits); n != 0 {
		t.Fatal("a request without the note it needs was saved")
	}
	// The reason code stays required.
	h.expect(admin, http.MethodPost, "/api/v1/findings/"+h.newFinding(org, "low")+"/approvals/",
		`{"requested_status":"false_positive","justification":"x"}`, http.StatusUnprocessableEntity)

	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"off"}`)
	lows := h.findings(org, "low", 2)
	if p := h.call(admin, "/preview", dismissBody(lows, nil), http.StatusOK); p.NoteRequired || p.NoteMinLength != 0 {
		t.Fatalf("non-serious alone: %+v", p.BulkDismissResult)
	}
	if out := h.call(admin, "", dismissBody(lows, nil), http.StatusOK); len(out.Decided) != 2 {
		t.Fatalf("non-serious alone without a note: %+v", out.Counts)
	}
	mixed := []string{h.newFinding(org, "low"), h.newFinding(org, "critical")}
	if p := h.call(admin, "/preview", dismissBody(mixed, nil), http.StatusOK); !p.NoteRequired || p.Counts.Decided != 2 {
		t.Fatalf("serious alone: %+v", p.BulkDismissResult)
	}
	h.call(admin, "", dismissBody(mixed, nil), http.StatusBadRequest)
	if findingStatusOf(h.findingApprovalHarness, mixed[0]) != "confirmed" {
		t.Fatal("a refused bulk changed a finding")
	}
}

// Performance (BULK_DISMISS_PERF=1; run alone so the counts are this test's):
// a tenant with 10,000 findings; dismiss 500 under level off (all decided
// alone) and under all (one group of 500); a filter preview over the 10,000
// is refused as too large. The org-wide lookups are memoized per call: the
// statements the plan runs do not grow with the findings beyond the
// per-finding writes. Prints wall time and statement counts
// (pg_stat_statements when the server loads it).
func TestBulkDismiss_Perf_DB(t *testing.T) {
	if os.Getenv("BULK_DISMISS_PERF") == "" {
		t.Skip("set BULK_DISMISS_PERF=1 to run the bulk dismiss performance test")
	}
	h := newBulkDismissHarness(t)
	org := h.org()
	admin := h.member(org, "admin")
	for range 3 {
		h.member(org, "owner")
	}
	tool := "perf-" + uuid.NewString()[:8]
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type)
		SELECT gen_random_uuid(), $1, 'perf-' || g || '.example', 'domain' FROM generate_series(1, 200) g`, org)
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, rule_id, message, severity, fingerprint, status)
		SELECT gen_random_uuid(), $1, (SELECT id FROM assets WHERE tenant_id = $1 ORDER BY id OFFSET (g % 200) LIMIT 1),
		       'sast', $2::text, 'rule-' || (g % 7), 'm', (ARRAY['low','medium','high','critical'])[1 + g % 4], 'perf-' || $2::text || '-' || g, 'confirmed'
		FROM generate_series(1, 10000) g`, org, tool)
	stats := true
	if _, err := h.db.ExecContext(context.Background(), `CREATE EXTENSION IF NOT EXISTS pg_stat_statements`); err != nil {
		stats = false
	}
	calls := func() int {
		if !stats {
			return -1
		}
		var n int
		if err := h.db.QueryRowContext(context.Background(), `SELECT COALESCE(SUM(calls), 0)::int FROM pg_stat_statements
			WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())`).Scan(&n); err != nil {
			stats = false
			return -1
		}
		return n
	}
	reset := func() {
		if stats {
			_, _ = h.db.ExecContext(context.Background(), `SELECT pg_stat_statements_reset()`)
		}
	}
	pick := func(n int) []string {
		rows, err := h.db.QueryContext(context.Background(), `SELECT id::text FROM findings WHERE tenant_id = $1 AND status = 'confirmed' ORDER BY id LIMIT $2`, org, n)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			out = append(out, id)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	run := func(name, path string, body map[string]any, want int) {
		reset()
		start := time.Now()
		r := h.call(admin, path, body, want)
		took := time.Since(start)
		// The counting query itself and the reset are included (2).
		t.Logf("PERF %-38s %8.0f ms  statements=%d  decided=%d grouped=%d skipped=%d code=%s",
			name, float64(took.Milliseconds()), calls(), r.Counts.Decided, r.Counts.Grouped, r.Counts.Skipped, r.Code)
		if stats && os.Getenv("BULK_DISMISS_PERF") == "top" {
			topStatements(t, h.db)
		}
	}
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"off"}`)
	ids := pick(500)
	run("preview 500 ids, level off", "/preview", dismissBody(ids, map[string]any{"note": "perf"}), http.StatusOK)
	run("apply 500 ids, level off (alone)", "", dismissBody(ids, map[string]any{"note": "perf"}), http.StatusOK)
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"all"}`)
	ids = pick(500)
	run("preview 500 ids, level all", "/preview", dismissBody(ids, map[string]any{"note": "perf"}), http.StatusOK)
	run("apply 500 ids, level all (one group)", "", dismissBody(ids, map[string]any{"note": "perf"}), http.StatusOK)
	run("filter preview over 10,000 (too large)", "/preview", map[string]any{"filter": map[string]any{"tool_name": tool},
		"expected_count": 10000, "closure_reason": "detection_error"}, http.StatusBadRequest)
}

// topStatements logs the statements of the database that took the most time
// (pg_stat_statements), for BULK_DISMISS_PERF=top.
func topStatements(t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `SELECT calls, round(total_exec_time)::int, left(regexp_replace(query, '\s+', ' ', 'g'), 110)
		FROM pg_stat_statements WHERE dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
		ORDER BY total_exec_time DESC LIMIT 8`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var c, ms int
		var q string
		if err := rows.Scan(&c, &ms, &q); err != nil {
			return
		}
		t.Logf("    %5d calls %6d ms  %s", c, ms, q)
	}
	if err := rows.Err(); err != nil {
		t.Log(err)
	}
}

// A bulk that decides 10 or more findings alone gets at least one second
// look when the organization's share is above 0 (even at 1%), and none when
// the share is 0.
func TestBulkDismiss_SecondLookFloor_DB(t *testing.T) {
	h := newBulkDismissHarness(t)
	count := func(org string) int {
		return h.countRows(`SELECT COUNT(*) FROM finding_decision_reviews WHERE tenant_id = $1 AND reason = 'second_look_sample'`, org)
	}
	for _, tc := range []struct {
		share string
		min   int
		max   int
	}{{"1", 1, 10}, {"0", 0, 0}} {
		org := h.org()
		setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"off","second_look_percent":`+tc.share+`}`)
		admin := h.member(org, "admin")
		ids := h.findings(org, "low", 10)
		r := h.call(admin, "", dismissBody(ids, map[string]any{"note": "fixtures"}), http.StatusOK)
		if len(r.Decided) != 10 {
			t.Fatalf("share %s: decided %d", tc.share, len(r.Decided))
		}
		if n := count(org); n < tc.min || n > tc.max {
			t.Fatalf("share %s: %d second looks, want %d..%d", tc.share, n, tc.min, tc.max)
		}
	}
}

// A client that leaves mid-apply gets its findings decided (the apply runs
// on its own context) and must not escape the audit trail: the per-decision
// rows and the bulk row are written all the same, and the retry is a replay.
func TestBulkDismiss_AuditSurvivesDisconnect_DB(t *testing.T) {
	h := newBulkDismissHarness(t)
	org := h.org()
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"off"}`)
	admin := h.member(org, "admin")
	h.member(org, "owner")
	ids := h.findings(org, "low", 300)
	body := dismissBody(ids, nil)
	b, _ := json.Marshal(body)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, h.srv.URL+"/api/v1/findings/bulk-dismissals", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+admin.token)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
		t.Skip("the apply finished before the client gave up; inconclusive")
	}
	// Wait for the apply, then for its audit trail, which the handler
	// writes after the apply.
	waitFor := func(q string, want int) int {
		deadline := time.Now().Add(120 * time.Second)
		n := 0
		for time.Now().Before(deadline) {
			if n = h.countRows(q, org); n >= want {
				return n
			}
			time.Sleep(200 * time.Millisecond)
		}
		return n
	}
	waitFor(`SELECT COUNT(*) FROM finding_bulk_dismissals WHERE tenant_id = $1 AND result <> '{}'::jsonb`, 1)
	decided := waitFor(`SELECT COUNT(*) FROM finding_status_approvals WHERE tenant_id = $1 AND single_person AND status = 'approved'`, len(ids))
	bulkAudit := waitFor(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding.bulk_dismissed'`, 1)
	singleAudit := waitFor(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.single_person_decided'`, decided)
	if decided != len(ids) || singleAudit != decided || bulkAudit != 1 {
		t.Fatalf("decided alone %d of %d, per-decision audit rows %d, bulk audit rows %d", decided, len(ids), singleAudit, bulkAudit)
	}
	if out := h.call(admin, "", body, http.StatusOK); !out.Replay {
		t.Fatal("the retry is not a replay")
	}
}

// The step-up counts the last hour, not only the call: two calls of 25
// decide 50 alone, and the second needs the re-authentication a single call
// of 50 needs.
func TestBulkDismiss_StepUpCountsTheLastHour_DB(t *testing.T) {
	h := newBulkDismissHarness(t)
	org := h.org()
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"off"}`)
	admin := h.member(org, "admin")
	h.member(org, "owner")
	h.stepUp.refuse.Store(true)
	ids := h.findings(org, "low", 50)
	h.call(admin, "", dismissBody(ids, nil), http.StatusForbidden)
	if a := h.call(admin, "", dismissBody(ids[:25], nil), http.StatusOK); len(a.Decided) != 25 {
		t.Fatalf("first 25: %+v", a.Counts)
	}
	p := h.call(admin, "/preview", dismissBody(ids[25:], nil), http.StatusOK)
	if !p.StepUpRequired {
		t.Fatalf("preview of the second 25 does not announce the step-up: %+v", p.BulkDismissResult)
	}
	if e := h.call(admin, "", dismissBody(ids[25:], nil), http.StatusForbidden); e.Code != "STEP_UP_REQUIRED" {
		t.Fatalf("second 25 without step-up: %+v", e)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM findings WHERE tenant_id = $1 AND status <> 'confirmed'`, org); n != 25 {
		t.Fatalf("%d findings moved, want 25", n)
	}
	// An hour on, the first call no longer counts.
	h.exec(`UPDATE finding_bulk_dismissals SET created_at = now() - interval '61 minutes' WHERE tenant_id = $1`, org)
	if b := h.call(admin, "", dismissBody(ids[25:], nil), http.StatusOK); len(b.Decided) != 25 {
		t.Fatalf("second 25 an hour later: %+v", b.Counts)
	}
	// With the step-up granted, a larger call goes through as before.
	h.stepUp.refuse.Store(false)
	more := h.findings(org, "low", 30)
	if c := h.call(admin, "", dismissBody(more, nil), http.StatusOK); len(c.Decided) != 30 {
		t.Fatalf("with step-up: %+v", c.Counts)
	}
}

// An undo that arrives while the apply is still running (the row is
// reserved, its outcome not recorded) answers 409 and leaves the row
// undoable; once the outcome is recorded the undo works.
func TestBulkDismiss_UndoWhileRunningIsRefused_DB(t *testing.T) {
	h := newBulkDismissHarness(t)
	org := h.org()
	admin := h.member(org, "admin")
	h.member(org, "owner")
	id := uuid.NewString()
	h.exec(`INSERT INTO finding_bulk_dismissals (id, tenant_id, created_by, idempotency_key, request_hash, requested_status, closure_reason, decided_count)
		VALUES ($1, $2, $3, 'k-running', 'x', 'false_positive', 'detection_error', 10)`, id, org, admin.id)
	code, resp := h.do(admin, http.MethodPost, "/api/v1/findings/bulk-dismissals/"+id+"/reopen", "{}")
	if code != http.StatusConflict {
		t.Fatalf("undo of a running bulk: %d %s", code, resp)
	}
	st := ""
	if err := h.db.QueryRowContext(context.Background(), `SELECT status FROM finding_bulk_dismissals WHERE id = $1`, id).Scan(&st); err != nil || st != "applied" {
		t.Fatalf("row status %q (%v), want applied", st, err)
	}
	h.exec(`UPDATE finding_bulk_dismissals SET result = '{"bulk_id":"x"}'::jsonb WHERE id = $1`, id)
	if code, resp := h.do(admin, http.MethodPost, "/api/v1/findings/bulk-dismissals/"+id+"/reopen", "{}"); code != http.StatusOK {
		t.Fatalf("undo once recorded: %d %s", code, resp)
	}
}
