package routes

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	activityapp "github.com/openctemio/openctem/api/internal/app/activity"
	lcapp "github.com/openctemio/openctem/api/internal/app/findinglifecycle"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	lc "github.com/openctemio/openctem/api/pkg/domain/findinglifecycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// lifecycleFixture publishes an organization lifecycle on the harness's
// tenant and wires it into the status paths.
type lifecycleFixture struct {
	svc                               *lcapp.Service
	inDev, inReview, qaPassed, bounty shared.ID
}

func newLifecycleFixture(t *testing.T, h *gsHarness, spec func(f *lifecycleFixture) lc.Spec) *lifecycleFixture {
	t.Helper()
	db := &postgres.DB{DB: h.db}
	log := logger.NewNop()
	svc := lcapp.NewService(postgres.NewLifecycleSubStatusRepository(db), postgres.NewLifecycleSchemeRepository(db), nil, nil, log)
	h.vuln.SetLifecycles(svc)
	h.actions.SetLifecycles(svc)
	h.vuln.SetActivityService(activityapp.NewFindingActivityService(postgres.NewFindingActivityRepository(db), postgres.NewFindingRepository(db), log))
	ctx := context.Background()
	f := &lifecycleFixture{svc: svc}
	mk := func(key, status, reason string) shared.ID {
		t.Helper()
		s, err := svc.CreateSubStatus(ctx, h.tenant, lc.SubStatusInput{Key: key, Name: key, Color: "blue", CanonicalStatus: status, ClosureReason: reason}, lcapp.Actor{})
		if err != nil {
			t.Fatal(err)
		}
		return s.ID()
	}
	f.inDev = mk("in_dev", "in_progress", "")
	f.inReview = mk("in_review", "in_progress", "")
	f.qaPassed = mk("qa_passed", "fix_applied", "")
	f.bounty = mk("bounty_paid", "resolved", "fixed")
	view, err := svc.CreateScheme(ctx, h.tenant, lc.SchemeInput{Key: "default", Name: "Default"}, lcapp.Actor{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(spec(f))
	if err != nil {
		t.Fatal(err)
	}
	if _, v, err := svc.UpdateDraft(ctx, h.tenant, view.Scheme.ID(), 1, raw, "", view.Draft.SpecHash); err != nil || !v.OK() {
		t.Fatalf("draft: %v %+v", err, v.Errors)
	}
	if _, err := svc.PublishVersion(ctx, h.tenant, view.Scheme.ID(), 1, "test", lcapp.Actor{}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *lifecycleFixture) ids() []string {
	return []string{f.inDev.String(), f.inReview.String(), f.qaPassed.String(), f.bounty.String()}
}

func (h *gsHarness) subStatusOf(id shared.ID) string {
	h.t.Helper()
	var sub sql.NullString
	if err := h.db.QueryRow(`SELECT sub_status_id::text FROM findings WHERE id = $1`, id.String()).Scan(&sub); err != nil {
		h.t.Fatal(err)
	}
	return sub.String
}

func (h *gsHarness) statusOf(id shared.ID) string {
	h.t.Helper()
	var st string
	if err := h.db.QueryRow(`SELECT status FROM findings WHERE id = $1`, id.String()).Scan(&st); err != nil {
		h.t.Fatal(err)
	}
	return st
}

// An organization lifecycle can only add constraints (RFC-110): through the
// real status routes, its listed moves never let anyone past a platform rule
// (findings:verify, the evidence matrix, the fix-claim rules, four-eyes, the
// lifecycle edges), while its own guards (a longer note, required fields, a
// permission, keeping automation off a move) do bind. Sub-statuses change only
// through these decided moves, each on the timeline with the lifecycle
// version that decided it; another organization's sub-status is refused.
func TestFindingLifecycle_CannotBypassTheEngine_DB(t *testing.T) {
	h := newGroupScopeHarness(t)
	fx := newLifecycleFixture(t, h, func(f *lifecycleFixture) lc.Spec {
		return lc.Spec{
			SubStatuses: f.ids(),
			Transitions: []lc.TransitionSpec{
				{ID: "start_dev", Name: "Start", From: []string{"status:confirmed"}, To: f.inDev.String()},
				{ID: "to_review", Name: "Review", From: []string{f.inDev.String()}, To: f.inReview.String(),
					Guards: []lc.Guard{{Kind: lc.GuardRequireNote, MinLen: 10}, {Kind: lc.GuardDenyActorKinds, Kinds: []string{"workflow", "api_key"}}}},
				{ID: "claim", Name: "Claim fix", From: []string{"status:in_progress"}, To: f.qaPassed.String(),
					Guards: []lc.Guard{{Kind: lc.GuardRequireFields, Fields: []string{"fix_reference"}}}},
				// Looks like a shortcut: a listed close with no guard. The
				// platform's verify permission and evidence still apply.
				{ID: "close_bounty", Name: "Bounty paid", From: []string{"status:fix_applied"}, To: f.bounty.String()},
				// A permission on top of the platform's for leaving review.
				{ID: "review_back", Name: "Back to backlog", From: []string{f.inReview.String()}, To: "status:confirmed",
					Guards: []lc.Guard{{Kind: lc.GuardRequirePermission, AnyOf: []string{"findings:approve"}}}},
			},
		}
	})
	fa := h.findingA
	patch := func(perms []string, body map[string]any) (int, string) {
		return h.doPerms(h.memberA, perms, http.MethodPatch, "/api/v1/findings/"+fa.String()+"/status", body)
	}
	h.exec(`UPDATE findings SET status = 'confirmed', severity = 'high', sub_status_id = NULL WHERE id = $1`, fa.String())

	// Start development onto the listed sub-status.
	if code, body := patch(rgMemberPerms, map[string]any{"status": "in_progress", "sub_status_id": fx.inDev.String()}); code != http.StatusOK {
		t.Fatalf("start dev: %d %.300s", code, body)
	}
	if h.subStatusOf(fa) != fx.inDev.String() {
		t.Fatalf("sub-status = %q, want in_dev", h.subStatusOf(fa))
	}
	var version string
	if err := h.db.QueryRow(`SELECT COALESCE(lifecycle_version, '') FROM finding_activities
		WHERE finding_id = $1 AND changes->>'new_sub_status_id' = $2 ORDER BY created_at DESC LIMIT 1`, fa.String(), fx.inDev.String()).Scan(&version); err != nil {
		t.Fatalf("timeline entry of the move: %v", err)
	}
	if !strings.HasPrefix(version, "lifecycle:") {
		t.Errorf("timeline lifecycle version = %q, want the scheme version", version)
	}

	// A label move inside in_progress needs the organization's longer note.
	if code, body := patch(rgMemberPerms, map[string]any{"status": "in_progress", "sub_status_id": fx.inReview.String(), "resolution": "short"}); code != http.StatusBadRequest {
		t.Fatalf("short note: %d %.300s", code, body)
	}
	if code, body := patch(rgMemberPerms, map[string]any{"status": "in_progress", "sub_status_id": fx.inReview.String(), "resolution": "ready for review"}); code != http.StatusOK {
		t.Fatalf("label move: %d %.300s", code, body)
	}
	// Leaving review needs findings:approve on top (the member has none).
	if code, body := patch(rgMemberPerms, map[string]any{"status": "confirmed"}); code != http.StatusBadRequest || !strings.Contains(body, "findings:approve") {
		t.Fatalf("back to backlog without the lifecycle's permission: %d %.300s", code, body)
	}

	// The fix claim needs the lifecycle's field AND the platform's rules
	// (findings:fix_apply, a note, the person's finding).
	noFixApply := []string{"findings:read", "findings:status"}
	if code, body := patch(noFixApply, map[string]any{"status": "fix_applied", "sub_status_id": fx.qaPassed.String(),
		"resolution": "patched", "fields": map[string]string{"fix_reference": "https://git.example.com/pr/1"}}); code != http.StatusForbidden {
		t.Fatalf("claim without findings:fix_apply: %d %.300s", code, body)
	}
	if code, body := patch(rgMemberPerms, map[string]any{"status": "fix_applied", "sub_status_id": fx.qaPassed.String(), "resolution": "patched"}); code != http.StatusBadRequest || !strings.Contains(body, "fix_reference") {
		t.Fatalf("claim without the required field: %d %.300s", code, body)
	}
	if code, body := patch(rgMemberPerms, map[string]any{"status": "fix_applied", "sub_status_id": fx.qaPassed.String(),
		"resolution": "patched", "fields": map[string]string{"fix_reference": "javascript:alert(1)"}}); code != http.StatusBadRequest {
		t.Fatalf("claim with a bad link: %d %.300s", code, body)
	}
	if code, body := patch(rgMemberPerms, map[string]any{"status": "fix_applied", "sub_status_id": fx.qaPassed.String(),
		"resolution": "patched", "fields": map[string]string{"fix_reference": "https://git.example.com/pr/1"}}); code != http.StatusOK {
		t.Fatalf("claim: %d %.300s", code, body)
	}
	if h.statusOf(fa) != "fix_applied" || h.subStatusOf(fa) != fx.qaPassed.String() {
		t.Fatalf("after claim: %s / %q", h.statusOf(fa), h.subStatusOf(fa))
	}
	var fields string
	if err := h.db.QueryRow(`SELECT COALESCE(changes->'fields'->>'fix_reference', '') FROM finding_activities
		WHERE finding_id = $1 AND changes->>'new_status' = 'fix_applied' ORDER BY created_at DESC LIMIT 1`, fa.String()).Scan(&fields); err != nil || fields == "" {
		t.Errorf("the fix reference is not on the timeline: %q %v", fields, err)
	}

	// The listed close does not skip the platform: no findings:verify, 403;
	// a high finding without its checklist or a retest, refused.
	if code, body := patch(rgMemberPerms, map[string]any{"status": "resolved", "sub_status_id": fx.bounty.String(), "resolution": "paid"}); code != http.StatusForbidden {
		t.Fatalf("listed close without findings:verify: %d %.300s", code, body)
	}
	if code, body := patch(rgVerifierPerms(), map[string]any{"status": "resolved", "sub_status_id": fx.bounty.String(), "resolution": "paid"}); code != http.StatusBadRequest || !strings.Contains(body, "checklist") {
		t.Fatalf("listed close of a high finding without evidence: %d %.300s", code, body)
	}
	if h.statusOf(fa) != "fix_applied" {
		t.Fatalf("a refused close moved the finding to %s", h.statusOf(fa))
	}
	// A medium finding: the verifier closes it onto the bound closure reason.
	h.exec(`UPDATE findings SET severity = 'medium' WHERE id = $1`, fa.String())
	if code, body := patch(rgVerifierPerms(), map[string]any{"status": "resolved", "sub_status_id": fx.bounty.String(), "resolution": "paid the reporter"}); code != http.StatusOK {
		t.Fatalf("close as bounty paid: %d %.300s", code, body)
	}
	var reason string
	if err := h.db.QueryRow(`SELECT COALESCE(closure_reason, '') FROM findings WHERE id = $1`, fa.String()).Scan(&reason); err != nil || reason != "fixed" {
		t.Errorf("closure reason = %q (%v), want the sub-status's fixed", reason, err)
	}

	// A disposition stays a four-eyes request whatever the lifecycle lists.
	h.exec(`UPDATE findings SET status = 'confirmed', sub_status_id = NULL, closure_reason = NULL, resolved_at = NULL WHERE id = $1`, fa.String())
	if code, body := patch(rgVerifierPerms(), map[string]any{"status": "false_positive", "resolution": "not real"}); code == http.StatusOK {
		t.Fatalf("a false positive was set directly: %.300s", body)
	}
	// An edge the canonical lifecycle lacks (confirmed -> fix_applied) is
	// refused even onto a listed sub-status.
	if code, body := patch(rgVerifierPerms(), map[string]any{"status": "fix_applied", "sub_status_id": fx.qaPassed.String(),
		"resolution": "x", "fields": map[string]string{"fix_reference": "https://git.example.com/pr/2"}}); code == http.StatusOK {
		t.Fatalf("a move off the canonical lifecycle was allowed: %.300s", body)
	}

	// Another organization's sub-status is never a target.
	other := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'other', $2)`, other.String(), "lc-other-"+uuid.NewString()[:8])
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, other.String()) })
	foreign := shared.NewID()
	h.exec(`INSERT INTO lifecycle_sub_statuses (id, tenant_id, canonical_status, key, name, color) VALUES ($1, $2, 'in_progress', 'in_dev', 'x', 'red')`,
		foreign.String(), other.String())
	if code, body := patch(rgMemberPerms, map[string]any{"status": "in_progress", "sub_status_id": foreign.String()}); code != http.StatusBadRequest {
		t.Fatalf("another organization's sub-status: %d %.300s", code, body)
	}
	if h.subStatusOf(fa) != "" || h.statusOf(fa) != "confirmed" {
		t.Fatalf("a refused move changed the finding: %s / %q", h.statusOf(fa), h.subStatusOf(fa))
	}

	// The allowed moves say what each needs and which sub-status it lands on.
	code, body := h.doPerms(h.memberA, rgMemberPerms, http.MethodGet, "/api/v1/findings/"+fa.String()+"/transitions", nil)
	if code != http.StatusOK || !strings.Contains(body, fx.inDev.String()) || !strings.Contains(body, `"transition":"start_dev"`) {
		t.Fatalf("transitions: %d %.500s", code, body)
	}
}

// The action routes (fix-applied, verify, reject) are also decided by the
// organization's lifecycle: a lifecycle that keeps people without
// findings:approve off a resolve stops the verify action too.
func TestFindingLifecycle_ActionRoutesNarrowed_DB(t *testing.T) {
	h := newGroupScopeHarness(t)
	newLifecycleFixture(t, h, func(f *lifecycleFixture) lc.Spec {
		return lc.Spec{SubStatuses: f.ids(), Transitions: []lc.TransitionSpec{
			{ID: "close", Name: "Close", From: []string{"status:fix_applied"}, To: "status:resolved",
				Guards: []lc.Guard{{Kind: lc.GuardRequirePermission, AnyOf: []string{"findings:approve"}}}},
		}}
	})
	fa := h.findingA
	h.exec(`UPDATE findings SET status = 'fix_applied', severity = 'medium', sub_status_id = NULL WHERE id = $1`, fa.String())
	// The verify action needs a complete checklist (a platform rule).
	h.exec(`INSERT INTO finding_verification_checklists (id, tenant_id, finding_id, exposure_cleared, evidence_attached,
		register_updated, monitoring_added, regression_scheduled, completed_by, completed_at)
		VALUES (gen_random_uuid(), $1, $2, true, true, true, true, true, $3, NOW())`, h.tenant.String(), fa.String(), h.memberA.String())
	code, body := h.doPerms(h.memberA, rgVerifierPerms(), http.MethodPost, "/api/v1/findings/actions/verify",
		map[string]any{"finding_ids": []string{fa.String()}, "note": "verified"})
	if code != http.StatusOK || h.statusOf(fa) != "fix_applied" {
		t.Fatalf("verify action past the lifecycle's permission: %d %s (status %s)", code, body, h.statusOf(fa))
	}
	withApprove := append(rgVerifierPerms(), "findings:approve")
	code, body = h.doPerms(h.memberA, withApprove, http.MethodPost, "/api/v1/findings/actions/verify",
		map[string]any{"finding_ids": []string{fa.String()}, "note": "verified"})
	if code != http.StatusOK || h.statusOf(fa) != "resolved" {
		t.Fatalf("verify with the lifecycle's permission: %d %s (status %s)", code, body, h.statusOf(fa))
	}
}
