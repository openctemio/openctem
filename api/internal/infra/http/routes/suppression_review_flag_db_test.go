package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Clearing the review flag of an approved suppression rule through the real
// routes and database: an approver may (the rule keeps its end, the tenant
// audit log has the flag before and after), a member without the approve
// permission may not (403), an unflagged rule answers 409, and another
// organization reaches nothing (404).
func TestSuppressionReviewFlag_Routes_DB(t *testing.T) {
	changeAuditExtraHandlers = func(hs *Handlers, db *postgres.DB) {
		log := logger.NewNop()
		repo := postgres.NewSuppressionRepository(db)
		svc := suppression.NewService(repo, log)
		svc.SetApproverDirectory(repo)
		sh := handler.NewSuppressionHandler(svc, log)
		sh.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log))
		hs.Suppression = sh
	}
	t.Cleanup(func() { changeAuditExtraHandlers = nil })
	h := newChangeAuditHarness(t)
	org, other := h.tenant(), h.tenant()
	t.Cleanup(func() {
		for _, id := range []string{org, other} {
			h.exec(`DELETE FROM suppression_rules WHERE tenant_id = $1`, id)
		}
	})
	admin, member := h.member(org, "admin"), h.member(org, "member")
	otherOwner := h.member(other, "owner")

	var ruleID string
	if err := h.db.QueryRowContext(context.Background(), `INSERT INTO suppression_rules
		(tenant_id, name, rule_id, suppression_type, status, approved_at, expires_at, review_flagged_at, review_reason)
		VALUES ($1, 'legacy', 'go.legacy', 'false_positive', 'approved', now(), now() + interval '90 days', now(), 'no_end_date')
		RETURNING id`, org).Scan(&ruleID); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/suppressions/" + ruleID + "/reviewed"

	h.expect(otherOwner, http.MethodPost, path, "", http.StatusNotFound)
	h.expect(member, http.MethodPost, path, "", http.StatusForbidden)
	body := h.expect(admin, http.MethodPost, path, "", http.StatusOK)
	var resp struct {
		ExpiresAt       string  `json:"expires_at"`
		ReviewFlaggedAt *string `json:"review_flagged_at"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil || resp.ReviewFlaggedAt != nil || resp.ExpiresAt == "" {
		t.Fatalf("response %s", body)
	}
	var flagged bool
	var status string
	if err := h.db.QueryRowContext(context.Background(), `SELECT review_flagged_at IS NOT NULL OR review_reason <> '', status
		FROM suppression_rules WHERE id = $1`, ruleID).Scan(&flagged, &status); err != nil || flagged || status != "approved" {
		t.Fatalf("after review: flagged=%v status=%s err=%v", flagged, status, err)
	}
	rows := h.auditRows(org, "suppression_rule.reviewed")
	requireAudited(t, rows, ruleID, []auditRow{{action: "suppression_rule.reviewed", actor: admin.id,
		before: map[string]any{"review_reason": "no_end_date"}, after: map[string]any{"review_reason": ""}}})
	if n := len(h.auditRows(other, "suppression_rule.")); n != 0 {
		t.Fatalf("tenant B got %d suppression audit rows", n)
	}
	// Nothing left to clear.
	h.expect(admin, http.MethodPost, path, "", http.StatusConflict)
}
