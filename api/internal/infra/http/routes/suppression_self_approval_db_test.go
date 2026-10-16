package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// routeTOTP accepts one authenticator code.
type routeTOTP struct{ good string }

func (f routeTOTP) VerifyFreshTOTP(_ context.Context, _, code string) error {
	if code != f.good {
		return suppression.ErrSelfApprovalBadCode
	}
	return nil
}

// An owner's own approval of a suppression rule through the real routes and
// database: never without a reason and a fresh authenticator code, only for
// a lone owner, refusals audited High, the approval audited Critical, and
// another organization reaches nothing (404).
func TestSuppressionSelfApproval_Routes_DB(t *testing.T) {
	changeAuditExtraHandlers = func(hs *Handlers, db *postgres.DB) {
		log := logger.NewNop()
		repo := postgres.NewSuppressionRepository(db)
		svc := suppression.NewService(repo, log)
		svc.SetApproverDirectory(repo)
		svc.SetTOTPVerifier(routeTOTP{good: "135790"})
		sh := handler.NewSuppressionHandler(svc, log)
		sh.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log))
		hs.Suppression = sh
	}
	t.Cleanup(func() { changeAuditExtraHandlers = nil })
	h := newChangeAuditHarness(t)
	solo, multi, lonelyAdminOrg, other := h.tenant(), h.tenant(), h.tenant(), h.tenant()
	t.Cleanup(func() {
		for _, id := range []string{solo, multi, lonelyAdminOrg, other} {
			h.exec(`DELETE FROM suppression_rules WHERE tenant_id = $1`, id)
		}
	})
	soloOwner := h.member(solo, "owner")
	multiOwner, multiAdmin := h.member(multi, "owner"), h.member(multi, "admin")
	lonelyAdmin := h.member(lonelyAdminOrg, "admin")
	otherOwner := h.member(other, "owner")

	create := func(u policyUser) (id, updatedAt string) {
		t.Helper()
		var rule struct {
			ID        string `json:"id"`
			UpdatedAt string `json:"updated_at"`
		}
		body := h.expect(u, http.MethodPost, "/api/v1/suppressions",
			`{"name":"test fixtures","suppression_type":"false_positive","rule_id":"go.test.fixture","expires_at":"`+
				time.Now().UTC().Add(30*24*time.Hour).Format(time.RFC3339)+`"}`, http.StatusCreated)
		if err := json.Unmarshal([]byte(body), &rule); err != nil || rule.ID == "" {
			t.Fatalf("create: %s", body)
		}
		// The approver reviews the stored version.
		body = h.expect(u, http.MethodGet, "/api/v1/suppressions/"+rule.ID, "", http.StatusOK)
		if err := json.Unmarshal([]byte(body), &rule); err != nil {
			t.Fatalf("get: %s", body)
		}
		return rule.ID, rule.UpdatedAt
	}
	approve := func(u policyUser, id, extra string, want int) {
		t.Helper()
		h.expect(u, http.MethodPost, "/api/v1/suppressions/"+id+"/approve", `{"reviewed_updated_at":"`+extra, want)
	}
	status := func(id string) string {
		var s string
		if err := h.db.QueryRowContext(context.Background(), `SELECT status FROM suppression_rules WHERE id = $1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	// A lone owner: no reason, no code, a wrong code are each refused and audited.
	id, ts := create(soloOwner)
	approve(soloOwner, id, ts+`"}`, http.StatusBadRequest)                                                          // no reason
	approve(soloOwner, id, ts+`","self_approval_reason":"only member"}`, http.StatusForbidden)                      // no code
	approve(soloOwner, id, ts+`","self_approval_reason":"only member","totp_code":"000000"}`, http.StatusForbidden) // wrong code
	// Another organization reaches nothing, even with a good code.
	approve(otherOwner, id, ts+`","self_approval_reason":"x","totp_code":"135790"}`, http.StatusNotFound)
	if s := status(id); s != "pending" {
		t.Fatalf("status %s after refused attempts, want pending", s)
	}
	refused := h.auditRows(solo, "suppression_rule.self_approval_refused")
	if len(refused) != 3 || refused[0].severity != "high" || refused[0].actor != soloOwner.id {
		t.Fatalf("refusals audited %+v, want 3 at high by the owner", refused)
	}
	if n := len(h.auditRows(other, "suppression_rule.")); n != 0 {
		t.Fatalf("tenant B got %d suppression audit rows", n)
	}
	approve(soloOwner, id, ts+`","self_approval_reason":"only member","totp_code":"135790"}`, http.StatusOK)
	if s := status(id); s != "approved" {
		t.Fatalf("status %s, want approved", s)
	}
	self := h.auditRows(solo, "suppression_rule.self_approved")
	if len(self) != 1 || self[0].severity != "critical" {
		t.Fatalf("self-approval audit %+v, want one critical", self)
	}

	// An owner with another approver may not approve their own rule, even
	// with a good code; the other approver may.
	id, ts = create(multiOwner)
	approve(multiOwner, id, ts+`","self_approval_reason":"x","totp_code":"135790"}`, http.StatusForbidden)
	if n := len(h.auditRows(multi, "suppression_rule.self_approval_refused")); n != 1 {
		t.Fatalf("refusal with a second approver audited %d times, want 1", n)
	}
	approve(multiAdmin, id, ts+`"}`, http.StatusOK)

	// Within 7 days of suspending a member, a lone owner may not approve
	// their own rule; after 7 days they may.
	recent := h.tenant()
	t.Cleanup(func() { h.exec(`DELETE FROM suppression_rules WHERE tenant_id = $1`, recent) })
	recentOwner := h.member(recent, "owner")
	suspended := h.member(recent, "admin")
	h.exec(`UPDATE tenant_members SET status = 'suspended', suspended_at = now() - interval '2 days' WHERE user_id = $1`, suspended.id)
	id, ts = create(recentOwner)
	code, body := h.do(recentOwner, http.MethodPost, "/api/v1/suppressions/"+id+"/approve",
		`{"reviewed_updated_at":"`+ts+`","self_approval_reason":"alone now","totp_code":"135790"}`)
	if code != http.StatusForbidden || !strings.Contains(body, "possible again from") {
		t.Fatalf("2 days after a suspension: %d %s", code, body)
	}
	if n := len(h.auditRows(recent, "suppression_rule.self_approval_refused")); n != 1 {
		t.Fatalf("refusal audited %d times, want 1", n)
	}
	h.exec(`UPDATE tenant_members SET suspended_at = now() - interval '8 days' WHERE user_id = $1`, suspended.id)
	approve(recentOwner, id, ts+`","self_approval_reason":"alone now","totp_code":"135790"}`, http.StatusOK)

	// A lone administrator who is not an owner may not.
	id, ts = create(lonelyAdmin)
	approve(lonelyAdmin, id, ts+`","self_approval_reason":"x","totp_code":"135790"}`, http.StatusForbidden)
	if s := status(id); s != "pending" {
		t.Fatalf("lone admin's rule %s, want pending", s)
	}
}
