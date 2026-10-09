package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
)

// codeTOTP accepts one code, once (a used code cannot be replayed).
type codeTOTP struct{ used map[string]bool }

func (c *codeTOTP) VerifyFreshTOTP(_ context.Context, userID, code string) error {
	if code != "123456" || c.used[userID] {
		return scopedom.ErrSelfApprovalBadCode
	}
	c.used[userID] = true
	return nil
}

func approvalOf(t *testing.T, body string) map[string]any {
	t.Helper()
	var out struct {
		Approval map[string]any `json:"approval"`
		InEffect bool           `json:"in_effect"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out.Approval
}

// Through the real routes and database (RFC-054 §12.2, §12.3): a pending
// entry names who can approve it; the only owner approves their own T2 entry
// with a fresh code; nobody else self-approves while another approver
// exists; reminders are rate-limited; another organization reaches nothing.
func TestScopeApprovers_Routes_DB(t *testing.T) {
	totp := &codeTOTP{used: map[string]bool{}}
	h := newChangeAuditHarness(t, func(s *scopeapp.Service, db *postgres.DB) {
		s.SetApprovers(postgres.NewScopeActorRepository(db), totp, nil, nil, "")
	})

	// A single-owner organization: a T2 entry waits for one approval and
	// nobody else can give it.
	solo := h.tenant()
	owner := h.member(solo, "owner")
	id := decodeID(t, h.expect(owner, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"t2.solo.example.com","max_tier":"t2","expires_in_days":3,"reason":"pentest window"}`, http.StatusCreated))
	base := "/api/v1/scope/targets/" + id
	ap := approvalOf(t, h.expect(owner, http.MethodGet, base, "", http.StatusOK))
	if ap == nil || ap["eligible_approver_count"] != float64(0) || ap["self_approval_available"] != true || ap["remaining"] != float64(1) {
		t.Fatalf("single owner's pending T2 entry: approval %v", ap)
	}
	h.expect(owner, http.MethodPost, base+"/approve", "", http.StatusForbidden) // the requester
	h.expect(owner, http.MethodPost, base+"/self-approve", `{"reason":"","totp_code":"123456"}`, http.StatusUnprocessableEntity)
	h.expect(owner, http.MethodPost, base+"/self-approve", `{"reason":"only owner","totp_code":"000000"}`, http.StatusForbidden)

	// Another organization's owner reaches nothing.
	other := h.tenant()
	stranger := h.member(other, "owner")
	h.expect(stranger, http.MethodPost, base+"/self-approve", `{"reason":"x","totp_code":"123456"}`, http.StatusNotFound)
	h.expect(stranger, http.MethodPost, base+"/remind", "", http.StatusNotFound)
	h.expect(stranger, http.MethodGet, base, "", http.StatusNotFound)

	body := h.expect(owner, http.MethodPost, base+"/self-approve", `{"reason":"only owner, pentest window","totp_code":"123456"}`, http.StatusOK)
	var got struct {
		InEffect  bool `json:"in_effect"`
		Approvals []struct {
			SelfApproved bool   `json:"self_approved"`
			Reason       string `json:"reason"`
		} `json:"approvals"`
	}
	_ = json.Unmarshal([]byte(body), &got)
	if !got.InEffect || len(got.Approvals) != 1 || !got.Approvals[0].SelfApproved || got.Approvals[0].Reason == "" {
		t.Fatalf("self-approved entry: %s", body)
	}
	requireAudited(t, h.auditRows(solo, "scope_target.self_approved"), id, []auditRow{
		{action: "scope_target.self_approved", actor: owner.id, severity: "high",
			before: map[string]any{"status": "pending"}, after: map[string]any{"status": "active", "in_effect": true}},
	})

	// Two administrators: the requester never self-approves, the approvers
	// are named, and reminders wait an hour.
	org := h.tenant()
	o2, admin, member := h.member(org, "owner"), h.member(org, "admin"), h.member(org, "member")
	id2 := decodeID(t, h.expect(admin, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"*.pair.example.com"}`, http.StatusCreated))
	base2 := "/api/v1/scope/targets/" + id2
	ap = approvalOf(t, h.expect(o2, http.MethodGet, base2, "", http.StatusOK))
	names, _ := ap["eligible_approvers"].([]any)
	if ap["eligible_approver_count"] != float64(1) || len(names) != 1 || names[0].(map[string]any)["id"] != o2.id {
		t.Fatalf("approvers of an administrator's entry: %v, want only the owner", ap)
	}
	if ap["self_approval_available"] != false {
		t.Fatal("self-approval offered while another approver exists")
	}
	h.expect(admin, http.MethodPost, base2+"/self-approve", `{"reason":"hurry","totp_code":"123456"}`, http.StatusForbidden)
	h.expect(o2, http.MethodPost, base2+"/self-approve", `{"reason":"hurry","totp_code":"123456"}`, http.StatusForbidden)
	h.expect(member, http.MethodPost, base2+"/self-approve", `{"reason":"x","totp_code":"123456"}`, http.StatusForbidden)
	h.expect(admin, http.MethodPost, base2+"/remind", "", http.StatusOK)
	h.expect(member, http.MethodPost, base2+"/remind", "", http.StatusTooManyRequests)
	if ap := approvalOf(t, h.expect(member, http.MethodGet, base2, "", http.StatusOK)); ap["can_remind_at"] == nil {
		t.Fatalf("no next reminder time after a reminder: %v", ap)
	}
	h.expect(o2, http.MethodPost, base2+"/approve", "", http.StatusOK)
	h.expect(admin, http.MethodPost, base2+"/remind", "", http.StatusConflict) // not pending any more
}
