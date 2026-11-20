package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/admin"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// A reason is optional, trimmed, and at most 1000 characters (counted as
// characters, not bytes).
func TestAdminActionReasonBounds(t *testing.T) {
	cases := []struct {
		name, raw, want string
		ok              bool
	}{
		{"none", "", "", true},
		{"blank", "   ", "", true},
		{"trimmed", "  lost phone \n", "lost phone", true},
		{"1000 characters", strings.Repeat("é", 1000), strings.Repeat("é", 1000), true},
		{"1000 after trimming", " " + strings.Repeat("a", 1000) + " ", strings.Repeat("a", 1000), true},
		{"1001 characters", strings.Repeat("a", 1001), "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			got, ok := adminActionReason(rec, c.raw)
			if ok != c.ok || got != c.want {
				t.Fatalf("got %q %v, want %q %v", got, ok, c.want, c.ok)
			}
			if !ok {
				assertReasonRefused(t, rec)
			}
		})
	}
}

// The body of an action with no other input: none, empty or {} is no
// reason; malformed JSON is refused.
func TestReadAdminActionReason(t *testing.T) {
	cases := []struct {
		name, body, want string
		ok               bool
	}{
		{"no body", "", "", true},
		{"empty object", "{}", "", true},
		{"reason", `{"reason":" drill "}`, "drill", true},
		{"malformed", `{"reason":`, "", false},
		{"too long", `{"reason":"` + strings.Repeat("a", 1001) + `"}`, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader(c.body))
			rec := httptest.NewRecorder()
			got, ok := readAdminActionReason(rec, req)
			if ok != c.ok || got != c.want {
				t.Fatalf("got %q %v, want %q %v", got, ok, c.want, c.ok)
			}
			if !ok && rec.Code != http.StatusBadRequest {
				t.Fatalf("refusal status = %d, want 400", rec.Code)
			}
		})
	}
}

func assertReasonRefused(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d %s, want 400", rec.Code, rec.Body.String())
	}
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body: %v %s", err, rec.Body.String())
	}
	if body.Code != string(apierror.BadRequest("").Code) || !strings.Contains(body.Message, "1000") {
		t.Fatalf("error body = %+v", body)
	}
}

var overLongReason = `{"reason":"` + strings.Repeat("a", 1001) + `"}`

// Every roster action refuses an over-long reason before anything else runs:
// the services and repository are nil here, so reaching them would panic, and
// the four-eyes gate is never asked (no approval is spent).
func TestRosterActionsRefuseOverLongReason(t *testing.T) {
	target := shared.NewID().String()
	gate := &fakeGate{}
	console := (&AdminConsoleHandler{logger: logger.NewNop()}).WithApprovals(gate)
	users := (&AdminUserHandler{logger: logger.NewNop()}).WithApprovals(gate)
	cases := []struct {
		name   string
		method string
		path   string
		body   string
		serve  http.HandlerFunc
	}{
		{"role change", http.MethodPatch, "/api/v1/admin/users/" + target,
			`{"role":"super_admin","reason":"` + strings.Repeat("a", 1001) + `"}`, users.Update},
		{"new administrator", http.MethodPost, "/api/v1/admin/administrators/",
			`{"email":"new@example.com","role":"super_admin","reason":"` + strings.Repeat("a", 1001) + `"}`, console.Provision},
		{"reset two-step", http.MethodPost, "/api/v1/admin/users/" + target + "/reset-credentials", overLongReason, console.ResetCredentials},
		{"break-glass test", http.MethodPost, "/api/v1/admin/users/" + target + "/break-glass-test", overLongReason, console.ConfirmBreakGlassTest},
		{"IdP unbind", http.MethodDelete, "/api/v1/admin/users/" + target + "/idp-binding", overLongReason, console.UnbindIdP},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c.serve(rec, withIDParam(superAdminRequest(t, c.method, c.path, c.body), target))
			assertReasonRefused(t, rec)
		})
	}
	if len(gate.calls) != 0 {
		t.Fatalf("the gate must not be asked: %v", gate.calls)
	}
}

// The reason reaches the four-eyes gate (its audit row keeps it); without one
// the action is gated as before.
func TestRosterActionsPassTheReasonToTheGate(t *testing.T) {
	target := shared.NewID()
	cases := []struct {
		name, body, want string
	}{
		{"with reason", `{"reason":"  lost phone, ticket 42 "}`, "lost phone, ticket 42"},
		{"no body", "", ""},
	}
	for _, c := range cases {
		t.Run("reset two-step "+c.name, func(t *testing.T) {
			gate := &fakeGate{err: &admin.ApprovalRequiredError{Action: admin.ApprovalResetCredentials, Target: "admin:" + target.String()}}
			h := (&AdminConsoleHandler{logger: logger.NewNop()}).WithApprovals(gate)
			rec := httptest.NewRecorder()
			h.ResetCredentials(rec, withIDParam(superAdminRequest(t, http.MethodPost,
				"/api/v1/admin/users/"+target.String()+"/reset-credentials", c.body), target.String()))
			if rec.Code != http.StatusPreconditionRequired {
				t.Fatalf("status = %d %s, want 428", rec.Code, rec.Body.String())
			}
			if len(gate.reasons) != 1 || gate.reasons[0] != c.want {
				t.Fatalf("gate reasons = %q, want %q", gate.reasons, c.want)
			}
		})
	}
	t.Run("new super admin", func(t *testing.T) {
		gate := &fakeGate{err: &admin.ApprovalRequiredError{Action: admin.ApprovalGrantSuperAdmin, Target: "email:new@example.com"}}
		h := (&AdminConsoleHandler{logger: logger.NewNop()}).WithApprovals(gate)
		rec := httptest.NewRecorder()
		h.Provision(rec, superAdminRequest(t, http.MethodPost, "/api/v1/admin/administrators/",
			`{"email":"new@example.com","role":"super_admin","reason":" second on-call lead "}`))
		if rec.Code != http.StatusPreconditionRequired {
			t.Fatalf("status = %d %s, want 428", rec.Code, rec.Body.String())
		}
		if len(gate.reasons) != 1 || gate.reasons[0] != "second on-call lead" {
			t.Fatalf("gate reasons = %q", gate.reasons)
		}
	})
}
