package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
)

// The platform relay receives every set-password, reset and invitation link:
// changing where mail goes is approved by a second super admin; rotating the
// password on the same relay, the sender and turning e-mail off are not.
func TestAdminEmailUpdateRelayNeedsSecondApproval(t *testing.T) {
	const path = "/api/v1/admin/settings/email"
	body := func(host string, port int, starttls bool, enabled bool, version int, pw string) map[string]any {
		b := map[string]any{"enabled": enabled, "host": host, "port": port, "username": "mailer",
			"from": "noreply@example.com", "from_name": "OpenCTEM", "starttls": starttls, "version": version, "totp_code": "123456"}
		if pw != "" {
			b["password"] = pw
		}
		return b
	}
	needApproval := &admin.ApprovalRequiredError{Action: admin.ApprovalPlatformEmailRelay}
	put := func(h *AdminEmailHandler, b map[string]any) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.Update(rec, emailRequest(t, http.MethodPut, path, b))
		return rec
	}

	t.Run("first relay: 428 and nothing is saved", func(t *testing.T) {
		gate := &fakeGate{err: needApproval}
		h := newEmailHandler(t, nil).WithApprovals(gate)
		rec := put(h, body("smtp.example.com", 587, true, true, 0, "pw"))
		if rec.Code != http.StatusPreconditionRequired || !strings.Contains(rec.Body.String(), "SECOND_APPROVAL_REQUIRED") {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
		if len(gate.calls) != 1 || !strings.HasPrefix(gate.calls[0], "platform_email.relay ") {
			t.Fatalf("gate calls %v", gate.calls)
		}
		target := strings.TrimPrefix(gate.calls[0], "platform_email.relay ")
		if !admin.ApprovalPlatformEmailRelay.ValidTarget(target) || strings.Contains(target, "pw") {
			t.Fatalf("target %q", target)
		}
		rec = httptest.NewRecorder()
		h.Get(rec, emailRequest(t, http.MethodGet, path, nil))
		if !strings.Contains(rec.Body.String(), `"version":0`) {
			t.Fatalf("nothing may be stored: %s", rec.Body.String())
		}
	})

	t.Run("approved relay saves; the rest stays one-person", func(t *testing.T) {
		gate := &fakeGate{}
		h := newEmailHandler(t, nil).WithApprovals(gate)
		if rec := put(h, body("smtp.example.com", 587, true, true, 0, "pw")); rec.Code != http.StatusOK || len(gate.calls) != 1 {
			t.Fatalf("first %d calls %v", rec.Code, gate.calls)
		}
		gate.err = needApproval
		// Password rotation on the same relay: no gate call, saved.
		if rec := put(h, body("smtp.example.com", 587, true, true, 1, "pw2")); rec.Code != http.StatusOK || len(gate.calls) != 1 {
			t.Fatalf("rotation %d calls %v", rec.Code, gate.calls)
		}
		// New host, new port, TLS downgrade: each refused with 428.
		for name, b := range map[string]map[string]any{
			"host":      body("smtp.attacker.example", 587, true, true, 2, ""),
			"port":      body("smtp.example.com", 25, true, true, 2, ""),
			"downgrade": body("smtp.example.com", 587, false, true, 2, ""),
		} {
			if rec := put(h, b); rec.Code != http.StatusPreconditionRequired {
				t.Fatalf("%s: status %d %s", name, rec.Code, rec.Body.String())
			}
		}
		// Turning e-mail off never asks.
		calls := len(gate.calls)
		if rec := put(h, body("smtp.example.com", 587, true, false, 2, "")); rec.Code != http.StatusOK || len(gate.calls) != calls {
			t.Fatalf("off %d calls %v", rec.Code, gate.calls)
		}
	})

	t.Run("a failed save hands the approval back", func(t *testing.T) {
		gate := &fakeGate{}
		h := newEmailHandler(t, nil).WithApprovals(gate)
		if rec := put(h, body("smtp.example.com", 587, true, true, 9, "pw")); rec.Code != http.StatusConflict || gate.released != 1 {
			t.Fatalf("status %d released %d", rec.Code, gate.released)
		}
	})
}
