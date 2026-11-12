package unit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// stepUpReason is the reason recorded on the latest auth.step_up_failed event.
func stepUpReason(t *testing.T, h *mfaHarness) string {
	t.Helper()
	l := h.lastLog(audit.ActionAuthStepUpFailed)
	if l == nil {
		t.Fatal("no auth.step_up_failed event")
	}
	r, _ := l.Metadata()["reason"].(string)
	return r
}

// A refused step-up says why in its audit event (invalid code, a code from a
// step already used, an unreadable secret), never what was typed; a code
// pasted with a separator is the same code; an unreadable secret is a server
// fault that does not count towards the lockout.
func TestStepUp_FailureReasons(t *testing.T) {
	ctx := context.Background()
	actx := auditsvc.AuditContext{}

	t.Run("wrong code: invalid_code, the code is not recorded", func(t *testing.T) {
		h, sess := newLinkProofHarness(t)
		id := h.seedUser(t, "a@example.com")
		secret, _ := h.enroll(t, id)
		h.forgetLastStep(id)
		sid := sess.signIn()
		bad := wrongCode(currentCode(t, secret))
		_, err := h.svc.StepUp(ctx, actx, id.String(), sid, authapp.StepUpProof{TOTP: bad})
		if !errors.Is(err, authapp.ErrStepUpFailed) || errors.Is(err, authapp.ErrStepUpCodeReused) {
			t.Fatalf("wrong code: %v", err)
		}
		if got := stepUpReason(t, h); got != authapp.StepUpReasonInvalidCode {
			t.Fatalf("reason %q", got)
		}
		l := h.lastLog(audit.ActionAuthStepUpFailed)
		if dump := fmt.Sprintf("%v %s", l.Metadata(), l.Message()); strings.Contains(dump, bad) {
			t.Fatal("the audit event records the typed code")
		}
	})

	t.Run("a code used once is refused as replayed_code", func(t *testing.T) {
		h, sess := newLinkProofHarness(t)
		id := h.seedUser(t, "b@example.com")
		secret, _ := h.enroll(t, id)
		h.forgetLastStep(id)
		sid := sess.signIn()
		code := currentCode(t, secret)
		if _, err := h.svc.StepUp(ctx, actx, id.String(), sid, authapp.StepUpProof{TOTP: code}); err != nil {
			t.Fatalf("first use: %v", err)
		}
		_, err := h.svc.StepUp(ctx, actx, id.String(), sid, authapp.StepUpProof{TOTP: code})
		if !errors.Is(err, authapp.ErrStepUpCodeReused) || !errors.Is(err, authapp.ErrStepUpFailed) {
			t.Fatalf("second use: %v", err)
		}
		if got := stepUpReason(t, h); got != authapp.StepUpReasonReplayedCode {
			t.Fatalf("reason %q", got)
		}
	})

	t.Run("a code typed with a dash or spaces is accepted", func(t *testing.T) {
		h, sess := newLinkProofHarness(t)
		id := h.seedUser(t, "c@example.com")
		secret, _ := h.enroll(t, id)
		h.forgetLastStep(id)
		sid := sess.signIn()
		code := currentCode(t, secret)
		if _, err := h.svc.StepUp(ctx, actx, id.String(), sid, authapp.StepUpProof{TOTP: " " + code[:3] + "-" + code[3:] + " "}); err != nil {
			t.Fatalf("dashed code: %v", err)
		}
	})

	t.Run("unreadable secret: decrypt_error, not a wrong code, no lockout", func(t *testing.T) {
		h, sess := newLinkProofHarness(t)
		id := h.seedUser(t, "d@example.com")
		secret, _ := h.enroll(t, id)
		h.forgetLastStep(id)
		h.mfa.mu.Lock()
		h.mfa.factors[id.String()].SecretEncrypted = "not-a-ciphertext"
		h.mfa.mu.Unlock()
		sid := sess.signIn()
		for range 12 {
			_, err := h.svc.StepUp(ctx, actx, id.String(), sid, authapp.StepUpProof{TOTP: currentCode(t, secret)})
			if !errors.Is(err, authapp.ErrStepUpSecretUnreadable) || errors.Is(err, authapp.ErrStepUpFailed) {
				t.Fatalf("unreadable secret: %v", err)
			}
		}
		if got := stepUpReason(t, h); got != authapp.StepUpReasonDecryptError {
			t.Fatalf("reason %q", got)
		}
		u, err := h.users.GetByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if u.IsLocked() || u.FailedLoginAttempts() != 0 {
			t.Fatalf("a server fault counted towards the lockout: locked=%v attempts=%d", u.IsLocked(), u.FailedLoginAttempts())
		}
	})

	t.Run("wrong password: invalid_password", func(t *testing.T) {
		h, sess := newLinkProofHarness(t)
		id := h.seedUser(t, "e@example.com")
		sid := sess.signIn()
		if _, err := h.svc.StepUp(ctx, actx, id.String(), sid, authapp.StepUpProof{Password: "wrong-password"}); !errors.Is(err, authapp.ErrStepUpFailed) {
			t.Fatalf("wrong password: %v", err)
		}
		if got := stepUpReason(t, h); got != authapp.StepUpReasonInvalidPassword {
			t.Fatalf("reason %q", got)
		}
	})

	t.Run("reason mapping", func(t *testing.T) {
		cases := []struct {
			err    error
			method authapp.StepUpMethod
			want   string
		}{
			{authapp.ErrStepUpFailed, authapp.StepUpTOTP, authapp.StepUpReasonInvalidCode},
			{authapp.ErrStepUpCodeReused, authapp.StepUpTOTP, authapp.StepUpReasonReplayedCode},
			{authapp.ErrAccountLocked, authapp.StepUpTOTP, authapp.StepUpReasonAccountLocked},
			{authapp.ErrStepUpNoFactor, authapp.StepUpTOTP, authapp.StepUpReasonNoTOTPFactor},
			{authapp.ErrStepUpSecretUnreadable, authapp.StepUpTOTP, authapp.StepUpReasonDecryptError},
			{authapp.ErrStepUpRequired, authapp.StepUpTOTP, ""},
			{errors.New("db down"), authapp.StepUpTOTP, ""},
		}
		for _, c := range cases {
			if got := authapp.StepUpFailureReason(c.err, c.method); got != c.want {
				t.Errorf("%v: %q, want %q", c.err, got, c.want)
			}
		}
		if !errors.Is(authapp.ErrStepUpNoFactor, authapp.ErrStepUpRequired) {
			t.Error("no factor must still ask for a proof (ErrStepUpRequired)")
		}
	})
}

// POST /auth/step-up tells a reused code (STEP_UP_CODE_USED) from a wrong
// one (STEP_UP_FAILED), so the person is told to wait for the next code.
func TestStepUpHandler_ReusedCodeHasItsOwnCode(t *testing.T) {
	h, sess := newLinkProofHarness(t)
	id := h.seedUser(t, "f@example.com")
	secret, _ := h.enroll(t, id)
	h.forgetLastStep(id)
	sid := sess.signIn()
	hd := handler.NewLocalAuthHandler(h.svc, nil, nil, config.AuthConfig{}, logger.NewNop())

	post := func(code string) (int, string) {
		body, _ := json.Marshal(map[string]string{"totp": code})
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/auth/step-up", bytes.NewReader(body))
		c := context.WithValue(req.Context(), middleware.UserIDKey, id.String())
		c = context.WithValue(c, middleware.SessionIDKey, sid)
		rec := httptest.NewRecorder()
		hd.StepUp(rec, req.WithContext(c))
		var out struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out.Code
	}

	code := currentCode(t, secret)
	if st, _ := post(wrongCode(code)); st != http.StatusForbidden {
		t.Fatalf("wrong code status %d", st)
	}
	if st, c := post(wrongCode(code)); st != http.StatusForbidden || c != handler.CodeStepUpFailed {
		t.Fatalf("wrong code: %d %q", st, c)
	}
	if st, _ := post(code); st != http.StatusOK {
		t.Fatalf("right code: %d", st)
	}
	if st, c := post(code); st != http.StatusForbidden || c != handler.CodeStepUpCodeUsed {
		t.Fatalf("reused code: %d %q", st, c)
	}
}

// A step-up refused by the rate limit is audited once per user per minute
// (reason rate_limited); a request the limit lets through is not.
func TestStepUpRateLimit_Audited(t *testing.T) {
	h, _ := newLinkProofHarness(t)
	hd := handler.NewLocalAuthHandler(h.svc, nil, nil, config.AuthConfig{}, logger.NewNop())
	refuse := true
	limit := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if refuse {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	reached := 0
	chain := hd.AuditStepUpRateLimit(limit)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusTooManyRequests) // the handler's own answer is not a limit refusal
	}))
	uid := shared.NewID().String()
	call := func() int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/auth/step-up", nil)
		req = req.WithContext(context.WithValue(req.Context(), middleware.UserIDKey, uid))
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		return rec.Code
	}
	for range 5 {
		if c := call(); c != http.StatusTooManyRequests {
			t.Fatalf("status %d", c)
		}
	}
	if n := h.audits.count(audit.ActionAuthStepUpFailed); n != 1 {
		t.Fatalf("rate-limit audit rows: %d, want 1 per minute", n)
	}
	if got := stepUpReason(t, h); got != authapp.StepUpReasonRateLimited {
		t.Fatalf("reason %q", got)
	}
	refuse = false
	call()
	if reached != 1 || h.audits.count(audit.ActionAuthStepUpFailed) != 1 {
		t.Fatalf("a request let through was audited as rate limited (reached %d)", reached)
	}
}

// New authenticator entries carry the host so two installations can be told
// apart; a port or a broken URL never leaks into the label.
func TestMFAIssuer(t *testing.T) {
	cases := map[string]string{
		"https://app.example.com":        "OpenCTEM (app.example.com)",
		"https://App.Example.com:8443/x": "OpenCTEM (app.example.com)",
		"https://192.168.1.10:8443":      "OpenCTEM (192.168.1.10)",
		"":                               "OpenCTEM",
		"::not a url":                    "OpenCTEM",
		"https://[2001:db8::1]:443/":     "OpenCTEM",
		"https://staging.example.com./":  "OpenCTEM (staging.example.com)",
	}
	for in, want := range cases {
		if got := authapp.MFAIssuer("OpenCTEM", in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if got := authapp.MFAIssuer(" ", "https://a.example"); got != authapp.DefaultMFAIssuer+" (a.example)" {
		t.Errorf("blank name: %q", got)
	}
}
