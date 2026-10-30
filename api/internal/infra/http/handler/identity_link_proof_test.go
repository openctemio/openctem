package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
)

// The proof travels in the body as step_up; an empty body is no proof (the
// service answers LINK_PROOF_REQUIRED) and a malformed one is a 400.
func TestDecodeLinkProof(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want auth.StepUpProof
		ok   bool
	}{
		"empty body": {"", auth.StepUpProof{}, true},
		"no proof":   {"{}", auth.StepUpProof{}, true},
		"code":       {`{"step_up":{"totp":"123456"}}`, auth.StepUpProof{TOTP: "123456"}, true},
		"password":   {`{"step_up":{"password":"pw"}}`, auth.StepUpProof{Password: "pw"}, true},
		"malformed":  {`{"step_up":`, auth.StepUpProof{}, false},
		"oversized":  {`{"step_up":{"password":"` + strings.Repeat("a", 5000) + `"}}`, auth.StepUpProof{}, false},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			got, ok := decodeLinkProof(rec, req)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("got %+v %v", got, ok)
			}
			if !ok && rec.Code != http.StatusBadRequest {
				t.Fatalf("status %d", rec.Code)
			}
		})
	}
}

// Only a missing or mistyped proof keeps the pending-link cookie for another
// try; every other answer (linked, locked, invalid) clears it.
func TestKeepsPendingLink(t *testing.T) {
	for err, want := range map[error]bool{
		auth.ErrLinkProofRequired:                          true,
		fmt.Errorf("wrapped: %w", auth.ErrLinkProofFailed): true,
		nil:                          false,
		auth.ErrAccountLocked:        false,
		auth.ErrLinkProofUnavailable: false,
		auth.ErrPendingLinkInvalid:   false,
		errors.New("db down"):        false,
	} {
		if got := keepsPendingLink(err); got != want {
			t.Errorf("%v: got %v", err, got)
		}
	}
}

// The proof refusals have their own codes, so the web client asks for the
// code or password in the confirm dialog instead of its step-up prompt.
func TestLinkProofErrorCodes(t *testing.T) {
	for err, code := range map[error]string{
		auth.ErrLinkProofRequired:    "LINK_PROOF_REQUIRED",
		auth.ErrLinkProofFailed:      "LINK_PROOF_FAILED",
		auth.ErrLinkProofUnavailable: "LINK_PROOF_UNAVAILABLE",
	} {
		en, ok := lookupAuthError(err)
		if !ok || string(en.Code) != code || en.Status != http.StatusForbidden {
			t.Errorf("%v: %+v %v", err, en, ok)
		}
	}
}
