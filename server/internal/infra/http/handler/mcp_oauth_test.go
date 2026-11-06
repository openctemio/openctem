package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcpoauthapp "github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Consent refusals map to stable statuses; nothing internal leaks.
func TestConsentErrorStatuses(t *testing.T) {
	h := &MCPOAuthHandler{log: logger.NewNop()}
	for err, want := range map[error]int{
		mcpoauthapp.ErrPolicy:                                 http.StatusForbidden,
		mcpoauthapp.ErrNothingToGrant:                         http.StatusForbidden,
		mcpoauthapp.ErrConsentUnavailable:                     http.StatusNotFound,
		fmt.Errorf("wrapped: %w", mcpoauthapp.ErrPolicy):      http.StatusForbidden,
		errors.New("pq: connection refused at 10.0.0.5:5432"): http.StatusInternalServerError,
	} {
		rec := httptest.NewRecorder()
		h.consentError(rec, err)
		if rec.Code != want {
			t.Errorf("%v: status %d, want %d", err, rec.Code, want)
		}
		if want == http.StatusInternalServerError && strings.Contains(rec.Body.String(), "10.0.0.5") {
			t.Error("internal detail leaked")
		}
	}
}

// Allowing access to all organization data: a stale session answers the
// step-up challenge the web dialog handles, a missing step-up check refuses,
// and a role without full data access is a plain 403.
func TestConsentErrorFullData(t *testing.T) {
	h := &MCPOAuthHandler{log: logger.NewNop()}
	for name, tc := range map[string]struct {
		err  error
		want int
		code string
	}{
		"stale session":  {fmt.Errorf("gate: %w", middleware.ErrStepUpRequired), http.StatusForbidden, "STEP_UP_REQUIRED"},
		"no step-up":     {mcpoauthapp.ErrFullDataStepUp, http.StatusForbidden, "STEP_UP_UNAVAILABLE"},
		"no full access": {mcpoauthapp.ErrFullDataNotAllowed, http.StatusForbidden, ""},
	} {
		rec := httptest.NewRecorder()
		h.consentError(rec, tc.err)
		if rec.Code != tc.want || (tc.code != "" && !strings.Contains(rec.Body.String(), tc.code)) {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
}
