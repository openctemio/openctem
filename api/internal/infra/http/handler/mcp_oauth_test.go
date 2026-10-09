package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcpoauthapp "github.com/openctemio/openctem/api/internal/app/mcpoauth"
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
