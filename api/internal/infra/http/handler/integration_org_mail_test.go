package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	integrationapp "github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Only an owner or administrator of the organization may turn organization
// mail on for a relay; the right to manage integrations is not enough.
func TestCanEnableOrgMail_OnlyOwnerOrAdmin(t *testing.T) {
	for role, want := range map[string]bool{"owner": true, "admin": true, "member": false, "viewer": false, "": false, "superuser": false} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/notifications", nil)
		r = r.WithContext(context.WithValue(r.Context(), middleware.TenantRoleKey, role))
		if got := canEnableOrgMail(r); got != want {
			t.Errorf("role %q: canEnableOrgMail = %v, want %v", role, got, want)
		}
	}
}

// A refused org-mail change answers 403 with a fixed sentence, and any other
// forbidden error answers 403 without the lower error's text.
func TestHandleServiceError_ForbiddenIsFixedText(t *testing.T) {
	h := &IntegrationHandler{}

	w := httptest.NewRecorder()
	h.handleServiceError(w, fmt.Errorf("update: %w", integrationapp.ErrOrgMailNeedsAdmin))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Only an owner or administrator") {
		t.Fatalf("org mail refusal = %d %s, want 403 with the fixed sentence", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	h.handleServiceError(w, fmt.Errorf("%w: relay host 10.0.0.7 tenant 42", shared.ErrForbidden))
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "10.0.0.7") {
		t.Fatalf("other forbidden = %d %s, want 403 without the lower error's text", w.Code, w.Body.String())
	}
}
