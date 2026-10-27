package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
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
