package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type refusingVerifier struct{ calls int }

func (v *refusingVerifier) StepUp(context.Context, *admin.AdminUser, string, string, adminconsole.ClientInfo) error {
	v.calls++
	return admin.ErrInvalidMFACode
}

// A handler-level step-up passes without a code inside the session's step-up
// window (opened by a security-key confirmation), and only then.
func TestConfirmAdminStepUpHonoursSessionWindow(t *testing.T) {
	now := time.Now()
	a := admin.Reconstitute(shared.NewID(), "a@x.io", "A", admin.AdminRoleSuperAdmin, true,
		nil, nil, "", 0, nil, nil, "", now, nil, now)
	recent := now.Add(-time.Minute)
	stale := now.Add(-admin.StepUpWindow - time.Second)
	for _, c := range []struct {
		name string
		at   *time.Time
		want bool
	}{
		{"inside the window", &recent, true},
		{"window expired", &stale, false},
		{"never stepped up", nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/settings/legal", nil)
			ctx := context.WithValue(r.Context(), middleware.AdminUserKey, a)
			ctx = context.WithValue(ctx, middleware.AdminSessionKey, &admin.Session{AdminID: a.ID(), MFAVerified: true, StepUpAt: c.at})
			v := &refusingVerifier{}
			rec := httptest.NewRecorder()
			got := confirmAdminStepUp(rec, r.WithContext(ctx), v, "", "test", logger.NewNop())
			if got != c.want {
				t.Fatalf("got %v want %v (%d %s)", got, c.want, rec.Code, rec.Body.String())
			}
			if !c.want && rec.Code != http.StatusUnauthorized {
				t.Fatalf("refusal: %d", rec.Code)
			}
		})
	}
}
