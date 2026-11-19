package handler

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
)

type countingAdmitter struct{ calls int }

func (c *countingAdmitter) MembershipAdmission(_ context.Context, _, _ string) (map[string]error, error) {
	c.calls++
	return map[string]error{"org-1": nil}, nil
}

// The per-organization policy chain runs only for an account token (no
// organization claim); a token bound to an organization skips it.
func TestAddAdmission_OnlyForAnAccountToken(t *testing.T) {
	base := context.WithValue(context.Background(), middleware.SessionIDKey, "sess-1")

	t.Run("account token gets the admission", func(t *testing.T) {
		a := &countingAdmitter{}
		rows := []TenantMembershipResponse{{ID: "org-1"}}
		(&UserHandler{admission: a}).addAdmission(base, "user-1", rows)
		if a.calls != 1 || rows[0].Admission != admissionOpen {
			t.Fatalf("calls=%d admission=%q, want 1 and %q", a.calls, rows[0].Admission, admissionOpen)
		}
	})

	t.Run("organization token does not run the policy chain", func(t *testing.T) {
		a := &countingAdmitter{}
		rows := []TenantMembershipResponse{{ID: "org-1"}}
		ctx := context.WithValue(base, middleware.TenantIDKey, "org-1")
		(&UserHandler{admission: a}).addAdmission(ctx, "user-1", rows)
		if a.calls != 0 || rows[0].Admission != "" {
			t.Fatalf("calls=%d admission=%q, want none", a.calls, rows[0].Admission)
		}
	})
}
