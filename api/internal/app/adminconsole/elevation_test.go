package adminconsole

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
)

// A session elevates to a role no higher than the administrator's own, for
// 15 to 60 minutes, with a reason; the elevation is audited and ends on
// request or when its time is up (the session then acts as read-only).
func TestElevation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, token := h.enroll(t)
	_, sess, err := h.svc.AuthenticateSession(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if got := sess.ActingRole(h.clock); got != admin.AdminRoleReadonly {
		t.Fatalf("a fresh session acts as %s, want readonly", got)
	}
	for name, tc := range map[string]struct {
		role    admin.AdminRole
		minutes int
		reason  string
		want    error
	}{
		"readonly is not an elevation": {admin.AdminRoleReadonly, 30, "Support case 4411 follow-up", ErrElevationRole},
		"unknown role":                 {"root", 30, "Support case 4411 follow-up", ErrElevationRole},
		"too short":                    {admin.AdminRoleOpsAdmin, 5, "Support case 4411 follow-up", ErrElevationDuration},
		"too long":                     {admin.AdminRoleOpsAdmin, 90, "Support case 4411 follow-up", ErrElevationDuration},
		"no reason":                    {admin.AdminRoleOpsAdmin, 30, "fix", ErrElevationReason},
	} {
		if _, err := h.svc.Elevate(ctx, h.admin, sess, tc.role, time.Duration(tc.minutes)*time.Minute, tc.reason, client); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}

	until, err := h.svc.Elevate(ctx, h.admin, sess, admin.AdminRoleSuperAdmin, 30*time.Minute, "Rotate the platform IdP secret, ticket 77", client)
	if err != nil || !until.Equal(h.clock.Add(30*time.Minute)) {
		t.Fatalf("elevate: %v %v", until, err)
	}
	if !h.audit.has(ActionElevated) {
		t.Fatal("an elevation must be audited")
	}
	_, sess, _ = h.svc.AuthenticateSession(ctx, token)
	if got := sess.ActingRole(h.clock.Add(29 * time.Minute)); got != admin.AdminRoleSuperAdmin {
		t.Fatalf("during the elevation: %s", got)
	}
	if got := sess.ActingRole(h.clock.Add(31 * time.Minute)); got != admin.AdminRoleReadonly {
		t.Fatalf("after the elevation: %s", got)
	}
	if err := h.svc.EndElevation(ctx, h.admin, sess, client); err != nil {
		t.Fatal(err)
	}
	_, sess, _ = h.svc.AuthenticateSession(ctx, token)
	if got := sess.ActingRole(h.clock); got != admin.AdminRoleReadonly {
		t.Fatalf("after ending: %s", got)
	}
}

// An ops administrator can never elevate to super admin, and acting as a
// role never exceeds the administrator's own.
func TestElevationNeverAboveOwnRole(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_ = h.admin.UpdateRole(admin.AdminRoleOpsAdmin)
	_, token := h.enroll(t)
	_, sess, _ := h.svc.AuthenticateSession(ctx, token)
	if _, err := h.svc.Elevate(ctx, h.admin, sess, admin.AdminRoleSuperAdmin, 30*time.Minute, "Need super for a moment, ticket 9", client); !errors.Is(err, ErrElevationRole) {
		t.Fatalf("ops to super: %v", err)
	}
	h.admin.ActAs(admin.AdminRoleSuperAdmin)
	if h.admin.EffectiveRole() != admin.AdminRoleOpsAdmin || h.admin.Role() != admin.AdminRoleOpsAdmin {
		t.Fatalf("ActAs above own role: effective %s, own %s", h.admin.EffectiveRole(), h.admin.Role())
	}
	h.admin.ActAs(admin.AdminRoleReadonly)
	if h.admin.EffectiveRole() != admin.AdminRoleReadonly || h.admin.Role() != admin.AdminRoleOpsAdmin {
		t.Fatal("acting read-only must not change the persisted role")
	}
}
