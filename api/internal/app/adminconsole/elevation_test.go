package adminconsole

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
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
		role    string
		minutes int
		reason  string
		want    error
	}{
		"readonly is not an elevation": {string(admin.AdminRoleReadonly), 30, "Support case 4411 follow-up", ErrElevationRole},
		"unknown role":                 {"root", 30, "Support case 4411 follow-up", ErrElevationRole},
		"too short":                    {string(admin.AdminRoleOpsAdmin), 5, "Support case 4411 follow-up", ErrElevationDuration},
		"too long":                     {string(admin.AdminRoleOpsAdmin), 90, "Support case 4411 follow-up", ErrElevationDuration},
		"no reason":                    {string(admin.AdminRoleOpsAdmin), 30, "fix", ErrElevationReason},
	} {
		if _, err := h.svc.Elevate(ctx, h.admin, sess, tc.role, time.Duration(tc.minutes)*time.Minute, tc.reason, client); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}

	until, err := h.svc.Elevate(ctx, h.admin, sess, string(admin.AdminRoleSuperAdmin), 30*time.Minute, "Rotate the platform IdP secret, ticket 77", client)
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
	if _, err := h.svc.Elevate(ctx, h.admin, sess, string(admin.AdminRoleSuperAdmin), 30*time.Minute, "Need super for a moment, ticket 9", client); !errors.Is(err, ErrElevationRole) {
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

// With the audit log unavailable the elevation is refused and the session
// stays read-only: a grant never exists without its record.
func TestElevationFailsClosedWhenAuditIsUnavailable(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, token := h.enroll(t)
	_, sess, err := h.svc.AuthenticateSession(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	h.audit.fail = true
	_, err = h.svc.Elevate(ctx, h.admin, sess, string(admin.AdminRoleSuperAdmin), 30*time.Minute, "Rotate the platform IdP secret, ticket 77", client)
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("elevate with a failing audit log: %v, want ErrAuditUnavailable", err)
	}
	h.audit.fail = false
	_, sess, _ = h.svc.AuthenticateSession(ctx, token)
	if got := sess.ActingRole(h.clock); got != admin.AdminRoleReadonly {
		t.Fatalf("the session acts as %s after a refused elevation, want readonly", got)
	}
}

// Elevation names a platform role (RFC-134): an owner may act as support
// (read-only tier, support's permissions), and a read-only administrator who
// also holds the support role may act as support but never as an admin.
func TestElevationByPlatformRole(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, token := h.enroll(t)
	_, sess, _ := h.svc.AuthenticateSession(ctx, token)
	if _, err := h.svc.Elevate(ctx, h.admin, sess, string(platformauthz.RoleSupport), 30*time.Minute, "Customer sign-in case 512", client); err != nil {
		t.Fatalf("owner as support: %v", err)
	}
	_, sess, _ = h.svc.AuthenticateSession(ctx, token)
	if got := sess.ElevatedAs(h.clock); got != platformauthz.RoleSupport {
		t.Fatalf("elevated as %q, want support", got)
	}
	if got := sess.ActingRole(h.clock); got != admin.AdminRoleReadonly {
		t.Fatalf("support acts at the read-only tier, got %s", got)
	}

	_ = h.admin.UpdateRole(admin.AdminRoleReadonly)
	h.admin.SetPlatformAccess([]platformauthz.RoleKey{platformauthz.RoleViewer, platformauthz.RoleSupport}, nil)
	if _, err := h.svc.Elevate(ctx, h.admin, sess, string(platformauthz.RoleSupport), 30*time.Minute, "Customer sign-in case 513", client); err != nil {
		t.Fatalf("support holder as support: %v", err)
	}
	for _, target := range []string{"platform_admin", "ops_admin", "super_admin", "operator", "platform_viewer"} {
		if _, err := h.svc.Elevate(ctx, h.admin, sess, target, 30*time.Minute, "Customer sign-in case 514", client); !errors.Is(err, ErrElevationRole) {
			t.Errorf("support holder as %s: %v, want ErrElevationRole", target, err)
		}
	}
}
