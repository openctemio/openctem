package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app"
	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// resetTenantRepo answers membership lookups from a real list of memberships,
// so the reset's per-organization authority checks run against data.
type resetTenantRepo struct {
	*mockAuthTenantRepo
	ms []*tenant.Membership
}

func (r *resetTenantRepo) GetMembership(_ context.Context, userID, tenantID shared.ID) (*tenant.Membership, error) {
	for _, m := range r.ms {
		if m.UserID() == userID && m.TenantID() == tenantID {
			return m, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (r *resetTenantRepo) GetMembershipByID(_ context.Context, tenantID, id shared.ID) (*tenant.Membership, error) {
	for _, m := range r.ms {
		if m.ID() == id && m.TenantID() == tenantID {
			return m, nil
		}
	}
	return nil, shared.ErrNotFound
}

func (r *resetTenantRepo) GetUserMembershipsWithStatus(_ context.Context, userID shared.ID) (*tenant.UserMembershipsByStatus, error) {
	out := &tenant.UserMembershipsByStatus{}
	for _, m := range r.ms {
		if m.UserID() != userID {
			continue
		}
		um := tenant.UserMembership{TenantID: m.TenantID().String(), Role: m.Role().String()}
		if m.IsSuspended() {
			out.Suspended = append(out.Suspended, um)
		} else {
			out.Active = append(out.Active, um)
		}
	}
	return out, nil
}

type resetHarness struct {
	*mfaHarness
	tenants *resetTenantRepo
	orgA    shared.ID
	orgB    shared.ID
}

func newResetHarness(t *testing.T) *resetHarness {
	t.Helper()
	base := newMFAHarness(t)
	tenants := &resetTenantRepo{mockAuthTenantRepo: newMockAuthTenantRepo()}
	svc := app.NewAuthService(base.users, base.sessions, newMockAuthRefreshTokenRepo(), tenants, auditsvc.NewAuditService(base.audits, logger.NewNop()), defaultAuthTestConfig(), logger.NewNop())
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	svc.SetMFA(base.mfa, cipher, "OpenCTEM")
	svc.SetSessionRevocationStore(base.revocations)
	svc.SetSecurityNotifier(base.notifier)
	base.svc = svc
	return &resetHarness{mfaHarness: base, tenants: tenants, orgA: shared.NewID(), orgB: shared.NewID()}
}

func (h *resetHarness) join(t *testing.T, userID, org shared.ID, role tenant.Role) *tenant.Membership {
	t.Helper()
	m, err := tenant.NewMembership(userID, org, role, nil)
	if err != nil {
		t.Fatalf("NewMembership: %v", err)
	}
	h.tenants.ms = append(h.tenants.ms, m)
	return m
}

// enrolledUser creates a password user with 2FA on and one live session.
func (h *resetHarness) enrolledUser(t *testing.T, email string) (shared.ID, *session.Session) {
	t.Helper()
	uid := h.seedUser(t, email)
	h.enroll(t, uid)
	sess, err := session.New(uid, "tok-"+email, "10.0.0.1", "Browser", 24*time.Hour)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	h.sessions.sessions[sess.ID().String()] = sess
	return uid, sess
}

func (h *resetHarness) reset(actor shared.ID, org shared.ID, target *tenant.Membership) error {
	return h.svc.ResetMemberMFA(context.Background(), auditsvc.AuditContext{ActorID: actor.String()}, org.String(), target.ID().String())
}

func (h *resetHarness) mfaOn(t *testing.T, uid shared.ID) bool {
	t.Helper()
	st, err := h.svc.GetMFAStatus(context.Background(), uid.String())
	if err != nil {
		t.Fatalf("GetMFAStatus: %v", err)
	}
	return st.Enabled
}

func TestResetMemberMFA(t *testing.T) {
	t.Run("an admin resets a member: factor gone, sessions revoked, audited, notified", func(t *testing.T) {
		h := newResetHarness(t)
		admin := h.seedUser(t, "admin@a.test")
		h.join(t, admin, h.orgA, tenant.RoleAdmin)
		uid, sess := h.enrolledUser(t, "member@a.test")
		target := h.join(t, uid, h.orgA, tenant.RoleMember)
		notified := h.notifier.mfaDisabled

		if err := h.reset(admin, h.orgA, target); err != nil {
			t.Fatalf("ResetMemberMFA: %v", err)
		}
		if h.mfaOn(t, uid) {
			t.Fatal("2FA still on after reset")
		}
		if h.sessions.sessions[sess.ID().String()].IsActive() || !h.revocations.has(sess.ID().String()) {
			t.Error("the member's session was not revoked")
		}
		if !h.audits.has(audit.ActionAuthMFAReset) {
			t.Error("reset was not audited")
		}
		if h.notifier.mfaDisabled != notified+1 {
			t.Error("the member was not notified")
		}
		if res := h.login(t, "member@a.test"); res.MFAChallenge != nil {
			t.Error("login still asks for a code after the reset")
		}
	})

	t.Run("a membership of another organization is not found", func(t *testing.T) {
		h := newResetHarness(t)
		admin := h.seedUser(t, "admin@a.test")
		h.join(t, admin, h.orgA, tenant.RoleAdmin)
		uid, _ := h.enrolledUser(t, "member@b.test")
		target := h.join(t, uid, h.orgB, tenant.RoleMember)

		if err := h.reset(admin, h.orgA, target); !errors.Is(err, shared.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
		if !h.mfaOn(t, uid) {
			t.Fatal("cross-organization reset turned 2FA off")
		}
	})

	t.Run("an admin cannot reset the owner or another admin; the owner can", func(t *testing.T) {
		h := newResetHarness(t)
		admin := h.seedUser(t, "admin@a.test")
		h.join(t, admin, h.orgA, tenant.RoleAdmin)
		ownerID, _ := h.enrolledUser(t, "owner@a.test")
		ownerM := h.join(t, ownerID, h.orgA, tenant.RoleOwner)
		peerID, _ := h.enrolledUser(t, "peer@a.test")
		peerM := h.join(t, peerID, h.orgA, tenant.RoleAdmin)

		for _, target := range []*tenant.Membership{ownerM, peerM} {
			if err := h.reset(admin, h.orgA, target); !errors.Is(err, shared.ErrForbidden) {
				t.Fatalf("admin -> %s: want ErrForbidden, got %v", target.Role(), err)
			}
		}
		if !h.mfaOn(t, ownerID) || !h.mfaOn(t, peerID) {
			t.Fatal("a refused reset changed 2FA")
		}
		if err := h.reset(ownerID, h.orgA, peerM); err != nil {
			t.Fatalf("owner -> admin: %v", err)
		}
	})

	t.Run("nobody resets their own factor here", func(t *testing.T) {
		h := newResetHarness(t)
		ownerID, _ := h.enrolledUser(t, "owner@a.test")
		ownerM := h.join(t, ownerID, h.orgA, tenant.RoleOwner)
		if err := h.reset(ownerID, h.orgA, ownerM); !errors.Is(err, app.ErrMFAResetSelf) {
			t.Fatalf("want ErrMFAResetSelf, got %v", err)
		}
	})

	t.Run("a member or viewer cannot reset anyone", func(t *testing.T) {
		h := newResetHarness(t)
		member := h.seedUser(t, "m@a.test")
		h.join(t, member, h.orgA, tenant.RoleMember)
		uid, _ := h.enrolledUser(t, "v@a.test")
		target := h.join(t, uid, h.orgA, tenant.RoleViewer)
		if err := h.reset(member, h.orgA, target); !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("want ErrForbidden, got %v", err)
		}
	})

	t.Run("a target who also belongs to another organization needs the same authority there", func(t *testing.T) {
		h := newResetHarness(t)
		admin := h.seedUser(t, "admin@a.test")
		h.join(t, admin, h.orgA, tenant.RoleAdmin)
		uid, _ := h.enrolledUser(t, "both@x.test")
		target := h.join(t, uid, h.orgA, tenant.RoleMember)
		h.join(t, uid, h.orgB, tenant.RoleOwner) // owns organization B

		if err := h.reset(admin, h.orgA, target); !errors.Is(err, app.ErrMFAResetOtherOrganization) {
			t.Fatalf("want ErrMFAResetOtherOrganization, got %v", err)
		}
		if !h.mfaOn(t, uid) {
			t.Fatal("refused reset turned 2FA off")
		}

		// Holding admin in B is still not enough for B's owner...
		h.join(t, admin, h.orgB, tenant.RoleAdmin)
		if err := h.reset(admin, h.orgA, target); !errors.Is(err, app.ErrMFAResetOtherOrganization) {
			t.Fatalf("admin of B vs owner of B: want ErrMFAResetOtherOrganization, got %v", err)
		}
	})

	t.Run("a suspended membership elsewhere still counts", func(t *testing.T) {
		h := newResetHarness(t)
		admin := h.seedUser(t, "admin@a.test")
		h.join(t, admin, h.orgA, tenant.RoleAdmin)
		uid, _ := h.enrolledUser(t, "both@x.test")
		target := h.join(t, uid, h.orgA, tenant.RoleMember)
		other := h.join(t, uid, h.orgB, tenant.RoleMember)
		if err := other.Suspend(shared.NewID()); err != nil {
			t.Fatalf("Suspend: %v", err)
		}
		if err := h.reset(admin, h.orgA, target); !errors.Is(err, app.ErrMFAResetOtherOrganization) {
			t.Fatalf("want ErrMFAResetOtherOrganization, got %v", err)
		}
	})

	t.Run("an admin of both organizations may reset a member of both", func(t *testing.T) {
		h := newResetHarness(t)
		admin := h.seedUser(t, "admin@a.test")
		h.join(t, admin, h.orgA, tenant.RoleAdmin)
		h.join(t, admin, h.orgB, tenant.RoleAdmin)
		uid, _ := h.enrolledUser(t, "both@x.test")
		target := h.join(t, uid, h.orgA, tenant.RoleMember)
		h.join(t, uid, h.orgB, tenant.RoleViewer)
		if err := h.reset(admin, h.orgA, target); err != nil {
			t.Fatalf("ResetMemberMFA: %v", err)
		}
	})

	t.Run("a suspended admin cannot reset", func(t *testing.T) {
		h := newResetHarness(t)
		admin := h.seedUser(t, "admin@a.test")
		am := h.join(t, admin, h.orgA, tenant.RoleAdmin)
		if err := am.Suspend(shared.NewID()); err != nil {
			t.Fatalf("Suspend: %v", err)
		}
		uid, _ := h.enrolledUser(t, "member@a.test")
		target := h.join(t, uid, h.orgA, tenant.RoleMember)
		if err := h.reset(admin, h.orgA, target); !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("want ErrForbidden, got %v", err)
		}
	})

	t.Run("a member without 2FA reports not enabled", func(t *testing.T) {
		h := newResetHarness(t)
		admin := h.seedUser(t, "admin@a.test")
		h.join(t, admin, h.orgA, tenant.RoleAdmin)
		uid := h.seedUser(t, "plain@a.test")
		target := h.join(t, uid, h.orgA, tenant.RoleMember)
		if err := h.reset(admin, h.orgA, target); !errors.Is(err, app.ErrMFANotEnabled) {
			t.Fatalf("want ErrMFANotEnabled, got %v", err)
		}
	})
}
