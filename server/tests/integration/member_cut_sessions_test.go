package integration

// Cutting a member's access in one organization ends only that
// organization's access (research/72 D3): the sessions its IdP signed in end,
// the sessions that also serve the person's other organization stay, and the
// cut organization refuses the person at the next request and at token
// exchange (active memberships only).

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type cutSessions struct {
	password, byHost, byOther shared.ID
}

func seedCutSessions(t *testing.T, f *lifecycleFixture) cutSessions {
	t.Helper()
	ctx := context.Background()
	repo := postgres.NewSessionRepository(f.db)
	mk := func(idp *shared.ID) shared.ID {
		s, err := sessiondom.New(f.memberID, "tok-"+shared.NewID().String(), "127.0.0.1", "UA", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if idp != nil {
			s.SetAuthMethod(sessiondom.AuthMethodSSO)
			s.SetIDPTenant(*idp)
		}
		if err := repo.Create(ctx, s); err != nil {
			t.Fatalf("create session: %v", err)
		}
		return s.ID()
	}
	t.Cleanup(func() {
		_, _ = f.db.ExecContext(context.Background(), `DELETE FROM sessions WHERE user_id = $1`, f.memberID.String())
	})
	return cutSessions{password: mk(nil), byHost: mk(&f.tenantID), byOther: mk(&f.otherTID)}
}

func (f *lifecycleFixture) sessionStatus(t *testing.T, id shared.ID) string {
	return f.str(t, `SELECT status FROM sessions WHERE id = $1`, id.String())
}

func wireSessions(f *lifecycleFixture) {
	f.svc.SetSessionService(auth.NewSessionService(
		postgres.NewSessionRepository(f.db), postgres.NewRefreshTokenRepository(f.db), logger.NewNop()))
}

func TestMemberCut_SuspendInOneOrganization_KeepsTheOtherOrganizationsSessions(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := context.Background()
	wireSessions(f)
	createTestMembership(t, f.db, f.otherTID, f.memberID, "member")
	s := seedCutSessions(t, f)

	if err := f.svc.SuspendMember(ctx, f.mshipID.String(), f.ownerCtx()); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if got := f.sessionStatus(t, s.byHost); got != "revoked" {
		t.Errorf("session signed in by the suspending organization's IdP = %q, want revoked", got)
	}
	for name, id := range map[string]shared.ID{"password": s.password, "other organization's IdP": s.byOther} {
		if got := f.sessionStatus(t, id); got != "active" {
			t.Errorf("%s session = %q, want active (it serves the other organization)", name, got)
		}
	}
	// The suspending organization no longer mints tokens for the person.
	ms, err := f.repo.GetUserMemberships(ctx, f.memberID)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.TenantID == f.tenantID.String() {
			t.Error("token exchange would still see the suspended membership")
		}
	}
}

func TestMemberCut_OffboardInOneOrganization_KeepsTheOtherOrganizationsSessions(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := context.Background()
	wireSessions(f)
	createTestMembership(t, f.db, f.otherTID, f.memberID, "member")
	s := seedCutSessions(t, f)

	if _, err := f.svc.OffboardMember(ctx, f.mshipID.String(), tenant.OffboardMemberInput{
		SchedulesTo: f.peerID.String(), FindingsTo: f.peerID.String(), AssetsTo: f.peerID.String(),
	}, f.ownerCtx()); err != nil {
		t.Fatalf("offboard: %v", err)
	}
	if got := f.sessionStatus(t, s.byHost); got != "revoked" {
		t.Errorf("host-IdP session = %q, want revoked", got)
	}
	if got := f.sessionStatus(t, s.byOther); got != "active" {
		t.Errorf("other organization's session = %q, want active", got)
	}
}

// Someone whose only organization cuts them loses every session, as before.
func TestMemberCut_OnlyOrganization_EndsEverySession(t *testing.T) {
	f := newLifecycleFixture(t)
	ctx := context.Background()
	wireSessions(f)
	s := seedCutSessions(t, f)

	if err := f.svc.SuspendMember(ctx, f.mshipID.String(), f.ownerCtx()); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	for _, id := range []shared.ID{s.password, s.byHost, s.byOther} {
		if got := f.sessionStatus(t, id); got != "revoked" {
			t.Errorf("session %s = %q, want revoked", id, got)
		}
	}
}
