package unit

import (
	"context"
	"errors"
	"testing"
	"time"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/totp"
)

// Turning two-factor off while an organization or the platform requires it
// is refused and names who requires it (research 346, S2). Allowed turn-offs
// and authenticator replacements sign out every other session.

// signInWithCode completes a password + TOTP sign-in and returns the session.
func (h *mfaHarness) signInWithCode(t *testing.T, uid shared.ID, email, secret string) *auth.LoginResult {
	t.Helper()
	h.forgetLastStep(uid)
	ch := h.login(t, email).MFAChallenge
	if ch == nil {
		t.Fatal("login did not ask for a code")
	}
	res, err := h.svc.VerifyMFALogin(context.Background(), auth.VerifyMFAInput{Token: ch.Token, Code: currentCode(t, secret)})
	if err != nil {
		t.Fatalf("VerifyMFALogin: %v", err)
	}
	h.forgetLastStep(uid)
	return res
}

func (h *mfaHarness) lastLog(action audit.Action) *audit.AuditLog {
	h.audits.mu.Lock()
	defer h.audits.mu.Unlock()
	for i := len(h.audits.logs) - 1; i >= 0; i-- {
		if h.audits.logs[i].Action() == action {
			return h.audits.logs[i]
		}
	}
	return nil
}

func TestMFAOff_RefusedWhileOrganizationRequiresIt(t *testing.T) {
	h := newMFAHarness(t)
	tn := newPolicyTenant(t, h.tenants, "need-2fa", true)
	h.tenants.userMemberships = []tenant.UserMembership{{TenantID: tn.ID().String(), TenantSlug: tn.Slug(), TenantName: "Acme", Role: "member"}}
	uid := h.seedUser(t, "held@example.com")
	// Enroll directly (the organization requires it: sign-in would enroll too).
	setup, err := h.svc.BeginMFASetup(context.Background(), uid.String())
	if err != nil {
		t.Fatal(err)
	}
	codes, err := h.svc.EnableMFA(context.Background(), auditsvc.AuditContext{}, uid.String(), mfaTestPassword, currentCode(t, setup.Secret))
	if err != nil {
		t.Fatal(err)
	}
	h.forgetLastStep(uid)

	err = h.svc.DisableMFA(context.Background(), auditsvc.AuditContext{}, uid.String(), mfaTestPassword, codes[0])
	var held *auth.MFARequiredError
	if !errors.As(err, &held) || !errors.Is(err, auth.ErrMFARequiredByPolicy) {
		t.Fatalf("want MFARequiredError, got %v", err)
	}
	if len(held.Holders.Organizations) != 1 || held.Holders.Organizations[0] != "Acme" || held.Holders.Platform {
		t.Fatalf("holders = %+v, want the organization Acme only", held.Holders)
	}
	if f, _ := h.mfa.GetFactor(context.Background(), uid); f == nil || !f.Enabled {
		t.Fatal("the factor was turned off")
	}
	// The refusal did not spend the recovery code.
	unused, _ := h.mfa.ListUnusedRecoveryCodes(context.Background(), uid)
	if len(unused) != len(codes) {
		t.Fatalf("a refused turn-off spent a recovery code: %d of %d left", len(unused), len(codes))
	}
	if l := h.lastLog(audit.ActionAuthMFADisabled); l == nil || l.Result() != audit.ResultFailure {
		t.Fatal("the refusal was not audited as a failure")
	}
	if h.notifier.mfaDisabled != 0 {
		t.Fatal("a refused turn-off sent the 'two-factor turned off' e-mail")
	}

	st, err := h.svc.GetMFAStatus(context.Background(), uid.String())
	if err != nil {
		t.Fatal(err)
	}
	if st.CanTurnOff || len(st.RequiredBy.Organizations) != 1 {
		t.Fatalf("status = %+v, want can_turn_off=false naming Acme", st)
	}
}

func TestMFAOff_RefusedWhilePlatformFloorCoversThem(t *testing.T) {
	cases := []struct {
		name          string
		effectiveFrom time.Time
	}{
		{"floor in force", time.Now().Add(-30 * 24 * time.Hour)},
		// During grace the floor does not gate sign-in yet, but turning an
		// existing factor off would only have to be undone by the due date.
		{"floor still in grace", time.Now().Add(-1 * time.Hour)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFloorFixture(t, "admin", 400*24*time.Hour, tenant.MFAFloorAdmins, c.effectiveFrom)
			setup, err := f.h.svc.BeginMFASetup(context.Background(), f.uid.String())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.h.svc.EnableMFA(context.Background(), auditsvc.AuditContext{}, f.uid.String(), mfaTestPassword, currentCode(t, setup.Secret)); err != nil {
				t.Fatal(err)
			}
			f.h.forgetLastStep(f.uid)
			err = f.h.svc.DisableMFA(context.Background(), auditsvc.AuditContext{}, f.uid.String(), mfaTestPassword, currentCode(t, setup.Secret))
			var held *auth.MFARequiredError
			if !errors.As(err, &held) {
				t.Fatalf("want MFARequiredError, got %v", err)
			}
			if !held.Holders.Platform || len(held.Holders.Organizations) != 0 {
				t.Fatalf("holders = %+v, want the platform floor only", held.Holders)
			}
		})
	}
	t.Run("a member under an administrators floor may turn it off", func(t *testing.T) {
		f := newFloorFixture(t, "member", 400*24*time.Hour, tenant.MFAFloorAdmins, time.Now().Add(-30*24*time.Hour))
		setup, _ := f.h.svc.BeginMFASetup(context.Background(), f.uid.String())
		if _, err := f.h.svc.EnableMFA(context.Background(), auditsvc.AuditContext{}, f.uid.String(), mfaTestPassword, currentCode(t, setup.Secret)); err != nil {
			t.Fatal(err)
		}
		f.h.forgetLastStep(f.uid)
		if err := f.h.svc.DisableMFA(context.Background(), auditsvc.AuditContext{}, f.uid.String(), mfaTestPassword, currentCode(t, setup.Secret)); err != nil {
			t.Fatalf("DisableMFA: %v", err)
		}
	})
}

// An unreadable policy refuses the turn-off instead of guessing.
func TestMFAOff_FailsClosedOnUnreadablePolicy(t *testing.T) {
	h := newMFAHarness(t)
	uid := h.seedUser(t, "unread@example.com")
	secret, _ := h.enroll(t, uid)
	h.forgetLastStep(uid)
	h.tenants.getUserMembershipsErr = errors.New("db down")
	err := h.svc.DisableMFA(context.Background(), auditsvc.AuditContext{}, uid.String(), mfaTestPassword, currentCode(t, secret))
	if err == nil {
		t.Fatal("turned off with an unreadable policy")
	}
	if f, _ := h.mfa.GetFactor(context.Background(), uid); f == nil || !f.Enabled {
		t.Fatal("the factor was turned off")
	}
	st, err := h.svc.GetMFAStatus(context.Background(), uid.String())
	if err != nil {
		t.Fatal(err)
	}
	if st.CanTurnOff {
		t.Fatal("status offers Turn off while the policy is unreadable")
	}
}

func TestMFAOff_AllowedEndsOtherSessions(t *testing.T) {
	h := newMFAHarness(t)
	uid := h.seedUser(t, "free@example.com")
	secret, _ := h.enroll(t, uid)
	cur := h.signInWithCode(t, uid, "free@example.com", secret)
	other := h.signInWithCode(t, uid, "free@example.com", secret)

	st, _ := h.svc.GetMFAStatus(context.Background(), uid.String())
	if !st.CanTurnOff || st.RequiredBy.Platform || len(st.RequiredBy.Organizations) != 0 {
		t.Fatalf("status = %+v, want can_turn_off", st)
	}
	actx := auditsvc.AuditContext{ActorID: uid.String(), SessionID: cur.SessionID}
	if err := h.svc.DisableMFA(context.Background(), actx, uid.String(), mfaTestPassword, currentCode(t, secret)); err != nil {
		t.Fatalf("DisableMFA: %v", err)
	}
	if !h.sessions.sessions[cur.SessionID].IsActive() {
		t.Error("the current session was signed out")
	}
	if h.sessions.sessions[other.SessionID].IsActive() || !h.revocations.has(other.SessionID) {
		t.Error("another session survived turning two-factor off")
	}
	if h.revocations.has(cur.SessionID) {
		t.Error("the current session was marked revoked")
	}
	l := h.lastLog(audit.ActionAuthMFADisabled)
	if l == nil || l.Result() != audit.ResultSuccess || l.Metadata()["other_sessions_ended"] != true {
		t.Fatalf("audit = %+v, want a success with other_sessions_ended", l)
	}
}

func TestMFAReplace(t *testing.T) {
	setup := func(t *testing.T) (*mfaHarness, shared.ID, string, []string) {
		h := newMFAHarness(t)
		tn := newPolicyTenant(t, h.tenants, "replace-2fa", true)
		h.tenants.userMemberships = []tenant.UserMembership{{TenantID: tn.ID().String(), TenantSlug: tn.Slug(), TenantName: "Acme", Role: "member"}}
		uid := h.seedUser(t, "swap@example.com")
		secret, codes := h.enroll(t, uid)
		h.forgetLastStep(uid)
		return h, uid, secret, codes
	}

	t.Run("needs the password and a current code", func(t *testing.T) {
		h, uid, secret, _ := setup(t)
		if _, err := h.svc.BeginMFAReplacement(context.Background(), uid.String(), "wrong", currentCode(t, secret)); !errors.Is(err, auth.ErrPasswordMismatch) {
			t.Fatalf("wrong password: %v", err)
		}
		if _, err := h.svc.BeginMFAReplacement(context.Background(), uid.String(), mfaTestPassword, wrongCode(currentCode(t, secret))); !errors.Is(err, auth.ErrMFACodeInvalid) {
			t.Fatalf("wrong code: %v", err)
		}
		if f, _ := h.mfa.GetFactor(context.Background(), uid); f.PendingSecretEncrypted != "" {
			t.Fatal("a refused start stored a new secret")
		}
	})

	t.Run("confirm without a start is refused", func(t *testing.T) {
		h, uid, secret, _ := setup(t)
		if _, err := h.svc.ConfirmMFAReplacement(context.Background(), auditsvc.AuditContext{}, uid.String(), currentCode(t, secret)); !errors.Is(err, auth.ErrMFANoPendingSetup) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("old device works until confirmed, then only the new one; other sessions end", func(t *testing.T) {
		h, uid, oldSecret, oldCodes := setup(t)
		cur := h.signInWithCode(t, uid, "swap@example.com", oldSecret)
		other := h.signInWithCode(t, uid, "swap@example.com", oldSecret)

		// A lost phone: the recovery code is the proof.
		ns, err := h.svc.BeginMFAReplacement(context.Background(), uid.String(), mfaTestPassword, oldCodes[0])
		if err != nil {
			t.Fatalf("BeginMFAReplacement: %v", err)
		}
		// Still the old authenticator until the new one is confirmed.
		h.signInWithCode(t, uid, "swap@example.com", oldSecret)
		if _, err := h.svc.ConfirmMFAReplacement(context.Background(), auditsvc.AuditContext{}, uid.String(), wrongCode(currentCode(t, ns.Secret))); !errors.Is(err, auth.ErrMFACodeInvalid) {
			t.Fatalf("wrong new code: %v", err)
		}
		actx := auditsvc.AuditContext{ActorID: uid.String(), SessionID: cur.SessionID}
		fresh, err := h.svc.ConfirmMFAReplacement(context.Background(), actx, uid.String(), currentCode(t, ns.Secret))
		if err != nil || len(fresh) == 0 {
			t.Fatalf("ConfirmMFAReplacement: %v", err)
		}
		if !h.sessions.sessions[cur.SessionID].IsActive() || h.sessions.sessions[other.SessionID].IsActive() {
			t.Fatal("want the current session kept and the other ended")
		}
		if !h.audits.has(audit.ActionAuthMFAReplaced) {
			t.Fatal("the replacement was not audited")
		}
		// Old code no longer signs in, new one does; old recovery codes are gone.
		h.forgetLastStep(uid)
		ch := h.login(t, "swap@example.com").MFAChallenge
		oldCode, _ := totp.Code(oldSecret, time.Now())
		if oldCode != currentCode(t, ns.Secret) {
			if _, err := h.svc.VerifyMFALogin(context.Background(), auth.VerifyMFAInput{Token: ch.Token, Code: oldCode}); !errors.Is(err, auth.ErrMFACodeInvalid) {
				t.Fatalf("old authenticator still works: %v", err)
			}
		}
		ch = h.login(t, "swap@example.com").MFAChallenge
		if _, err := h.svc.VerifyMFALogin(context.Background(), auth.VerifyMFAInput{Token: ch.Token, RecoveryCode: oldCodes[1]}); !errors.Is(err, auth.ErrMFACodeInvalid) {
			t.Fatalf("old recovery code still works: %v", err)
		}
		h.signInWithCode(t, uid, "swap@example.com", ns.Secret)
	})

	t.Run("a start older than the window cannot be confirmed", func(t *testing.T) {
		h, uid, secret, _ := setup(t)
		ns, err := h.svc.BeginMFAReplacement(context.Background(), uid.String(), mfaTestPassword, currentCode(t, secret))
		if err != nil {
			t.Fatal(err)
		}
		h.mfa.mu.Lock()
		old := time.Now().Add(-16 * time.Minute)
		h.mfa.factors[uid.String()].PendingCreatedAt = &old
		h.mfa.mu.Unlock()
		if _, err := h.svc.ConfirmMFAReplacement(context.Background(), auditsvc.AuditContext{}, uid.String(), currentCode(t, ns.Secret)); !errors.Is(err, auth.ErrMFANoPendingSetup) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("without two-factor on there is nothing to replace", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "none@example.com")
		if _, err := h.svc.BeginMFAReplacement(context.Background(), uid.String(), mfaTestPassword, "123456"); !errors.Is(err, auth.ErrMFANotEnabled) {
			t.Fatalf("got %v", err)
		}
	})
}
