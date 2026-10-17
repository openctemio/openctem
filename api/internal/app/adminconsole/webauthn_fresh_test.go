package adminconsole

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/totp"
)

// stepUpWithKey opens the session's step-up window with a security key.
func (w *waHarness) stepUpWithKey(t *testing.T, token string, k *virtualKey) *admin.Session {
	t.Helper()
	ctx := context.Background()
	sess := w.session(t, token)
	opts, err := w.svc.BeginWebAuthnStepUp(ctx, w.admin, sess)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.svc.FinishWebAuthnStepUp(ctx, w.admin, sess, k.get(t, opts, w.userHandle()), client); err != nil {
		t.Fatalf("step-up: %v", err)
	}
	return w.session(t, token)
}

// An action that asks for a fresh check never rides the 5 minute window: a key
// confirmation given within the last minute pays for exactly one such action.
func TestFreshStepUpIsSingleUseAndShortLived(t *testing.T) {
	w := newWAHarness(t)
	ctx := context.Background()
	_, token := w.enroll(t)
	k := newVirtualKey(t)
	w.register(t, token, k, "key")
	fresh := admin.WithFreshStepUp(ctx)

	sess := w.stepUpWithKey(t, token, k)
	// The window passes an ordinary protected action, repeatedly.
	if err := w.svc.ConfirmProtected(ctx, w.admin, sess, "", "admin.provision", client); err != nil {
		t.Fatalf("window: %v", err)
	}
	// A fresh action takes the just-given confirmation once.
	if err := w.svc.ConfirmProtected(fresh, w.admin, sess, "", "webauthn.register", client); err != nil {
		t.Fatalf("fresh with a just-given key check: %v", err)
	}
	sess = w.session(t, token)
	if err := w.svc.ConfirmProtected(fresh, w.admin, sess, "", "recovery_codes.generate", client); !errors.Is(err, admin.ErrStepUpRequired) {
		t.Fatalf("second fresh action on the same confirmation: %v", err)
	}
	// The ordinary window was spent with it.
	if err := w.svc.ConfirmProtected(ctx, w.admin, sess, "", "admin.provision", client); !errors.Is(err, admin.ErrStepUpRequired) {
		t.Fatalf("window after a fresh action: %v", err)
	}

	// Inside the 5 minute window but older than a minute: refused.
	w.stepUpWithKey(t, token, k)
	w.clock = w.clock.Add(admin.FreshStepUpWindow + time.Second)
	sess = w.session(t, token)
	if err := w.svc.ConfirmProtected(fresh, w.admin, sess, "", "webauthn.register", client); !errors.Is(err, admin.ErrStepUpRequired) {
		t.Fatalf("stale key check for a fresh action: %v", err)
	}
	if !sess.SteppedUp(w.clock) {
		t.Fatal("test setup: the 5 minute window should still be open")
	}
}

func TestFreshStepUpWithTOTPCode(t *testing.T) {
	w := newWAHarness(t)
	ctx := context.Background()
	secret, token := w.enroll(t)
	w.clock = w.clock.Add(totp.Period)
	code, _ := totp.Code(secret, w.clock)
	sess := w.session(t, token)
	if err := w.svc.ConfirmProtected(admin.WithFreshStepUp(ctx), w.admin, sess, code, "webauthn.register", client); err != nil {
		t.Fatalf("fresh code: %v", err)
	}
	// A code opens no window for the next action.
	if w.session(t, token).SteppedUp(w.clock) {
		t.Fatal("a fresh code must not open the step-up window")
	}
}

// Under "require WebAuthn" an administrator without a key keeps TOTP until the
// grace deadline set at the policy switch, then is refused.
func TestRequireWebAuthnGraceDeadline(t *testing.T) {
	w := newWAHarness(t)
	ctx := context.Background()
	_, token := w.enroll(t)
	w.register(t, token, newVirtualKey(t), "one")
	w.register(t, token, newVirtualKey(t), "two")
	if _, err := w.svc.GenerateRecoveryCodes(ctx, w.admin, client); err != nil {
		t.Fatal(err)
	}
	switched := w.clock
	if _, err := w.svc.SetMFAPolicy(ctx, w.admin, admin.ConsoleMFAPolicy{RequireWebAuthn: true}, 0, client); err != nil {
		t.Fatal(err)
	}
	p, version, _ := w.svc.MFAPolicy(ctx)
	if p.GraceUntil == nil || !p.GraceUntil.Equal(switched.Add(7*24*time.Hour)) {
		t.Fatalf("grace deadline: %v", p.GraceUntil)
	}
	// Saving the policy again while on keeps the deadline.
	w.clock = w.clock.Add(time.Hour)
	if _, err := w.svc.SetMFAPolicy(ctx, w.admin, admin.ConsoleMFAPolicy{RequireWebAuthn: true}, version, client); err != nil {
		t.Fatal(err)
	}
	if again, _, _ := w.svc.MFAPolicy(ctx); !again.GraceUntil.Equal(*p.GraceUntil) {
		t.Fatalf("deadline moved to %v", again.GraceUntil)
	}

	ou := &SignedInUser{UserID: shared.NewID(), Email: "two@acme.io", Name: "Two", Active: true}
	oa := admin.Reconstitute(shared.NewID(), "two@acme.io", "Two", admin.AdminRoleOpsAdmin, true,
		&ou.UserID, nil, "", 0, nil, nil, "", w.clock, nil, w.clock)
	w.admins.byID[oa.ID().String()] = oa
	w.admins.userLink[ou.UserID.String()] = oa.ID().String()
	w.accounts.sessions["refresh-two"] = ou

	st, err := w.svc.FactorStatus(ctx, oa)
	if err != nil || !st.TOTPAllowed() {
		t.Fatalf("inside the grace: %+v %v", st, err)
	}
	res, err := w.svc.Start(ctx, "refresh-two", password, client)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.Code(res.Secret, w.clock)
	if _, _, err := w.svc.VerifyMFA(ctx, res.PendingToken, code, client); err != nil {
		t.Fatalf("TOTP inside the grace: %v", err)
	}

	w.clock = p.GraceUntil.Add(time.Second)
	st, _ = w.svc.FactorStatus(ctx, oa)
	if st.TOTPAllowed() {
		t.Fatal("TOTP must be refused after the grace deadline")
	}
	res, err = w.svc.Start(ctx, "refresh-two", password, client)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range res.Methods {
		if m == MethodTOTP {
			t.Fatalf("TOTP offered after the grace: %v", res.Methods)
		}
	}
	code, _ = totp.Code(res.Secret, w.clock)
	if _, _, err := w.svc.VerifyMFA(ctx, res.PendingToken, code, client); !errors.Is(err, admin.ErrWebAuthnRequired) {
		t.Fatalf("TOTP after the grace: %v", err)
	}
	// A break-glass account is never refused.
	if !(admin.FactorStatus{PolicyRequires: true, BreakGlassExempted: true, GraceOver: true}).TOTPAllowed() {
		t.Fatal("break-glass keeps TOTP")
	}
	// Switched off: no deadline.
	if _, err := w.svc.SetMFAPolicy(ctx, w.admin, admin.ConsoleMFAPolicy{}, version+1, client); err != nil {
		t.Fatal(err)
	}
	if off, _, _ := w.svc.MFAPolicy(ctx); off.GraceUntil != nil {
		t.Fatalf("deadline kept after switching off: %v", off.GraceUntil)
	}
}

type recordingNotifier struct {
	mu    sync.Mutex
	kinds []string
	last  FactorNotice
}

func (r *recordingNotifier) NotifyFactorChange(_ context.Context, n FactorNotice) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kinds = append(r.kinds, n.Kind)
	r.last = n
	return nil
}

// Every key added and every recovery-code regeneration emails the administrator.
func TestFactorChangesEmailTheAdministrator(t *testing.T) {
	w := newWAHarness(t)
	ctx := context.Background()
	n := &recordingNotifier{}
	w.svc.SetFactorChangeNotifier(n)
	_, token := w.enroll(t)
	w.register(t, token, newVirtualKey(t), "yubikey")
	if len(n.kinds) != 1 || n.kinds[0] != FactorKeyAdded || n.last.Detail != "yubikey" || n.last.AdminEmail != w.admin.Email() {
		t.Fatalf("after adding a key: %+v %v", n.last, n.kinds)
	}
	if _, err := w.svc.GenerateRecoveryCodes(ctx, w.admin, client); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.GenerateRecoveryCodes(ctx, w.admin, client); err != nil {
		t.Fatal(err)
	}
	want := []string{FactorKeyAdded, FactorRecoveryCodesRegenerated, FactorRecoveryCodesRegenerated}
	if len(n.kinds) != len(want) || n.kinds[1] != want[1] || n.kinds[2] != want[2] {
		t.Fatalf("notices %v, want %v", n.kinds, want)
	}
}

// The per-request enrollment gate reads the factor policy once per administrator,
// not on every console request, and sees a change made on this instance at once.
func TestEnrollmentGateFactorStatusIsCached(t *testing.T) {
	w := newWAHarness(t)
	ctx := context.Background()
	_, token := w.enroll(t)
	base := w.factors.lists
	for range 5 {
		if _, _, err := w.svc.AuthenticateSession(ctx, token); err != nil {
			t.Fatal(err)
		}
	}
	if n := w.factors.lists - base; n != 1 {
		t.Fatalf("5 requests ran %d factor lookups, want 1", n)
	}
	w.register(t, token, newVirtualKey(t), "k")
	_, sess, _ := w.svc.AuthenticateSession(ctx, token)
	if sess.EnrollmentRequired {
		t.Fatal("policy is off")
	}
	// Expires after the TTL.
	before := w.factors.lists
	w.clock = w.clock.Add(factorCacheTTL + time.Second)
	if _, _, err := w.svc.AuthenticateSession(ctx, token); err != nil {
		t.Fatal(err)
	}
	if w.factors.lists == before {
		t.Fatal("cache never expires")
	}
}
