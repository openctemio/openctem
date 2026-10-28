package platformuser

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/user"
)

type fakeUsers struct {
	user.Repository
	u       *user.User
	updated *user.User
}

func (f *fakeUsers) GetByID(context.Context, shared.ID) (*user.User, error) { return f.u, nil }
func (f *fakeUsers) Update(_ context.Context, u *user.User) error           { f.updated = u; return nil }

type fakeStates struct {
	admin, erased bool
	cleared       bool
}

func (f *fakeStates) AccountState(context.Context, shared.ID) (bool, bool, error) {
	return f.admin, f.erased, nil
}
func (f *fakeStates) ClearLockout(context.Context, shared.ID) error { f.cleared = true; return nil }

type fakeRevoker struct{ userID string }

func (f *fakeRevoker) RevokeAllSessions(_ context.Context, userID, _ string) error {
	f.userID = userID
	return nil
}

type fakeResets struct{ token string }

func (f fakeResets) ForgotPassword(context.Context, auth.ForgotPasswordInput) (*auth.ForgotPasswordResult, error) {
	return &auth.ForgotPasswordResult{Token: f.token}, nil
}

type fakeMailer struct {
	configured        bool
	resetTo, verifyTo string
	verifyToken       string
}

func (f *fakeMailer) IsConfigured() bool { return f.configured }
func (f *fakeMailer) SendPasswordResetEmail(_ context.Context, to, _, _ string, _ time.Duration, _ string) error {
	f.resetTo = to
	return nil
}
func (f *fakeMailer) SendVerificationEmail(_ context.Context, to, _, token string, _ time.Duration) error {
	f.verifyTo, f.verifyToken = to, token
	return nil
}

func localUser(t *testing.T, verified bool) *user.User {
	t.Helper()
	u, err := user.NewLocalUser("person@corp.test", "Person", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if verified {
		u.VerifyEmail()
	}
	return u
}

func TestRefusesAdministratorAndErasedAccounts(t *testing.T) {
	for _, st := range []*fakeStates{{admin: true}, {erased: true}} {
		rev := &fakeRevoker{}
		s := NewService(&fakeUsers{u: localUser(t, true)}, rev, nil, nil, st, Durations{})
		err := s.RevokeSessions(context.Background(), shared.NewID())
		if !errors.Is(err, shared.ErrConflict) || rev.userID != "" {
			t.Fatalf("state %+v: err %v, revoked %q", st, err, rev.userID)
		}
		if err := s.Unlock(context.Background(), shared.NewID()); !errors.Is(err, shared.ErrConflict) || st.cleared {
			t.Fatalf("state %+v: unlock err %v", st, err)
		}
	}
}

func TestRevokeSessions(t *testing.T) {
	rev := &fakeRevoker{}
	id := shared.NewID()
	s := NewService(&fakeUsers{u: localUser(t, true)}, rev, nil, nil, &fakeStates{}, Durations{})
	if err := s.RevokeSessions(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if rev.userID != id.String() {
		t.Fatalf("revoked %q, want %q", rev.userID, id)
	}
}

func TestUnlockNeedsALock(t *testing.T) {
	st := &fakeStates{}
	s := NewService(&fakeUsers{u: localUser(t, true)}, nil, nil, nil, st, Durations{})
	if err := s.Unlock(context.Background(), shared.NewID()); !errors.Is(err, ErrNotLocked) || st.cleared {
		t.Fatalf("unlock of an unlocked account: %v", err)
	}
}

func TestPasswordResetGoesToTheAccountMailbox(t *testing.T) {
	m := &fakeMailer{configured: true}
	s := NewService(&fakeUsers{u: localUser(t, true)}, nil, fakeResets{token: "raw"}, m, &fakeStates{}, Durations{})
	if err := s.SendPasswordReset(context.Background(), shared.NewID()); err != nil {
		t.Fatal(err)
	}
	if m.resetTo != "person@corp.test" {
		t.Fatalf("reset sent to %q", m.resetTo)
	}

	m.configured = false
	if err := s.SendPasswordReset(context.Background(), shared.NewID()); !errors.Is(err, ErrEmailUnavailable) {
		t.Fatalf("without SMTP: %v", err)
	}
}

func TestResendVerificationStoresOnlyTheHash(t *testing.T) {
	users := &fakeUsers{u: localUser(t, false)}
	m := &fakeMailer{configured: true}
	s := NewService(users, nil, nil, m, &fakeStates{}, Durations{EmailVerification: time.Hour})
	if err := s.ResendVerification(context.Background(), shared.NewID()); err != nil {
		t.Fatal(err)
	}
	if m.verifyTo != "person@corp.test" || m.verifyToken == "" {
		t.Fatalf("verification mail: %+v", m)
	}
	stored := users.updated.EmailVerificationToken()
	if stored == nil || *stored == m.verifyToken {
		t.Fatal("the raw verification token was stored")
	}

	users.u = localUser(t, true)
	if err := s.ResendVerification(context.Background(), shared.NewID()); !errors.Is(err, ErrAlreadyVerified) {
		t.Fatalf("verified account: %v", err)
	}
}

type fakeMFA struct {
	id  shared.ID
	err error
	ip  string
}

func (f *fakeMFA) ResetUserMFAByConsole(_ context.Context, id shared.ID, ip string) error {
	f.id, f.ip = id, ip
	return f.err
}

func TestIssueResetLinkOnlyWithoutEmailAndStoresOnlyTheHash(t *testing.T) {
	users := &fakeUsers{u: localUser(t, true)}
	m := &fakeMailer{}
	s := NewService(users, nil, nil, m, &fakeStates{}, Durations{})

	token, expires, err := s.IssueResetLink(context.Background(), shared.NewID())
	if err != nil || token == "" {
		t.Fatalf("issue: token %q err %v", token, err)
	}
	if d := time.Until(expires); d > ResetLinkTTL || d < ResetLinkTTL-time.Minute {
		t.Fatalf("link lives %v, want about %v", d, ResetLinkTTL)
	}
	stored := users.updated.PasswordResetToken()
	if stored == nil || *stored == token {
		t.Fatal("the raw reset token was stored")
	}
	if exp := users.updated.PasswordResetExpiresAt(); exp == nil || !exp.Equal(expires) {
		t.Fatalf("stored expiry %v, returned %v", exp, expires)
	}

	// Email works: the account's own mailbox is the way, nothing is issued.
	users.updated = nil
	m.configured = true
	if _, _, err := s.IssueResetLink(context.Background(), shared.NewID()); !errors.Is(err, ErrEmailAvailable) || users.updated != nil {
		t.Fatalf("with email: %v (updated %v)", err, users.updated != nil)
	}
}

func TestIssueResetLinkRefusesAdministratorAndFederatedAccounts(t *testing.T) {
	users := &fakeUsers{u: localUser(t, true)}
	s := NewService(users, nil, nil, &fakeMailer{}, &fakeStates{admin: true}, Durations{})
	if _, _, err := s.IssueResetLink(context.Background(), shared.NewID()); !errors.Is(err, ErrPlatformAdmin) || users.updated != nil {
		t.Fatalf("platform administrator: %v", err)
	}
	if err := s.MarkVerified(context.Background(), shared.NewID()); !errors.Is(err, ErrPlatformAdmin) {
		t.Fatalf("mark verified, platform administrator: %v", err)
	}
	if err := s.ResetMFA(context.Background(), shared.NewID(), ""); !errors.Is(err, ErrPlatformAdmin) {
		t.Fatalf("reset mfa, platform administrator: %v", err)
	}
}

func TestMarkVerified(t *testing.T) {
	users := &fakeUsers{u: localUser(t, false)}
	m := &fakeMailer{}
	s := NewService(users, nil, nil, m, &fakeStates{}, Durations{})
	if err := s.MarkVerified(context.Background(), shared.NewID()); err != nil {
		t.Fatal(err)
	}
	if users.updated == nil || !users.updated.EmailVerified() {
		t.Fatal("the account was not marked verified")
	}

	m.configured = true
	users.u, users.updated = localUser(t, false), nil
	if err := s.MarkVerified(context.Background(), shared.NewID()); !errors.Is(err, ErrEmailAvailable) || users.updated != nil {
		t.Fatalf("with email: %v", err)
	}
	m.configured = false
	users.u = localUser(t, true)
	if err := s.MarkVerified(context.Background(), shared.NewID()); !errors.Is(err, ErrAlreadyVerified) {
		t.Fatalf("already verified: %v", err)
	}
}

func TestResetMFA(t *testing.T) {
	id := shared.NewID()
	mfa := &fakeMFA{}
	s := NewService(&fakeUsers{u: localUser(t, true)}, nil, nil, nil, &fakeStates{}, Durations{})
	if err := s.ResetMFA(context.Background(), id, "203.0.113.5"); err == nil {
		t.Fatal("without a resetter the reset must be refused, not skipped")
	}
	s.SetMFAResetter(mfa)
	if err := s.ResetMFA(context.Background(), id, "203.0.113.5"); err != nil || mfa.id != id || mfa.ip != "203.0.113.5" {
		t.Fatalf("reset: %v, got %+v", err, mfa)
	}
	mfa.err = auth.ErrMFANotEnabled
	if err := s.ResetMFA(context.Background(), id, ""); !errors.Is(err, ErrMFANotEnabled) || !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("no factor: %v", err)
	}
}
