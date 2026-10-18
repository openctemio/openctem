package unit

import (
	"context"
	"testing"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type recordingAuthAuditRepo struct {
	mockAuthAuditRepo
	logs []*audit.AuditLog
}

func (r *recordingAuthAuditRepo) Create(_ context.Context, l *audit.AuditLog) error {
	r.logs = append(r.logs, l)
	return nil
}

func newResetAuditHarness() (*auth.AuthService, *authTestDeps, *recordingAuthAuditRepo, *fakeNotifier) {
	cfg := defaultAuthTestConfig()
	deps := &authTestDeps{
		userRepo: newMockAuthUserRepo(), sessionRepo: newMockAuthSessionRepo(),
		rtRepo: newMockAuthRefreshTokenRepo(), tenantRepo: newMockAuthTenantRepo(), cfg: cfg,
	}
	rec := &recordingAuthAuditRepo{}
	log := logger.NewNop()
	svc := auth.NewAuthService(deps.userRepo, deps.sessionRepo, deps.rtRepo, deps.tenantRepo,
		auditsvc.NewAuditService(rec, log), cfg, log)
	n := &fakeNotifier{}
	svc.SetSecurityNotifier(n)
	return svc, deps, rec, n
}

func passwordChangeLogs(rec *recordingAuthAuditRepo) []*audit.AuditLog {
	var out []*audit.AuditLog
	for _, l := range rec.logs {
		if l.Action() == audit.ActionAuthPasswordChanged {
			out = append(out, l)
		}
	}
	return out
}

// A reset by emailed link is audited and the account holder is told, like a
// change from the account page. It used to leave no audit event and send no
// notice: a password reset by someone with access to the mailbox went
// unnoticed. The link also proves the address, so it verifies the email.
func TestAuthService_ResetPassword_AuditedAndNotified(t *testing.T) {
	svc, deps, rec, n := newResetAuditHarness()
	u := seedAuthUserWithResetToken(deps.userRepo, "reset@example.com", "$2a$04$dummy", "tok-1")
	u.SetEmailVerificationToken("pending", u.CreatedAt())
	deps.userRepo.users[u.ID().String()] = u

	if err := svc.ResetPassword(context.Background(), auth.ResetPasswordInput{
		Token: "tok-1", NewPassword: "NewStrongPassword123!", IPAddress: "203.0.113.9", UserAgent: "UA",
	}); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	logs := passwordChangeLogs(rec)
	if len(logs) != 1 {
		t.Fatalf("expected one auth.password_changed event, got %d", len(logs))
	}
	if logs[0].ActorIP() != "203.0.113.9" || logs[0].Metadata()["via"] != "reset" {
		t.Fatalf("event must carry the caller IP and via=reset, got ip=%q meta=%v", logs[0].ActorIP(), logs[0].Metadata())
	}
	if n.passwordChanged != 1 {
		t.Fatalf("the account holder must be notified once, got %d", n.passwordChanged)
	}
	if !deps.userRepo.users[u.ID().String()].EmailVerified() {
		t.Fatal("the emailed link proves the address: the email must be verified")
	}
}

// The first password of an account (an administrator's setup link) is
// audited as a set, without a "your password was changed" email.
func TestAuthService_ResetPassword_FirstPasswordNoNotice(t *testing.T) {
	svc, deps, rec, n := newResetAuditHarness()
	u := seedAuthUserWithResetToken(deps.userRepo, "setup@example.com", "x", "tok-2")
	fresh := user.Reconstitute(u.ID(), nil, u.Email(), u.Name(), "", "", user.StatusActive, user.Preferences{}, nil,
		u.CreatedAt(), u.UpdatedAt(), user.AuthProviderLocal, nil, true, nil, nil,
		u.PasswordResetToken(), u.PasswordResetExpiresAt(), 0, nil)
	deps.userRepo.users[u.ID().String()] = fresh

	if err := svc.ResetPassword(context.Background(), auth.ResetPasswordInput{Token: "tok-2", NewPassword: "NewStrongPassword123!"}); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	logs := passwordChangeLogs(rec)
	if len(logs) != 1 || logs[0].Metadata()["via"] != "setup" {
		t.Fatalf("expected one via=setup event, got %d", len(logs))
	}
	if n.passwordChanged != 0 {
		t.Fatalf("no change notice for a first password, got %d", n.passwordChanged)
	}
}

// A password reset revokes the account's sessions and then runs the
// sessions-revoked hook, which the platform admin console uses to end the
// console sessions of the administrator linked to the account.
func TestAuthService_ResetPassword_RunsSessionsRevokedHook(t *testing.T) {
	svc, deps, _, _ := newResetAuditHarness()
	u := seedAuthUserWithResetToken(deps.userRepo, "admin@example.com", "$2a$04$dummy", "tok-3")
	var got []string
	svc.SetSessionsRevokedHook(func(_ context.Context, userID shared.ID) { got = append(got, userID.String()) })

	if err := svc.ResetPassword(context.Background(), auth.ResetPasswordInput{Token: "tok-3", NewPassword: "NewStrongPassword123!"}); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if len(got) != 1 || got[0] != u.ID().String() {
		t.Fatalf("hook must run once for the account, got %v", got)
	}
}
