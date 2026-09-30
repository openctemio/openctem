package adminconsole

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/totp"
)

// ---- in-memory fakes -------------------------------------------------------

type fakeAdmins struct {
	admin.Repository // unimplemented methods panic if a test reaches them
	mu               sync.Mutex
	byID             map[string]*admin.AdminUser
}

func (f *fakeAdmins) GetByEmail(_ context.Context, email string) (*admin.AdminUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.byID {
		if strings.EqualFold(a.Email(), email) {
			return a, nil
		}
	}
	return nil, admin.ErrAdminNotFound
}

func (f *fakeAdmins) GetByID(_ context.Context, id shared.ID) (*admin.AdminUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a, ok := f.byID[id.String()]; ok {
		return a, nil
	}
	return nil, admin.ErrAdminNotFound
}

func (f *fakeAdmins) Update(_ context.Context, a *admin.AdminUser) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byID[a.ID().String()] = a
	return nil
}

type fakeConsole struct {
	mu       sync.Mutex
	creds    map[string]*admin.Credentials
	sessions map[string]*admin.Session // by token hash
}

func newFakeConsole() *fakeConsole {
	return &fakeConsole{creds: map[string]*admin.Credentials{}, sessions: map[string]*admin.Session{}}
}

func (f *fakeConsole) GetCredentials(_ context.Context, id shared.ID) (*admin.Credentials, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.creds[id.String()]
	if !ok {
		return nil, admin.ErrCredentialsNotFound
	}
	cp := *c
	return &cp, nil
}

func (f *fakeConsole) SaveCredentials(_ context.Context, c *admin.Credentials) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *c
	f.creds[c.AdminID.String()] = &cp
	return nil
}

func (f *fakeConsole) DeleteCredentials(_ context.Context, id shared.ID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.creds, id.String())
	return nil
}

func (f *fakeConsole) AdvanceMFAStep(_ context.Context, id shared.ID, step int64) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.creds[id.String()]
	if !ok || c.MFALastStep >= step {
		return false, nil
	}
	c.MFALastStep = step
	return true, nil
}

func (f *fakeConsole) CreateSession(_ context.Context, s *admin.Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *s
	f.sessions[s.TokenHash] = &cp
	return nil
}

func (f *fakeConsole) GetSessionByTokenHash(_ context.Context, h string) (*admin.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[h]
	if !ok {
		return nil, admin.ErrSessionNotFound
	}
	cp := *s
	return &cp, nil
}

func (f *fakeConsole) TouchSession(_ context.Context, id shared.ID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.sessions {
		if s.ID == id {
			s.LastSeenAt = at
		}
	}
	return nil
}

func (f *fakeConsole) DeleteSession(_ context.Context, id shared.ID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for h, s := range f.sessions {
		if s.ID == id {
			delete(f.sessions, h)
		}
	}
	return nil
}

func (f *fakeConsole) DeleteSessionsForAdmin(_ context.Context, id shared.ID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for h, s := range f.sessions {
		if s.AdminID == id {
			delete(f.sessions, h)
		}
	}
	return nil
}

func (f *fakeConsole) DeleteExpiredSessions(_ context.Context, now time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for h, s := range f.sessions {
		if s.ExpiresAt.Before(now) {
			delete(f.sessions, h)
			n++
		}
	}
	return n, nil
}

func (f *fakeConsole) sessionCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sessions)
}

type fakeAudit struct {
	admin.AuditLogRepository
	mu      sync.Mutex
	actions []string
}

func (f *fakeAudit) Create(_ context.Context, l *admin.AuditLog) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actions = append(f.actions, l.Action)
	return nil
}

func (f *fakeAudit) has(action string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, a := range f.actions {
		if a == action {
			return true
		}
	}
	return false
}

// ---- harness ---------------------------------------------------------------

const password = "correct horse battery"

type harness struct {
	svc     *Service
	admins  *fakeAdmins
	console *fakeConsole
	audit   *fakeAudit
	admin   *admin.AdminUser
	clock   time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	a, _, err := admin.NewAdminUser("ops@acme.io", "Ops", admin.AdminRoleSuperAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		admins:  &fakeAdmins{byID: map[string]*admin.AdminUser{a.ID().String(): a}},
		console: newFakeConsole(),
		audit:   &fakeAudit{},
		admin:   a,
		clock:   time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC),
	}
	h.svc = NewService(h.admins, h.console, h.audit, cipher, logger.NewNop())
	h.svc.now = func() time.Time { return h.clock }
	return h
}

var client = ClientInfo{IP: "203.0.113.7", UserAgent: "test"}

func (h *harness) setPassword(t *testing.T) {
	t.Helper()
	if err := h.svc.SetPassword(context.Background(), h.admin, "", password, false, client); err != nil {
		t.Fatalf("set password: %v", err)
	}
}

// enroll runs first login + MFA enrollment and returns the TOTP secret and a
// verified session token.
func (h *harness) enroll(t *testing.T) (secret, token string) {
	t.Helper()
	h.setPassword(t)
	res, err := h.svc.Login(context.Background(), "ops@acme.io", password, client)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if res.Status != StatusMFAEnrollment || res.Secret == "" || !strings.HasPrefix(res.OTPAuthURI, "otpauth://totp/") {
		t.Fatalf("expected enrollment with secret + uri, got %+v", res)
	}
	code, _ := totp.Code(res.Secret, h.clock)
	token, _, err = h.svc.VerifyMFA(context.Background(), res.PendingToken, code, client)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return res.Secret, token
}

// ---- tests -----------------------------------------------------------------

func TestEnrollmentThenLoginWithMFA(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	secret, token := h.enroll(t)

	got, err := h.svc.Authenticate(ctx, token)
	if err != nil || got.ID() != h.admin.ID() {
		t.Fatalf("authenticate: %v", err)
	}
	if !h.audit.has(ActionMFAEnrolled) || !h.audit.has(ActionLogin) {
		t.Fatalf("expected enroll + login audit, got %v", h.audit.actions)
	}

	// Second login: MFA already enrolled, no new secret is issued.
	h.clock = h.clock.Add(time.Minute)
	res, err := h.svc.Login(ctx, "OPS@acme.io", password, client)
	if err != nil || res.Status != StatusMFARequired || res.Secret != "" {
		t.Fatalf("second login: %+v %v", res, err)
	}
	code, _ := totp.Code(secret, h.clock)
	if _, _, err := h.svc.VerifyMFA(ctx, res.PendingToken, code, client); err != nil {
		t.Fatalf("second verify: %v", err)
	}
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// No password set yet.
	if _, err := h.svc.Login(ctx, "ops@acme.io", password, client); !errors.Is(err, admin.ErrInvalidCredentials) {
		t.Fatalf("no password: %v", err)
	}
	h.setPassword(t)
	for name, tc := range map[string][2]string{
		"unknown email":  {"nobody@acme.io", password},
		"wrong password": {"ops@acme.io", "wrong password here"},
	} {
		if _, err := h.svc.Login(ctx, tc[0], tc[1], client); !errors.Is(err, admin.ErrInvalidCredentials) {
			t.Errorf("%s: got %v, want ErrInvalidCredentials", name, err)
		}
	}
	h.admin.Deactivate()
	if _, err := h.svc.Login(ctx, "ops@acme.io", password, client); !errors.Is(err, admin.ErrInvalidCredentials) {
		t.Fatalf("inactive: %v", err)
	}
}

func TestLockoutBlocksEvenTheCorrectPassword(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.setPassword(t)
	for i := 0; i < admin.MaxFailedLoginAttempts; i++ {
		_, _ = h.svc.Login(ctx, "ops@acme.io", "wrong password here", client)
	}
	if !h.admin.IsLocked() {
		t.Fatal("expected account locked")
	}
	// A correct password must not unlock, nor reveal that it was correct.
	if _, err := h.svc.Login(ctx, "ops@acme.io", password, client); !errors.Is(err, admin.ErrInvalidCredentials) {
		t.Fatalf("locked login: %v", err)
	}
}

func TestReplayedCodeIsRejected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	secret, _ := h.enroll(t)

	h.clock = h.clock.Add(totp.Period) // new step
	code, _ := totp.Code(secret, h.clock)
	res1, _ := h.svc.Login(ctx, "ops@acme.io", password, client)
	if _, _, err := h.svc.VerifyMFA(ctx, res1.PendingToken, code, client); err != nil {
		t.Fatalf("first use: %v", err)
	}
	res2, _ := h.svc.Login(ctx, "ops@acme.io", password, client)
	if _, _, err := h.svc.VerifyMFA(ctx, res2.PendingToken, code, client); !errors.Is(err, admin.ErrInvalidMFACode) {
		t.Fatalf("replay: got %v, want ErrInvalidMFACode", err)
	}
}

func TestPendingSessionCannotAuthenticateAndExpires(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.setPassword(t)
	res, _ := h.svc.Login(ctx, "ops@acme.io", password, client)

	if _, err := h.svc.Authenticate(ctx, res.PendingToken); err == nil {
		t.Fatal("a pending (password-only) session must not authenticate")
	}
	h.clock = h.clock.Add(admin.PendingMFATTL + time.Second)
	code, _ := totp.Code(res.Secret, h.clock)
	if _, _, err := h.svc.VerifyMFA(ctx, res.PendingToken, code, client); !errors.Is(err, admin.ErrInvalidMFACode) {
		t.Fatalf("expired pending: %v", err)
	}
}

func TestWrongCodeCountsTowardLockout(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.setPassword(t)
	res, _ := h.svc.Login(ctx, "ops@acme.io", password, client)
	if _, _, err := h.svc.VerifyMFA(ctx, res.PendingToken, "000000", client); !errors.Is(err, admin.ErrInvalidMFACode) {
		t.Fatalf("wrong code: %v", err)
	}
	if h.admin.FailedLoginCount() != 1 {
		t.Fatalf("failed count %d, want 1", h.admin.FailedLoginCount())
	}
}

func TestIdleSessionExpires(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, token := h.enroll(t)

	h.clock = h.clock.Add(20 * time.Minute)
	if _, err := h.svc.Authenticate(ctx, token); err != nil {
		t.Fatalf("active use within idle window: %v", err)
	}
	h.clock = h.clock.Add(admin.SessionIdleTimeout + time.Second)
	if _, err := h.svc.Authenticate(ctx, token); err == nil {
		t.Fatal("idle session must expire")
	}
}

func TestSetPasswordRules(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.svc.SetPassword(ctx, h.admin, "", "short", false, client); !errors.Is(err, admin.ErrWeakPassword) {
		t.Fatalf("weak: %v", err)
	}
	_, token := h.enroll(t)

	// Session path must supply the current password.
	if err := h.svc.SetPassword(ctx, h.admin, "not the password", "another long password", true, client); !errors.Is(err, admin.ErrCurrentPassword) {
		t.Fatalf("wrong current: %v", err)
	}
	if err := h.svc.SetPassword(ctx, h.admin, password, "another long password", true, client); err != nil {
		t.Fatalf("change: %v", err)
	}
	// Changing the password ends existing sessions.
	if _, err := h.svc.Authenticate(ctx, token); err == nil {
		t.Fatal("session must end after password change")
	}
}

func TestResetCredentialsEndsAccess(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, token := h.enroll(t)
	actor, _, _ := admin.NewAdminUser("root@acme.io", "Root", admin.AdminRoleSuperAdmin, nil)

	if err := h.svc.ResetCredentials(ctx, actor, h.admin.ID(), client); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Authenticate(ctx, token); err == nil {
		t.Fatal("sessions must end on reset")
	}
	if _, err := h.svc.Login(ctx, "ops@acme.io", password, client); !errors.Is(err, admin.ErrInvalidCredentials) {
		t.Fatalf("login after reset: %v", err)
	}
	if !h.audit.has(ActionCredentialsReset) {
		t.Fatal("reset must be audited")
	}
}

func TestLogoutEndsSession(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, token := h.enroll(t)
	if err := h.svc.Logout(ctx, token, client); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Authenticate(ctx, token); err == nil {
		t.Fatal("logged-out session must not authenticate")
	}
	if h.console.sessionCount() != 0 {
		t.Fatalf("sessions left: %d", h.console.sessionCount())
	}
}
