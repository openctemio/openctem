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
	userLink         map[string]string // user id -> admin id
	memberUsers      map[string]bool   // user ids that belong to an organization
}

func (f *fakeAdmins) GetByUserID(_ context.Context, userID shared.ID) (*admin.AdminUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.userLink[userID.String()]; ok {
		return f.byID[id], nil
	}
	return nil, admin.ErrAdminNotFound
}

func (f *fakeAdmins) Create(_ context.Context, a *admin.AdminUser) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byID[a.ID().String()] = a
	return nil
}

func (f *fakeAdmins) Delete(_ context.Context, id shared.ID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.byID, id.String())
	return nil
}

func (f *fakeAdmins) LinkUser(_ context.Context, adminID, userID shared.ID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.memberUsers[userID.String()] {
		return admin.ErrUserHasMemberships
	}
	if _, taken := f.userLink[userID.String()]; taken {
		return admin.ErrUserAlreadyAdmin
	}
	f.userLink[userID.String()] = adminID.String()
	return nil
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

// fakeAccounts stands in for the auth service: refresh tokens name signed-in
// users, and provisioning creates or reuses accounts by email.
type fakeAccounts struct {
	mu       sync.Mutex
	sessions map[string]*SignedInUser // refresh token -> user
	byEmail  map[string]shared.ID
}

func (f *fakeAccounts) SignedInUser(_ context.Context, token string) (*SignedInUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.sessions[token]; ok {
		return u, nil
	}
	return nil, errors.New("invalid refresh token")
}

func (f *fakeAccounts) EndSignIn(_ context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sessions, token)
	return nil
}

func (f *fakeAccounts) ProvisionAccount(_ context.Context, email, _ string) (shared.ID, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.byEmail[strings.ToLower(email)]; ok {
		return id, "", nil
	}
	id := shared.NewID()
	f.byEmail[strings.ToLower(email)] = id
	return id, "Temp-Password-1!", nil
}

// ---- harness ---------------------------------------------------------------

// refresh is the admin's normal /login session (password sign-in).
const refresh = "refresh-token-of-ops"

type harness struct {
	svc      *Service
	admins   *fakeAdmins
	console  *fakeConsole
	audit    *fakeAudit
	accounts *fakeAccounts
	admin    *admin.AdminUser
	user     *SignedInUser
	clock    time.Time
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
	u := &SignedInUser{UserID: shared.NewID(), Email: "ops@acme.io", Name: "Ops", Active: true, PasswordSignIn: true}
	h := &harness{
		admins: &fakeAdmins{
			byID:        map[string]*admin.AdminUser{a.ID().String(): a},
			userLink:    map[string]string{u.UserID.String(): a.ID().String()},
			memberUsers: map[string]bool{},
		},
		console:  newFakeConsole(),
		audit:    &fakeAudit{},
		accounts: &fakeAccounts{sessions: map[string]*SignedInUser{refresh: u}, byEmail: map[string]shared.ID{"ops@acme.io": u.UserID}},
		admin:    a,
		user:     u,
		clock:    time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC),
	}
	h.svc = NewService(h.admins, h.console, h.audit, cipher, h.accounts, logger.NewNop())
	h.svc.now = func() time.Time { return h.clock }
	return h
}

var client = ClientInfo{IP: "203.0.113.7", UserAgent: "test"}

// enroll opens the console for the first time (TOTP enrollment) and returns
// the TOTP secret and a verified session token.
func (h *harness) enroll(t *testing.T) (secret, token string) {
	t.Helper()
	res, err := h.svc.Start(context.Background(), refresh, client)
	if err != nil {
		t.Fatalf("start: %v", err)
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

func TestEnrollmentThenStartWithMFA(t *testing.T) {
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

	// Next time: MFA already enrolled, no new secret is issued.
	h.clock = h.clock.Add(time.Minute)
	res, err := h.svc.Start(ctx, refresh, client)
	if err != nil || res.Status != StatusMFARequired || res.Secret != "" {
		t.Fatalf("second start: %+v %v", res, err)
	}
	code, _ := totp.Code(secret, h.clock)
	if _, _, err := h.svc.VerifyMFA(ctx, res.PendingToken, code, client); err != nil {
		t.Fatalf("second verify: %v", err)
	}
}

func TestStartRefusals(t *testing.T) {
	ctx := context.Background()

	t.Run("not signed in", func(t *testing.T) {
		h := newHarness(t)
		for _, tok := range []string{"", "forged"} {
			if _, err := h.svc.Start(ctx, tok, client); !errors.Is(err, admin.ErrNotSignedIn) {
				t.Fatalf("token %q: got %v, want ErrNotSignedIn", tok, err)
			}
		}
	})

	t.Run("signed-in user who is not an administrator", func(t *testing.T) {
		h := newHarness(t)
		h.accounts.sessions["member"] = &SignedInUser{UserID: shared.NewID(), Active: true, PasswordSignIn: true}
		if _, err := h.svc.Start(ctx, "member", client); !errors.Is(err, admin.ErrNotPlatformAdmin) {
			t.Fatalf("got %v, want ErrNotPlatformAdmin", err)
		}
	})

	t.Run("SSO sign-in cannot open the console", func(t *testing.T) {
		h := newHarness(t)
		h.user.PasswordSignIn = false
		if _, err := h.svc.Start(ctx, refresh, client); !errors.Is(err, admin.ErrPasswordSignInRequired) {
			t.Fatalf("got %v, want ErrPasswordSignInRequired", err)
		}
		if !h.audit.has(ActionLoginFailed) {
			t.Fatal("refused SSO attempt must be audited")
		}
	})

	t.Run("suspended user account", func(t *testing.T) {
		h := newHarness(t)
		h.user.Active = false
		if _, err := h.svc.Start(ctx, refresh, client); !errors.Is(err, admin.ErrNotSignedIn) {
			t.Fatalf("got %v, want ErrNotSignedIn", err)
		}
	})

	t.Run("deactivated administrator", func(t *testing.T) {
		h := newHarness(t)
		h.admin.Deactivate()
		if _, err := h.svc.Start(ctx, refresh, client); !errors.Is(err, admin.ErrNotPlatformAdmin) {
			t.Fatalf("got %v, want ErrNotPlatformAdmin", err)
		}
	})
}

func TestLockoutBlocksTheConsole(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for i := 0; i < admin.MaxFailedLoginAttempts; i++ {
		res, err := h.svc.Start(ctx, refresh, client)
		if err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		_, _, _ = h.svc.VerifyMFA(ctx, res.PendingToken, "000000", client)
	}
	if !h.admin.IsLocked() {
		t.Fatal("expected administrator locked after repeated wrong codes")
	}
	if _, err := h.svc.Start(ctx, refresh, client); !errors.Is(err, admin.ErrNotPlatformAdmin) {
		t.Fatalf("locked start: %v", err)
	}
}

func TestReplayedCodeIsRejected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	secret, _ := h.enroll(t)

	h.clock = h.clock.Add(totp.Period) // new step
	code, _ := totp.Code(secret, h.clock)
	res1, _ := h.svc.Start(ctx, refresh, client)
	if _, _, err := h.svc.VerifyMFA(ctx, res1.PendingToken, code, client); err != nil {
		t.Fatalf("first use: %v", err)
	}
	res2, _ := h.svc.Start(ctx, refresh, client)
	if _, _, err := h.svc.VerifyMFA(ctx, res2.PendingToken, code, client); !errors.Is(err, admin.ErrInvalidMFACode) {
		t.Fatalf("replay: got %v, want ErrInvalidMFACode", err)
	}
}

func TestPendingSessionCannotAuthenticateAndExpires(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	res, _ := h.svc.Start(ctx, refresh, client)

	if _, err := h.svc.Authenticate(ctx, res.PendingToken); err == nil {
		t.Fatal("a pending (pre-TOTP) session must not authenticate")
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
	res, _ := h.svc.Start(ctx, refresh, client)
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

func TestResetCredentialsRequiresReenrollment(t *testing.T) {
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
	res, err := h.svc.Start(ctx, refresh, client)
	if err != nil || res.Status != StatusMFAEnrollment {
		t.Fatalf("after reset the next start must re-enroll: %+v %v", res, err)
	}
	if !h.audit.has(ActionCredentialsReset) {
		t.Fatal("reset must be audited")
	}
}

func TestLogoutEndsSession(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, token := h.enroll(t)
	if err := h.svc.Logout(ctx, token, refresh, client); err != nil {
		t.Fatal(err)
	}
	// The /login session it was opened from ends too.
	if _, err := h.svc.Start(ctx, refresh, client); !errors.Is(err, admin.ErrNotSignedIn) {
		t.Fatalf("start after logout: got %v, want ErrNotSignedIn", err)
	}
	if _, err := h.svc.Authenticate(ctx, token); err == nil {
		t.Fatal("logged-out session must not authenticate")
	}
	if h.console.sessionCount() != 0 {
		t.Fatalf("sessions left: %d", h.console.sessionCount())
	}
}

func TestProvisionAdmin(t *testing.T) {
	ctx := context.Background()

	t.Run("new person gets a local account with a temporary password", func(t *testing.T) {
		h := newHarness(t)
		a, temp, err := h.svc.ProvisionAdmin(ctx, h.admin, "new@acme.io", "New", admin.AdminRoleOpsAdmin, client)
		if err != nil {
			t.Fatal(err)
		}
		if temp == "" || a.Role() != admin.AdminRoleOpsAdmin {
			t.Fatalf("temp=%q role=%s", temp, a.Role())
		}
		uid := h.accounts.byEmail["new@acme.io"]
		if linked, err := h.admins.GetByUserID(ctx, uid); err != nil || linked.ID() != a.ID() {
			t.Fatalf("administrator not linked to the account: %v", err)
		}
		if !h.audit.has(ActionAdminProvisioned) {
			t.Fatal("provisioning must be audited")
		}
	})

	t.Run("existing account is linked, no password issued", func(t *testing.T) {
		h := newHarness(t)
		uid := shared.NewID()
		h.accounts.byEmail["existing@acme.io"] = uid
		_, temp, err := h.svc.ProvisionAdmin(ctx, h.admin, "existing@acme.io", "Existing", admin.AdminRoleReadonly, client)
		if err != nil || temp != "" {
			t.Fatalf("temp=%q err=%v", temp, err)
		}
	})

	t.Run("organization member is refused and nothing is left behind", func(t *testing.T) {
		h := newHarness(t)
		uid := shared.NewID()
		h.accounts.byEmail["member@acme.io"] = uid
		h.admins.memberUsers[uid.String()] = true
		before := len(h.admins.byID)
		if _, _, err := h.svc.ProvisionAdmin(ctx, h.admin, "member@acme.io", "M", admin.AdminRoleReadonly, client); !errors.Is(err, admin.ErrUserHasMemberships) {
			t.Fatalf("got %v, want ErrUserHasMemberships", err)
		}
		if len(h.admins.byID) != before {
			t.Fatal("unlinked administrator row was left behind")
		}
	})

	t.Run("already an administrator", func(t *testing.T) {
		h := newHarness(t)
		if _, _, err := h.svc.ProvisionAdmin(ctx, h.admin, "OPS@acme.io", "Ops", admin.AdminRoleReadonly, client); !errors.Is(err, admin.ErrAdminAlreadyExists) {
			t.Fatalf("got %v, want ErrAdminAlreadyExists", err)
		}
	})
}
