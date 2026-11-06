package adminconsole

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/totp"
)

// ---- in-memory fakes -------------------------------------------------------

type fakeAdmins struct {
	admin.Repository // unimplemented methods panic if a test reaches them
	mu               sync.Mutex
	byID             map[string]*admin.AdminUser
	userLink         map[string]string // user id -> admin id
}

func (f *fakeAdmins) RecordUsage(context.Context, shared.ID, string) error { return nil }

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
	// isBreakGlass answers DeletePasswordSessionsExceptBreakGlass.
	isBreakGlass func(adminID shared.ID) bool
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

func (f *fakeConsole) SetSessionElevation(_ context.Context, id shared.ID, role admin.AdminRole, until *time.Time, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.sessions {
		if s.ID == id && s.MFAVerified {
			s.ElevatedRole, s.ElevatedUntil = role, until
			return nil
		}
	}
	return admin.ErrSessionNotFound
}

func (f *fakeConsole) MarkSessionStepUp(_ context.Context, id shared.ID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.sessions {
		if s.ID == id && s.MFAVerified {
			s.StepUpAt = &at
			return nil
		}
	}
	return admin.ErrSessionNotFound
}

func (f *fakeConsole) ConsumeSessionStepUp(_ context.Context, id shared.ID, notBefore time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.sessions {
		if s.ID == id && s.MFAVerified && s.StepUpAt != nil && !s.StepUpAt.Before(notBefore) {
			s.StepUpAt = nil
			return true, nil
		}
	}
	return false, nil
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

func (f *fakeConsole) EndOldestVerifiedSessions(_ context.Context, id shared.ID, keep int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var mine []*admin.Session
	for _, s := range f.sessions {
		if s.AdminID == id && s.MFAVerified {
			mine = append(mine, s)
		}
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].CreatedAt.After(mine[j].CreatedAt) })
	var n int64
	for i := keep; i < len(mine); i++ {
		delete(f.sessions, mine[i].TokenHash)
		n++
	}
	return n, nil
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
	entries []*admin.AuditLog
	// fail makes every write return an error (an unavailable audit table).
	fail bool
}

func (f *fakeAudit) Create(_ context.Context, l *admin.AuditLog) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("audit table unavailable")
	}
	f.actions = append(f.actions, l.Action)
	f.entries = append(f.entries, l)
	return nil
}

// last returns the newest entry of an action, or nil.
func (f *fakeAudit) last(action string) *admin.AuditLog {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.entries) - 1; i >= 0; i-- {
		if f.entries[i].Action == action {
			return f.entries[i]
		}
	}
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
	mu        sync.Mutex
	sessions  map[string]*SignedInUser // sign-in email -> account
	byEmail   map[string]shared.ID
	suspended map[string]bool
	passwords map[string]string // user id -> password
	resets    int               // RecordPasswordSuccess calls
	failures  int               // RecordPasswordFailure calls
	lockedFor map[string]bool   // sign-in email -> directory reports a locked tenant account
}

func (f *fakeAccounts) RecordPasswordFailure(_ context.Context, _ shared.ID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures++
}

func (f *fakeAccounts) RecordPasswordSuccess(_ context.Context, _ shared.ID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resets++
}

// VerifyPassword: sessions maps the email the test signs in with to the
// account; its password is passwords[user id], or the shared test password.
func (f *fakeAccounts) VerifyPassword(_ context.Context, email, pw string, _ ClientInfo) (*SignedInUser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.sessions[email]
	if !ok {
		return nil, admin.ErrInvalidCredentials
	}
	if f.lockedFor[email] {
		return nil, admin.ErrAccountLocked
	}
	want, ok := f.passwords[u.UserID.String()]
	if !ok {
		want = password
	}
	if pw != want {
		return nil, admin.ErrInvalidCredentials
	}
	return u, nil
}

func (f *fakeAccounts) CreateInvitedAccount(_ context.Context, email, _ string, ttl time.Duration) (shared.ID, Invitation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.byEmail[strings.ToLower(email)]; ok {
		return shared.ID{}, Invitation{}, admin.ErrEmailHasAccount
	}
	id := shared.NewID()
	f.byEmail[strings.ToLower(email)] = id
	return id, Invitation{Token: "invite-token-" + id.String(), ExpiresAt: time.Now().Add(ttl)}, nil
}

// fakeInvites is the invitation mailer: it records what would be emailed.
type fakeInvites struct {
	can     bool
	sendErr error
	sent    []sentInvite
}

type sentInvite struct{ to, token string }

func (f *fakeInvites) CanDeliver(context.Context) bool { return f.can }
func (f *fakeInvites) SetupURL(token string) string {
	return "https://app.example.test/set-password#token=" + token
}
func (f *fakeInvites) SendAdminInvitation(_ context.Context, email, _, token string, _ time.Duration) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, sentInvite{to: email, token: token})
	return nil
}

func (f *fakeAccounts) AccountActive(_ context.Context, userID shared.ID) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.suspended[userID.String()], nil
}

func (f *fakeAccounts) ChangePassword(_ context.Context, userID shared.ID, current, next string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.passwords[userID.String()] != current {
		return errors.New("current password is incorrect")
	}
	f.passwords[userID.String()] = next
	return nil
}

// ---- harness ---------------------------------------------------------------

const password = "Current-Pass-123"

// refresh is the email the admin signs in to the console with.
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
	u := &SignedInUser{UserID: shared.NewID(), Email: "ops@acme.io", Name: "Ops", Active: true}
	now := time.Now()
	a := admin.Reconstitute(shared.NewID(), "ops@acme.io", "Ops", admin.AdminRoleSuperAdmin, true,
		&u.UserID, nil, "", 0, nil, nil, "", now, nil, now)
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		admins: &fakeAdmins{
			byID:     map[string]*admin.AdminUser{a.ID().String(): a},
			userLink: map[string]string{u.UserID.String(): a.ID().String()},
		},
		console: newFakeConsole(),
		audit:   &fakeAudit{},
		accounts: &fakeAccounts{
			sessions:  map[string]*SignedInUser{refresh: u},
			byEmail:   map[string]shared.ID{"ops@acme.io": u.UserID},
			suspended: map[string]bool{},
			passwords: map[string]string{u.UserID.String(): password},
		},
		admin: a,
		user:  u,
		clock: time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC),
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
	res, err := h.svc.Start(context.Background(), refresh, password, client)
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
	res, err := h.svc.Start(ctx, refresh, password, client)
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

	t.Run("wrong password or unknown email answer the same", func(t *testing.T) {
		h := newHarness(t)
		for _, tc := range []struct{ email, pw string }{{"", password}, {"nobody@acme.io", password}, {refresh, "wrong"}, {refresh, ""}} {
			if _, err := h.svc.Start(ctx, tc.email, tc.pw, client); !errors.Is(err, admin.ErrInvalidCredentials) {
				t.Fatalf("%q/%q: got %v, want ErrInvalidCredentials", tc.email, tc.pw, err)
			}
		}
	})

	t.Run("signed-in user who is not an administrator", func(t *testing.T) {
		h := newHarness(t)
		h.accounts.sessions["member"] = &SignedInUser{UserID: shared.NewID(), Active: true}
		if _, err := h.svc.Start(ctx, "member", password, client); !errors.Is(err, admin.ErrInvalidCredentials) {
			t.Fatalf("got %v, want ErrInvalidCredentials", err)
		}
	})

	t.Run("non-admin, inactive and locked admins never reset the lockout counter", func(t *testing.T) {
		h := newHarness(t)
		h.accounts.sessions["member"] = &SignedInUser{UserID: shared.NewID(), Active: true}
		_, _ = h.svc.Start(ctx, "member", password, client)
		h.admin.Deactivate()
		_, _ = h.svc.Start(ctx, refresh, password, client)
		if h.accounts.resets != 0 {
			t.Fatalf("lockout counter reset %d times for refused accounts", h.accounts.resets)
		}
	})

	t.Run("an accepted administrator resets the counter once", func(t *testing.T) {
		h := newHarness(t)
		if _, err := h.svc.Start(ctx, refresh, password, client); err != nil {
			t.Fatal(err)
		}
		if h.accounts.resets != 1 {
			t.Fatalf("resets = %d, want 1", h.accounts.resets)
		}
	})

	t.Run("suspended user account", func(t *testing.T) {
		h := newHarness(t)
		h.user.Active = false
		if _, err := h.svc.Start(ctx, refresh, password, client); !errors.Is(err, admin.ErrInvalidCredentials) {
			t.Fatalf("got %v, want ErrInvalidCredentials", err)
		}
	})

	t.Run("locked tenant account answers like a wrong password", func(t *testing.T) {
		h := newHarness(t)
		h.accounts.lockedFor = map[string]bool{refresh: true}
		if _, err := h.svc.Start(ctx, refresh, password, client); !errors.Is(err, admin.ErrInvalidCredentials) {
			t.Fatalf("got %v, want ErrInvalidCredentials", err)
		}
	})

	t.Run("deactivated administrator", func(t *testing.T) {
		h := newHarness(t)
		h.admin.Deactivate()
		if _, err := h.svc.Start(ctx, refresh, password, client); !errors.Is(err, admin.ErrInvalidCredentials) {
			t.Fatalf("got %v, want ErrInvalidCredentials", err)
		}
	})
}

func TestLockoutBlocksTheConsole(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for i := 0; i < admin.MaxFailedLoginAttempts; i++ {
		res, err := h.svc.Start(ctx, refresh, password, client)
		if err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		_, _, _ = h.svc.VerifyMFA(ctx, res.PendingToken, "000000", client)
	}
	if !h.admin.IsLocked() {
		t.Fatal("expected administrator locked after repeated wrong codes")
	}
	if _, err := h.svc.Start(ctx, refresh, password, client); !errors.Is(err, admin.ErrInvalidCredentials) {
		t.Fatalf("locked start: %v", err)
	}
}

func TestReplayedCodeIsRejected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	secret, _ := h.enroll(t)

	h.clock = h.clock.Add(totp.Period) // new step
	code, _ := totp.Code(secret, h.clock)
	res1, _ := h.svc.Start(ctx, refresh, password, client)
	if _, _, err := h.svc.VerifyMFA(ctx, res1.PendingToken, code, client); err != nil {
		t.Fatalf("first use: %v", err)
	}
	res2, _ := h.svc.Start(ctx, refresh, password, client)
	if _, _, err := h.svc.VerifyMFA(ctx, res2.PendingToken, code, client); !errors.Is(err, admin.ErrInvalidMFACode) {
		t.Fatalf("replay: got %v, want ErrInvalidMFACode", err)
	}
}

func TestPendingSessionCannotAuthenticateAndExpires(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	res, _ := h.svc.Start(ctx, refresh, password, client)

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
	res, _ := h.svc.Start(ctx, refresh, password, client)
	if _, _, err := h.svc.VerifyMFA(ctx, res.PendingToken, "000000", client); !errors.Is(err, admin.ErrInvalidMFACode) {
		t.Fatalf("wrong code: %v", err)
	}
	if h.admin.FailedLoginCount() != 1 {
		t.Fatalf("failed count %d, want 1", h.admin.FailedLoginCount())
	}
}

func TestFourthVerifiedSessionEndsTheOldest(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	secret, first := h.enroll(t)
	tokens := []string{first}
	for i := 0; i < 3; i++ {
		h.clock = h.clock.Add(time.Minute)
		res, err := h.svc.Start(ctx, refresh, password, client)
		if err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		code, _ := totp.Code(secret, h.clock)
		tok, _, err := h.svc.VerifyMFA(ctx, res.PendingToken, code, client)
		if err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
		tokens = append(tokens, tok)
	}
	if _, err := h.svc.Authenticate(ctx, tokens[0]); err == nil {
		t.Fatal("the oldest session must have been ended by the fourth")
	}
	for _, tok := range tokens[1:] {
		if _, err := h.svc.Authenticate(ctx, tok); err != nil {
			t.Fatalf("a newer session must stay: %v", err)
		}
	}
	if !h.audit.has(ActionSessionEvicted) {
		t.Fatalf("eviction must be audited, got %v", h.audit.actions)
	}
}

func TestIdleSessionExpires(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, token := h.enroll(t)

	h.clock = h.clock.Add(admin.SessionIdleTimeout - time.Minute)
	if _, err := h.svc.Authenticate(ctx, token); err != nil {
		t.Fatalf("active use within idle window: %v", err)
	}
	// Use keeps it alive past one idle window in total.
	h.clock = h.clock.Add(admin.SessionIdleTimeout - time.Minute)
	if _, err := h.svc.Authenticate(ctx, token); err != nil {
		t.Fatalf("second use within idle window: %v", err)
	}
	h.clock = h.clock.Add(admin.SessionIdleTimeout + time.Second)
	if _, err := h.svc.Authenticate(ctx, token); err == nil {
		t.Fatal("idle session must expire")
	}
}

// An open console tab refreshes its pages on a timer. Those background reads
// authenticate but must not keep the session alive: an unattended tab still
// signs out after the idle timeout.
func TestBackgroundReadsDoNotPreventIdleTimeout(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	bg := admin.WithBackgroundRequest(ctx)
	_, token := h.enroll(t)

	for elapsed := time.Duration(0); elapsed < admin.SessionIdleTimeout-time.Minute; elapsed += 30 * time.Second {
		h.clock = h.clock.Add(30 * time.Second)
		if _, err := h.svc.Authenticate(bg, token); err != nil {
			t.Fatalf("background read within the idle window must authenticate: %v", err)
		}
	}
	h.clock = h.clock.Add(2 * time.Minute)
	if _, err := h.svc.Authenticate(bg, token); err == nil {
		t.Fatal("a session used only by background reads must idle out")
	}
}

func TestInteractiveReadKeepsSessionAliveBetweenBackgroundReads(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	bg := admin.WithBackgroundRequest(ctx)
	_, token := h.enroll(t)

	h.clock = h.clock.Add(admin.SessionIdleTimeout - time.Minute)
	if _, err := h.svc.Authenticate(ctx, token); err != nil {
		t.Fatalf("interactive use: %v", err)
	}
	h.clock = h.clock.Add(admin.SessionIdleTimeout - time.Minute)
	if _, err := h.svc.Authenticate(bg, token); err != nil {
		t.Fatalf("background read after recent activity: %v", err)
	}
}

// A password reset or change on the account's own sign-in (forgot password,
// change password, two-step reset) ends the linked administrator's console
// sessions: a stolen console session must not outlive the password.
func TestEndSessionsForAccountEndsConsoleSessions(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, token := h.enroll(t)
	if _, err := h.svc.Authenticate(ctx, token); err != nil {
		t.Fatalf("session before the change: %v", err)
	}

	h.svc.EndSessionsForAccount(ctx, *h.admin.UserID())

	if _, err := h.svc.Authenticate(ctx, token); err == nil {
		t.Fatal("console session must end when the linked account's sessions are revoked")
	}
	if !h.audit.has(ActionSessionsEndedByAccount) {
		t.Fatal("ending the sessions must be audited")
	}
}

// An account that is not an administrator is ignored (most password resets).
func TestEndSessionsForAccountIgnoresNonAdmins(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, token := h.enroll(t)

	h.svc.EndSessionsForAccount(ctx, shared.NewID())

	if _, err := h.svc.Authenticate(ctx, token); err != nil {
		t.Fatalf("another account's change must not end this session: %v", err)
	}
	if h.audit.has(ActionSessionsEndedByAccount) {
		t.Fatal("nothing to audit for an account without an administrator")
	}
}

func TestResetCredentialsRequiresReenrollment(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, token := h.enroll(t)
	actor, _ := admin.NewAdminUser("root@acme.io", "Root", admin.AdminRoleSuperAdmin, nil)

	if err := h.svc.ResetCredentials(ctx, actor, h.admin.ID(), client); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Authenticate(ctx, token); err == nil {
		t.Fatal("sessions must end on reset")
	}
	res, err := h.svc.Start(ctx, refresh, password, client)
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

type recordingEnder struct{ ended []shared.ID }

func (r *recordingEnder) EndForConsoleSession(_ context.Context, id shared.ID) {
	r.ended = append(r.ended, id)
}

// Signing out ends the support sessions the console session opened; an unknown
// token ends nothing.
func TestLogoutEndsSupportSessions(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	rec := &recordingEnder{}
	h.svc.SetSupportSessionEnder(rec)
	_, token := h.enroll(t)
	_, sess, err := h.svc.AuthenticateSession(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.svc.Logout(ctx, "not-a-token", client); err != nil || len(rec.ended) != 0 {
		t.Fatalf("unknown token: %v ended=%v", err, rec.ended)
	}
	if err := h.svc.Logout(ctx, token, client); err != nil {
		t.Fatal(err)
	}
	if len(rec.ended) != 1 || rec.ended[0] != sess.ID {
		t.Fatalf("ended = %v, want the signed-out console session %v", rec.ended, sess.ID)
	}
}

func TestProvisionAdmin(t *testing.T) {
	ctx := context.Background()
	provision := func(h *harness, email string, role admin.AdminRole, approvals bool) (*Provisioned, error) {
		return h.svc.Provision(ctx, h.admin, ProvisionInput{Email: email, Name: "New", Role: role, ApprovalsActive: approvals}, client)
	}

	t.Run("new person gets an emailed invitation and nobody learns a password", func(t *testing.T) {
		h := newHarness(t)
		mail := &fakeInvites{can: true}
		h.svc.SetInvitationMailer(mail)
		res, err := provision(h, "new@acme.io", admin.AdminRoleOpsAdmin, false)
		if err != nil {
			t.Fatal(err)
		}
		if res.Admin.Role() != admin.AdminRoleOpsAdmin || !res.Emailed || res.SetupLink != "" {
			t.Fatalf("want an emailed invitation and no link for the caller: %+v", res)
		}
		if len(mail.sent) != 1 || mail.sent[0].to != "new@acme.io" || mail.sent[0].token == "" {
			t.Fatalf("invitation not sent to the new address: %+v", mail.sent)
		}
		if res.Admin.PasswordChangeRequired() {
			t.Fatal("the administrator chooses their own password; no temporary one exists")
		}
		uid := h.accounts.byEmail["new@acme.io"]
		if linked, err := h.admins.GetByUserID(ctx, uid); err != nil || linked.ID() != res.Admin.ID() {
			t.Fatalf("administrator not linked to the account: %v", err)
		}
		e := h.audit.last(ActionAdminProvisioned)
		if e == nil {
			t.Fatal("provisioning must be audited")
		}
		if e.RequestBody["invitation_emailed"] != true || e.RequestBody["setup_link_returned"] != false {
			t.Fatalf("the audit row must say how the invitation was delivered: %v", e.RequestBody)
		}
		if strings.Contains(fmt.Sprint(e.RequestBody), mail.sent[0].token) {
			t.Fatal("the audit row must not carry the token")
		}
	})

	// The four-eyes bypass: the requester of a super admin must never be able
	// to obtain anything that signs in as the account the second administrator
	// approved.
	t.Run("a super admin with approvals on and no mail is refused and nothing is created", func(t *testing.T) {
		h := newHarness(t)
		h.svc.SetInvitationMailer(&fakeInvites{can: false})
		before := len(h.admins.byID)
		if _, err := provision(h, "bob@acme.io", admin.AdminRoleSuperAdmin, true); !errors.Is(err, ErrInvitationNeedsEmail) {
			t.Fatalf("got %v, want ErrInvitationNeedsEmail", err)
		}
		if len(h.admins.byID) != before || h.accounts.byEmail["bob@acme.io"] != (shared.ID{}) {
			t.Fatal("no administrator or account may be created")
		}
	})
	t.Run("without any mailer a super admin with approvals on is refused too", func(t *testing.T) {
		h := newHarness(t)
		if _, err := provision(h, "bob@acme.io", admin.AdminRoleSuperAdmin, true); !errors.Is(err, ErrInvitationNeedsEmail) {
			t.Fatalf("got %v, want ErrInvitationNeedsEmail", err)
		}
	})
	t.Run("a super admin with approvals on and mail never gets the link in the response", func(t *testing.T) {
		h := newHarness(t)
		mail := &fakeInvites{can: true}
		h.svc.SetInvitationMailer(mail)
		res, err := provision(h, "bob@acme.io", admin.AdminRoleSuperAdmin, true)
		if err != nil || !res.Emailed || res.SetupLink != "" {
			t.Fatalf("want emailed and no link: %+v %v", res, err)
		}
	})
	t.Run("a failed send never falls back to showing the link", func(t *testing.T) {
		h := newHarness(t)
		h.svc.SetInvitationMailer(&fakeInvites{can: true, sendErr: errors.New("relay down")})
		res, err := provision(h, "bob@acme.io", admin.AdminRoleSuperAdmin, true)
		if err != nil || res.Emailed || !res.EmailFailed || res.SetupLink != "" {
			t.Fatalf("want a failed send and no link: %+v %v", res, err)
		}
	})
	t.Run("no mail: the link is shown once for a non-super role", func(t *testing.T) {
		h := newHarness(t)
		h.svc.SetInvitationMailer(&fakeInvites{can: false})
		res, err := provision(h, "ro@acme.io", admin.AdminRoleReadonly, true)
		if err != nil || res.Emailed || res.SetupLink == "" {
			t.Fatalf("want the link for a read-only role: %+v %v", res, err)
		}
		if e := h.audit.last(ActionAdminProvisioned); e == nil || e.RequestBody["setup_link_returned"] != true {
			t.Fatalf("the audit row must record that the link was returned: %v", e)
		}
		if e := h.audit.last(ActionInvitationLinkDisclosed); e == nil || e.Severity != admin.SeverityCritical {
			t.Fatalf("showing the link needs its own critical audit row: %v", e)
		}
	})
	t.Run("no mail: the link is shown once for a super admin only while approvals are off", func(t *testing.T) {
		h := newHarness(t)
		h.svc.SetInvitationMailer(&fakeInvites{can: false})
		res, err := provision(h, "bob@acme.io", admin.AdminRoleSuperAdmin, false)
		if err != nil || res.SetupLink == "" {
			t.Fatalf("approvals off: want the link: %+v %v", res, err)
		}
	})

	// Pre-registration takeover: an attacker self-registers the email a super
	// admin is about to provision. Linking that account would make the
	// attacker, who owns its password, the administrator.
	t.Run("an email that already has an account is refused and nothing is left behind", func(t *testing.T) {
		h := newHarness(t)
		h.svc.SetInvitationMailer(&fakeInvites{can: true})
		h.accounts.byEmail["victim@acme.io"] = shared.NewID() // registered by someone else
		before := len(h.admins.byID)
		if _, err := provision(h, "victim@acme.io", admin.AdminRoleSuperAdmin, false); !errors.Is(err, admin.ErrEmailHasAccount) {
			t.Fatalf("got %v, want ErrEmailHasAccount", err)
		}
		if len(h.admins.byID) != before {
			t.Fatal("an administrator row was left behind")
		}
	})

	t.Run("already an administrator", func(t *testing.T) {
		h := newHarness(t)
		if _, err := provision(h, "OPS@acme.io", admin.AdminRoleReadonly, false); !errors.Is(err, admin.ErrAdminAlreadyExists) {
			t.Fatalf("got %v, want ErrAdminAlreadyExists", err)
		}
	})
}

func TestSuspendedAccountEndsConsoleSession(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, token := h.enroll(t)
	h.accounts.suspended[h.user.UserID.String()] = true
	if _, err := h.svc.Authenticate(ctx, token); err == nil {
		t.Fatal("a suspended account must lose console access immediately")
	}
	if h.console.sessionCount() != 0 {
		t.Fatalf("sessions left: %d", h.console.sessionCount())
	}
}

func TestChangePasswordEndsConsoleSessions(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, token := h.enroll(t)
	if err := h.svc.ChangePassword(ctx, h.admin, "wrong", "Another-Long-Pass-1", client); err == nil {
		t.Fatal("wrong current password must be refused")
	}
	if _, err := h.svc.Authenticate(ctx, token); err != nil {
		t.Fatalf("a refused change must not end the session: %v", err)
	}
	if err := h.svc.ChangePassword(ctx, h.admin, password, "Another-Long-Pass-1", client); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Authenticate(ctx, token); err == nil {
		t.Fatal("console sessions must end after a password change")
	}
	if !h.audit.has(ActionPasswordChanged) {
		t.Fatal("password change must be audited")
	}
}
