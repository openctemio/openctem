package unit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/mfa"
	"github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/password"
	"github.com/openctemio/openctem/api/pkg/totp"
)

// =============================================================================
// In-memory fakes with the same semantics as the postgres implementations
// =============================================================================

type fakeMFARepo struct {
	mu         sync.Mutex
	factors    map[string]*mfa.Factor
	codes      map[string][]*mfa.RecoveryCode
	challenges map[string]*mfa.Challenge // by token hash
}

func newFakeMFARepo() *fakeMFARepo {
	return &fakeMFARepo{
		factors:    map[string]*mfa.Factor{},
		codes:      map[string][]*mfa.RecoveryCode{},
		challenges: map[string]*mfa.Challenge{},
	}
}

func (r *fakeMFARepo) GetFactor(_ context.Context, userID shared.ID) (*mfa.Factor, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.factors[userID.String()]
	if !ok {
		return nil, mfa.ErrFactorNotFound
	}
	cp := *f
	return &cp, nil
}

func (r *fakeMFARepo) SavePendingSecret(_ context.Context, userID shared.ID, enc string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.factors[userID.String()]
	if !ok {
		f = &mfa.Factor{UserID: userID}
		r.factors[userID.String()] = f
	}
	now := time.Now()
	f.PendingSecretEncrypted = enc
	f.PendingCreatedAt = &now
	return nil
}

func (r *fakeMFARepo) Activate(_ context.Context, userID shared.ID, step int64, hashes []string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.factors[userID.String()]
	if !ok || f.PendingSecretEncrypted == "" {
		return false, nil
	}
	now := time.Now()
	f.SecretEncrypted = f.PendingSecretEncrypted
	f.PendingSecretEncrypted = ""
	f.PendingCreatedAt = nil
	f.Enabled = true
	f.EnabledAt = &now
	f.LastUsedStep = step
	r.replaceLocked(userID, hashes)
	return true, nil
}

func (r *fakeMFARepo) Disable(_ context.Context, userID shared.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.factors, userID.String())
	delete(r.codes, userID.String())
	return nil
}

func (r *fakeMFARepo) AdvanceStep(_ context.Context, userID shared.ID, step int64) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.factors[userID.String()]
	if !ok || !f.Enabled || f.LastUsedStep >= step {
		return false, nil
	}
	f.LastUsedStep = step
	return true, nil
}

func (r *fakeMFARepo) ListUnusedRecoveryCodes(_ context.Context, userID shared.ID) ([]mfa.RecoveryCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []mfa.RecoveryCode
	for _, c := range r.codes[userID.String()] {
		if c.UsedAt == nil {
			out = append(out, *c)
		}
	}
	return out, nil
}

func (r *fakeMFARepo) ConsumeRecoveryCode(_ context.Context, userID, codeID shared.ID) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.codes[userID.String()] {
		if c.ID.Equals(codeID) && c.UsedAt == nil {
			now := time.Now()
			c.UsedAt = &now
			return true, nil
		}
	}
	return false, nil
}

func (r *fakeMFARepo) ReplaceRecoveryCodes(_ context.Context, userID shared.ID, hashes []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.replaceLocked(userID, hashes)
	return nil
}

func (r *fakeMFARepo) replaceLocked(userID shared.ID, hashes []string) {
	list := make([]*mfa.RecoveryCode, 0, len(hashes))
	for _, h := range hashes {
		list = append(list, &mfa.RecoveryCode{ID: shared.NewID(), UserID: userID, CodeHash: h})
	}
	r.codes[userID.String()] = list
}

func (r *fakeMFARepo) CreateChallenge(_ context.Context, c *mfa.Challenge) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := *c
	r.challenges[c.TokenHash] = &cp
	return nil
}

func (r *fakeMFARepo) GetChallengeByTokenHash(_ context.Context, h string) (*mfa.Challenge, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.challenges[h]
	if !ok {
		return nil, mfa.ErrChallengeNotFound
	}
	cp := *c
	return &cp, nil
}

func (r *fakeMFARepo) byID(id shared.ID) *mfa.Challenge {
	for _, c := range r.challenges {
		if c.ID.Equals(id) {
			return c
		}
	}
	return nil
}

func (r *fakeMFARepo) RecordChallengeAttempt(_ context.Context, id shared.ID) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.byID(id)
	if c == nil {
		return 0, mfa.ErrChallengeNotFound
	}
	c.Attempts++
	return c.Attempts, nil
}

func (r *fakeMFARepo) ConsumeChallenge(_ context.Context, id shared.ID) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.byID(id)
	if c == nil || c.ConsumedAt != nil || !time.Now().Before(c.ExpiresAt) {
		return false, nil
	}
	now := time.Now()
	c.ConsumedAt = &now
	return true, nil
}

func (r *fakeMFARepo) DeleteExpiredChallenges(_ context.Context) (int64, error) { return 0, nil }

// mfaSessionRepo tracks session status so revocation can be asserted.
type mfaSessionRepo struct {
	*mockAuthSessionRepo
}

func (m *mfaSessionRepo) GetActiveByUserID(_ context.Context, userID shared.ID) ([]*session.Session, error) {
	var out []*session.Session
	for _, s := range m.sessions {
		if s.UserID().Equals(userID) && s.IsActive() {
			out = append(out, s)
		}
	}
	return out, nil
}

func (m *mfaSessionRepo) RevokeAllByUserID(_ context.Context, userID shared.ID) error {
	for _, s := range m.sessions {
		if s.UserID().Equals(userID) && s.IsActive() {
			_ = s.Revoke()
		}
	}
	return nil
}

func (m *mfaSessionRepo) RevokeAllByUserIDExcept(_ context.Context, userID, except shared.ID) error {
	for _, s := range m.sessions {
		if s.UserID().Equals(userID) && !s.ID().Equals(except) && s.IsActive() {
			_ = s.Revoke()
		}
	}
	return nil
}

type fakeRevocations struct {
	mu      sync.Mutex
	revoked map[string]time.Duration
}

func (f *fakeRevocations) MarkSessionRevoked(_ context.Context, id string, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revoked == nil {
		f.revoked = map[string]time.Duration{}
	}
	f.revoked[id] = ttl
	return nil
}

func (f *fakeRevocations) has(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.revoked[id]
	return ok
}

type capturingAuditRepo struct {
	mockAuthAuditRepo
	mu      sync.Mutex
	actions []audit.Action
}

func (c *capturingAuditRepo) Create(_ context.Context, l *audit.AuditLog) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.actions = append(c.actions, l.Action())
	return nil
}

func (c *capturingAuditRepo) has(a audit.Action) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, x := range c.actions {
		if x == a {
			return true
		}
	}
	return false
}

type fakeNotifier struct {
	mu                       sync.Mutex
	mfaDisabled, recoveryUse int
	passwordChanged          int
	lastRemaining            int
}

func (n *fakeNotifier) NotifyMFADisabled(context.Context, string, string, string) {
	n.mu.Lock()
	n.mfaDisabled++
	n.mu.Unlock()
}

func (n *fakeNotifier) NotifyRecoveryCodeUsed(_ context.Context, _, _, _ string, remaining int) {
	n.mu.Lock()
	n.recoveryUse++
	n.lastRemaining = remaining
	n.mu.Unlock()
}

func (n *fakeNotifier) NotifyPasswordChanged(context.Context, string, string, string) {
	n.mu.Lock()
	n.passwordChanged++
	n.mu.Unlock()
}

// =============================================================================
// Harness
// =============================================================================

type mfaHarness struct {
	svc         *app.AuthService
	users       *mockAuthUserRepo
	sessions    *mfaSessionRepo
	tenants     *mockAuthTenantRepo
	mfa         *fakeMFARepo
	revocations *fakeRevocations
	audits      *capturingAuditRepo
	notifier    *fakeNotifier
}

const mfaTestPassword = "ValidPassword123"

func newMFAHarness(t *testing.T) *mfaHarness {
	t.Helper()
	users := newMockAuthUserRepo()
	sessions := &mfaSessionRepo{newMockAuthSessionRepo()}
	tenants := newMockAuthTenantRepo()
	audits := &capturingAuditRepo{}
	cfg := defaultAuthTestConfig()
	svc := app.NewAuthService(users, sessions, newMockAuthRefreshTokenRepo(), tenants,
		app.NewAuditService(audits, logger.NewNop()), cfg, logger.NewNop())
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	h := &mfaHarness{
		svc: svc, users: users, sessions: sessions, tenants: tenants,
		mfa: newFakeMFARepo(), revocations: &fakeRevocations{}, audits: audits, notifier: &fakeNotifier{},
	}
	svc.SetMFA(h.mfa, cipher, "OpenCTEM")
	svc.SetSessionRevocationStore(h.revocations)
	svc.SetSecurityNotifier(h.notifier)
	return h
}

func (h *mfaHarness) seedUser(t *testing.T, email string) shared.ID {
	t.Helper()
	hash, _ := password.New(password.WithCost(4)).Hash(mfaTestPassword)
	return seedAuthLocalUser(h.users, email, hash).ID()
}

func (h *mfaHarness) login(t *testing.T, email string) *app.LoginResult {
	t.Helper()
	res, err := h.svc.Login(context.Background(), app.LoginInput{Email: email, Password: mfaTestPassword})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	return res
}

// enroll turns 2FA on for the user and returns the secret and recovery codes.
func (h *mfaHarness) enroll(t *testing.T, userID shared.ID) (string, []string) {
	t.Helper()
	setup, err := h.svc.BeginMFASetup(context.Background(), userID.String())
	if err != nil {
		t.Fatalf("BeginMFASetup: %v", err)
	}
	code, _ := totp.Code(setup.Secret, time.Now())
	codes, err := h.svc.EnableMFA(context.Background(), app.AuditContext{ActorID: userID.String()}, userID.String(), mfaTestPassword, code)
	if err != nil {
		t.Fatalf("EnableMFA: %v", err)
	}
	return setup.Secret, codes
}

// forgetLastStep lets a test use a fresh TOTP code in the same 30s window by
// pretending the previous step was never used (the replay test does not).
func (h *mfaHarness) forgetLastStep(userID shared.ID) {
	h.mfa.mu.Lock()
	defer h.mfa.mu.Unlock()
	if f, ok := h.mfa.factors[userID.String()]; ok {
		f.LastUsedStep = 0
	}
}

func currentCode(t *testing.T, secret string) string {
	t.Helper()
	c, err := totp.Code(secret, time.Now())
	if err != nil {
		t.Fatalf("totp.Code: %v", err)
	}
	return c
}

func wrongCode(right string) string {
	if right == "000000" {
		return "111111"
	}
	return "000000"
}

func newPolicyTenant(t *testing.T, repo *mockAuthTenantRepo, slug string, required bool) *tenant.Tenant {
	t.Helper()
	tn, err := tenant.NewTenant("Acme", slug, "creator")
	if err != nil {
		t.Fatalf("NewTenant: %v", err)
	}
	st := tn.TypedSettings()
	st.Security.MFARequired = required
	if err := tn.UpdateSettings(st); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}
	repo.tenants[tn.ID().String()] = tn
	return tn
}

// =============================================================================
// Enrollment
// =============================================================================

func TestMFA_Enrollment(t *testing.T) {
	t.Run("setup + enable with a valid code turns 2FA on with 10 recovery codes", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "a@example.com")

		_, codes := h.enroll(t, uid)

		if len(codes) != mfa.RecoveryCodeCount {
			t.Fatalf("want %d recovery codes, got %d", mfa.RecoveryCodeCount, len(codes))
		}
		seen := map[string]bool{}
		for _, c := range codes {
			if len(c) != 11 || c[5] != '-' {
				t.Errorf("recovery code %q not in xxxxx-xxxxx form", c)
			}
			if seen[c] {
				t.Errorf("duplicate recovery code %q", c)
			}
			seen[c] = true
		}
		st, err := h.svc.GetMFAStatus(context.Background(), uid.String())
		if err != nil {
			t.Fatalf("GetMFAStatus: %v", err)
		}
		if !st.Enabled || !st.Supported || st.RecoveryCodesRemaining != 10 {
			t.Fatalf("unexpected status %+v", st)
		}
		if !h.audits.has(audit.ActionAuthMFAEnabled) {
			t.Error("auth.mfa_enabled was not audited")
		}
	})

	t.Run("secret is encrypted at rest and recovery codes are hashed", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "enc@example.com")
		secret, codes := h.enroll(t, uid)

		f := h.mfa.factors[uid.String()]
		if f.SecretEncrypted == "" || strings.Contains(f.SecretEncrypted, secret) {
			t.Fatalf("secret stored in plaintext: %q", f.SecretEncrypted)
		}
		for _, rc := range h.mfa.codes[uid.String()] {
			for _, c := range codes {
				plain := strings.ReplaceAll(c, "-", "")
				if strings.Contains(rc.CodeHash, plain) {
					t.Fatal("recovery code stored in plaintext")
				}
			}
			if !strings.HasPrefix(rc.CodeHash, "$2") {
				t.Fatalf("recovery code hash is not bcrypt: %q", rc.CodeHash)
			}
		}
	})

	t.Run("wrong code does not enable", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "b@example.com")
		setup, _ := h.svc.BeginMFASetup(context.Background(), uid.String())
		_, err := h.svc.EnableMFA(context.Background(), app.AuditContext{}, uid.String(), mfaTestPassword, wrongCode(currentCode(t, setup.Secret)))
		if !errors.Is(err, app.ErrMFACodeInvalid) {
			t.Fatalf("want ErrMFACodeInvalid, got %v", err)
		}
		st, _ := h.svc.GetMFAStatus(context.Background(), uid.String())
		if st.Enabled {
			t.Fatal("2FA enabled after a wrong code")
		}
		// A pending secret alone must not make login ask for a code.
		if res := h.login(t, "b@example.com"); res.MFAChallenge != nil {
			t.Fatal("pending (unconfirmed) setup must not change login")
		}
	})

	t.Run("enable without setup is refused", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "c@example.com")
		_, err := h.svc.EnableMFA(context.Background(), app.AuditContext{}, uid.String(), mfaTestPassword, "123456")
		if !errors.Is(err, app.ErrMFANoPendingSetup) {
			t.Fatalf("want ErrMFANoPendingSetup, got %v", err)
		}
	})

	t.Run("setup while enabled is refused", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "d@example.com")
		h.enroll(t, uid)
		if _, err := h.svc.BeginMFASetup(context.Background(), uid.String()); !errors.Is(err, app.ErrMFAAlreadyEnabled) {
			t.Fatalf("want ErrMFAAlreadyEnabled, got %v", err)
		}
	})

	t.Run("federated account cannot enroll; status says unsupported", func(t *testing.T) {
		h := newMFAHarness(t)
		u := seedAuthOIDCUser(h.users, "sso@example.com")
		if _, err := h.svc.BeginMFASetup(context.Background(), u.ID().String()); !errors.Is(err, app.ErrMFANotSupported) {
			t.Fatalf("want ErrMFANotSupported, got %v", err)
		}
		st, err := h.svc.GetMFAStatus(context.Background(), u.ID().String())
		if err != nil || st.Supported {
			t.Fatalf("federated status must be unsupported: %+v %v", st, err)
		}
	})

	t.Run("enabling signs out every other session but keeps the current one", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "e@example.com")
		cur := h.login(t, "e@example.com")
		other := h.login(t, "e@example.com")

		setup, _ := h.svc.BeginMFASetup(context.Background(), uid.String())
		_, err := h.svc.EnableMFA(context.Background(),
			app.AuditContext{ActorID: uid.String(), SessionID: cur.SessionID}, uid.String(), mfaTestPassword, currentCode(t, setup.Secret))
		if err != nil {
			t.Fatalf("EnableMFA: %v", err)
		}
		if !h.sessions.sessions[cur.SessionID].IsActive() {
			t.Error("current session was revoked")
		}
		if h.sessions.sessions[other.SessionID].IsActive() {
			t.Error("other session survived enabling 2FA")
		}
		if !h.revocations.has(other.SessionID) || h.revocations.has(cur.SessionID) {
			t.Error("immediate revocation must cover exactly the other session")
		}
	})
}

// =============================================================================
// Login with a second factor
// =============================================================================

func TestMFA_Login(t *testing.T) {
	t.Run("password login returns a challenge and creates no session or token", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "l@example.com")
		h.enroll(t, uid)
		before := len(h.sessions.sessions)

		res := h.login(t, "l@example.com")

		if res.MFAChallenge == nil || res.MFAChallenge.Purpose != mfa.PurposeVerify {
			t.Fatalf("expected a verify challenge, got %+v", res.MFAChallenge)
		}
		if res.RefreshToken != "" || res.SessionID != "" {
			t.Fatal("a session/refresh token was issued before the second factor")
		}
		if len(h.sessions.sessions) != before {
			t.Fatal("a session row was created before the second factor")
		}
	})

	t.Run("challenge token is not an access token", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "tok@example.com")
		h.enroll(t, uid)
		res := h.login(t, "tok@example.com")
		if _, err := h.svc.ValidateAccessToken(res.MFAChallenge.Token); err == nil {
			t.Fatal("MFA challenge validated as an access token")
		}
	})

	t.Run("valid code completes the login", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "v@example.com")
		secret, _ := h.enroll(t, uid)
		h.forgetLastStep(uid)
		ch := h.login(t, "v@example.com").MFAChallenge

		res, err := h.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: ch.Token, Code: currentCode(t, secret)})
		if err != nil {
			t.Fatalf("VerifyMFALogin: %v", err)
		}
		if res.RefreshToken == "" || res.SessionID == "" || res.MFAChallenge != nil {
			t.Fatalf("expected a full login result, got %+v", res)
		}
	})

	t.Run("wrong code is rejected and counts toward the lockout", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "w@example.com")
		secret, _ := h.enroll(t, uid)
		ch := h.login(t, "w@example.com").MFAChallenge

		_, err := h.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: ch.Token, Code: wrongCode(currentCode(t, secret))})
		if !errors.Is(err, app.ErrMFACodeInvalid) {
			t.Fatalf("want ErrMFACodeInvalid, got %v", err)
		}
		if got := h.users.users[uid.String()].FailedLoginAttempts(); got != 1 {
			t.Fatalf("failed attempts = %d, want 1", got)
		}
		if !h.audits.has(audit.ActionAuthMFAFailed) {
			t.Error("auth.mfa_failed was not audited")
		}
	})

	t.Run("a code already used in its time step is rejected (replay)", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "r@example.com")
		secret, _ := h.enroll(t, uid)
		h.forgetLastStep(uid)
		code := currentCode(t, secret)

		ch1 := h.login(t, "r@example.com").MFAChallenge
		if _, err := h.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: ch1.Token, Code: code}); err != nil {
			t.Fatalf("first use: %v", err)
		}
		ch2 := h.login(t, "r@example.com").MFAChallenge
		_, err := h.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: ch2.Token, Code: code})
		if !errors.Is(err, app.ErrMFACodeInvalid) {
			t.Fatalf("replayed code: want ErrMFACodeInvalid, got %v", err)
		}
	})

	t.Run("challenge is single-use", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "s@example.com")
		secret, _ := h.enroll(t, uid)
		h.forgetLastStep(uid)
		ch := h.login(t, "s@example.com").MFAChallenge
		if _, err := h.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: ch.Token, Code: currentCode(t, secret)}); err != nil {
			t.Fatalf("first: %v", err)
		}
		h.forgetLastStep(uid)
		_, err := h.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: ch.Token, Code: currentCode(t, secret)})
		if !errors.Is(err, app.ErrMFAChallengeInvalid) {
			t.Fatalf("reused challenge: want ErrMFAChallengeInvalid, got %v", err)
		}
	})

	t.Run("expired challenge is rejected", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "x@example.com")
		secret, _ := h.enroll(t, uid)
		ch := h.login(t, "x@example.com").MFAChallenge
		for _, c := range h.mfa.challenges {
			c.ExpiresAt = time.Now().Add(-time.Second)
		}
		_, err := h.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: ch.Token, Code: currentCode(t, secret)})
		if !errors.Is(err, app.ErrMFAChallengeInvalid) {
			t.Fatalf("want ErrMFAChallengeInvalid, got %v", err)
		}
	})

	t.Run("unknown token is rejected", func(t *testing.T) {
		h := newMFAHarness(t)
		_, err := h.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: "nope", Code: "123456"})
		if !errors.Is(err, app.ErrMFAChallengeInvalid) {
			t.Fatalf("want ErrMFAChallengeInvalid, got %v", err)
		}
	})

	t.Run("verify token cannot be used for enrollment", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "p@example.com")
		h.enroll(t, uid)
		ch := h.login(t, "p@example.com").MFAChallenge
		if _, err := h.svc.BeginMFAEnrollmentFromChallenge(context.Background(), ch.Token); !errors.Is(err, app.ErrMFAChallengeInvalid) {
			t.Fatalf("want ErrMFAChallengeInvalid, got %v", err)
		}
	})

	t.Run("correct password does not reset the counter while a code is pending", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "lock@example.com")
		secret, _ := h.enroll(t, uid)
		bad := wrongCode(currentCode(t, secret))

		// 3 misses, fresh password login, 2 more misses = 5 = MaxLoginAttempts.
		ch := h.login(t, "lock@example.com").MFAChallenge
		for i := 0; i < 3; i++ {
			_, _ = h.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: ch.Token, Code: bad})
		}
		ch = h.login(t, "lock@example.com").MFAChallenge
		for i := 0; i < 2; i++ {
			_, _ = h.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: ch.Token, Code: bad})
		}
		if !h.users.users[uid.String()].IsLocked() {
			t.Fatal("account not locked after 5 wrong second factors")
		}
		_, err := h.svc.Login(context.Background(), app.LoginInput{Email: "lock@example.com", Password: mfaTestPassword})
		if !errors.Is(err, app.ErrAccountLocked) {
			t.Fatalf("locked account login: want ErrAccountLocked, got %v", err)
		}
	})

	t.Run("challenge is burned after the attempt limit", func(t *testing.T) {
		cfgH := newMFAHarness(t)
		uid := cfgH.seedUser(t, "burn@example.com")
		secret, _ := cfgH.enroll(t, uid)
		ch := cfgH.login(t, "burn@example.com").MFAChallenge
		// Avoid the account lockout so only the per-challenge cap applies.
		for i := 0; i < mfa.MaxChallengeAttempts; i++ {
			cfgH.users.users[uid.String()].Unlock()
			_, _ = cfgH.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: ch.Token, Code: wrongCode(currentCode(t, secret))})
		}
		cfgH.users.users[uid.String()].Unlock()
		cfgH.forgetLastStep(uid)
		_, err := cfgH.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: ch.Token, Code: currentCode(t, secret)})
		if !errors.Is(err, app.ErrMFAChallengeInvalid) {
			t.Fatalf("want ErrMFAChallengeInvalid after %d attempts, got %v", mfa.MaxChallengeAttempts, err)
		}
	})
}

// =============================================================================
// Recovery codes
// =============================================================================

func TestMFA_RecoveryCodes(t *testing.T) {
	t.Run("a recovery code signs in exactly once", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "rc@example.com")
		_, codes := h.enroll(t, uid)

		ch := h.login(t, "rc@example.com").MFAChallenge
		res, err := h.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: ch.Token, RecoveryCode: strings.ToUpper(codes[3])})
		if err != nil || res.RefreshToken == "" {
			t.Fatalf("recovery login failed: %v", err)
		}
		if !h.audits.has(audit.ActionAuthMFARecoveryCodeUsed) {
			t.Error("auth.mfa_recovery_code_used was not audited")
		}
		if h.notifier.recoveryUse != 1 || h.notifier.lastRemaining != 9 {
			t.Errorf("notifier: uses=%d remaining=%d", h.notifier.recoveryUse, h.notifier.lastRemaining)
		}

		ch = h.login(t, "rc@example.com").MFAChallenge
		_, err = h.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: ch.Token, RecoveryCode: codes[3]})
		if !errors.Is(err, app.ErrMFACodeInvalid) {
			t.Fatalf("reused recovery code: want ErrMFACodeInvalid, got %v", err)
		}
		st, _ := h.svc.GetMFAStatus(context.Background(), uid.String())
		if st.RecoveryCodesRemaining != 9 {
			t.Fatalf("remaining = %d, want 9", st.RecoveryCodesRemaining)
		}
	})

	t.Run("regenerate needs a TOTP code and invalidates the old codes", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "regen@example.com")
		secret, old := h.enroll(t, uid)

		if _, err := h.svc.RegenerateRecoveryCodes(context.Background(), app.AuditContext{}, uid.String(), old[0]); !errors.Is(err, app.ErrMFACodeInvalid) {
			t.Fatalf("recovery code must not regenerate codes, got %v", err)
		}
		h.forgetLastStep(uid)
		fresh, err := h.svc.RegenerateRecoveryCodes(context.Background(), app.AuditContext{}, uid.String(), currentCode(t, secret))
		if err != nil || len(fresh) != mfa.RecoveryCodeCount {
			t.Fatalf("regenerate: %v (%d codes)", err, len(fresh))
		}
		if !h.audits.has(audit.ActionAuthMFARecoveryCodesRegenerated) {
			t.Error("regeneration was not audited")
		}
		ch := h.login(t, "regen@example.com").MFAChallenge
		if _, err := h.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: ch.Token, RecoveryCode: old[1]}); !errors.Is(err, app.ErrMFACodeInvalid) {
			t.Fatalf("old code still works after regeneration: %v", err)
		}
		ch = h.login(t, "regen@example.com").MFAChallenge
		if _, err := h.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: ch.Token, RecoveryCode: fresh[0]}); err != nil {
			t.Fatalf("new code rejected: %v", err)
		}
	})
}

// =============================================================================
// Disable
// =============================================================================

func TestMFA_Disable(t *testing.T) {
	setup := func(t *testing.T) (*mfaHarness, shared.ID, string) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "off@example.com")
		secret, _ := h.enroll(t, uid)
		h.forgetLastStep(uid)
		return h, uid, secret
	}

	t.Run("needs the current password", func(t *testing.T) {
		h, uid, secret := setup(t)
		err := h.svc.DisableMFA(context.Background(), app.AuditContext{}, uid.String(), "wrong", currentCode(t, secret))
		if !errors.Is(err, app.ErrPasswordMismatch) {
			t.Fatalf("want ErrPasswordMismatch, got %v", err)
		}
	})

	t.Run("needs a valid code", func(t *testing.T) {
		h, uid, secret := setup(t)
		err := h.svc.DisableMFA(context.Background(), app.AuditContext{}, uid.String(), mfaTestPassword, wrongCode(currentCode(t, secret)))
		if !errors.Is(err, app.ErrMFACodeInvalid) {
			t.Fatalf("want ErrMFACodeInvalid, got %v", err)
		}
	})

	t.Run("password + code disables, audits, notifies, and login stops asking", func(t *testing.T) {
		h, uid, secret := setup(t)
		if err := h.svc.DisableMFA(context.Background(), app.AuditContext{}, uid.String(), mfaTestPassword, currentCode(t, secret)); err != nil {
			t.Fatalf("DisableMFA: %v", err)
		}
		if !h.audits.has(audit.ActionAuthMFADisabled) || h.notifier.mfaDisabled != 1 {
			t.Error("disable was not audited/notified")
		}
		if res := h.login(t, "off@example.com"); res.MFAChallenge != nil {
			t.Fatal("login still asks for a code after disabling")
		}
	})

	t.Run("a recovery code also works", func(t *testing.T) {
		h := newMFAHarness(t)
		uid := h.seedUser(t, "off2@example.com")
		_, codes := h.enroll(t, uid)
		if err := h.svc.DisableMFA(context.Background(), app.AuditContext{}, uid.String(), mfaTestPassword, codes[0]); err != nil {
			t.Fatalf("DisableMFA with recovery code: %v", err)
		}
	})
}

// =============================================================================
// Organization policy
// =============================================================================

func TestMFA_OrganizationPolicy(t *testing.T) {
	t.Run("unenrolled member of a 2FA-required org is sent to enrollment, then signed in", func(t *testing.T) {
		h := newMFAHarness(t)
		tn := newPolicyTenant(t, h.tenants, "req-tenant", true)
		h.tenants.userMemberships = []tenant.UserMembership{{TenantID: tn.ID().String(), TenantSlug: tn.Slug(), TenantName: "Acme", Role: "member"}}
		uid := h.seedUser(t, "pol@example.com")

		res := h.login(t, "pol@example.com")
		if res.MFAChallenge == nil || res.MFAChallenge.Purpose != mfa.PurposeEnroll || res.RefreshToken != "" {
			t.Fatalf("expected an enrollment challenge and no session, got %+v", res)
		}
		// The enrollment challenge cannot be used as a verify challenge.
		if _, err := h.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: res.MFAChallenge.Token, Code: "123456"}); !errors.Is(err, app.ErrMFAChallengeInvalid) {
			t.Fatalf("enroll token accepted at verify: %v", err)
		}

		setup, err := h.svc.BeginMFAEnrollmentFromChallenge(context.Background(), res.MFAChallenge.Token)
		if err != nil {
			t.Fatalf("BeginMFAEnrollmentFromChallenge: %v", err)
		}
		done, codes, err := h.svc.CompleteMFAEnrollmentFromChallenge(context.Background(), app.CompleteMFAEnrollmentInput{
			Token: res.MFAChallenge.Token, Code: currentCode(t, setup.Secret),
		})
		if err != nil {
			t.Fatalf("CompleteMFAEnrollmentFromChallenge: %v", err)
		}
		if len(codes) != mfa.RecoveryCodeCount || done.RefreshToken == "" {
			t.Fatalf("expected codes + session, got %d codes, rt=%q", len(codes), done.RefreshToken)
		}
		if _, err := h.svc.ExchangeToken(context.Background(), app.ExchangeTokenInput{RefreshToken: done.RefreshToken, TenantID: tn.ID().String()}); err != nil {
			t.Fatalf("exchange after enrollment: %v", err)
		}
		if st, _ := h.svc.GetMFAStatus(context.Background(), uid.String()); !st.Enabled || !st.RequiredByOrganization {
			t.Fatalf("status after forced enrollment: %+v", st)
		}
	})

	t.Run("token exchange and refresh refuse a password session without 2FA", func(t *testing.T) {
		h := newMFAHarness(t)
		tn := newPolicyTenant(t, h.tenants, "later", false)
		h.tenants.userMemberships = []tenant.UserMembership{{TenantID: tn.ID().String(), TenantSlug: tn.Slug(), TenantName: "Acme", Role: "admin"}}
		h.seedUser(t, "late@example.com")
		res := h.login(t, "late@example.com") // policy off: plain session
		ex, err := h.svc.ExchangeToken(context.Background(), app.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: tn.ID().String()})
		if err != nil {
			t.Fatalf("exchange before policy: %v", err)
		}

		// The owner turns the policy on.
		st := tn.TypedSettings()
		st.Security.MFARequired = true
		_ = tn.UpdateSettings(st)

		if _, err := h.svc.RefreshToken(context.Background(), app.RefreshTokenInput{RefreshToken: ex.RefreshToken, TenantID: tn.ID().String()}); !errors.Is(err, app.ErrMFAEnrollmentRequired) {
			t.Fatalf("refresh must not bypass the 2FA policy: %v", err)
		}
		res2 := h.login(t, "late@example.com")
		if res2.MFAChallenge == nil || res2.MFAChallenge.Purpose != mfa.PurposeEnroll {
			t.Fatal("login after policy must require enrollment")
		}
	})

	t.Run("sessions from the tenant's own IdP are not double-prompted", func(t *testing.T) {
		h := newMFAHarness(t)
		tn := newPolicyTenant(t, h.tenants, "fed-tenant", false)
		h.tenants.userMemberships = []tenant.UserMembership{{TenantID: tn.ID().String(), TenantSlug: tn.Slug(), TenantName: "Acme", Role: "member"}}
		h.seedUser(t, "fed@example.com")
		res := h.login(t, "fed@example.com")
		h.sessions.sessions[res.SessionID].SetAuthMethod(session.AuthMethodSSO)
		h.sessions.sessions[res.SessionID].SetIDPTenant(tn.ID()) // issued by this tenant's IdP
		st := tn.TypedSettings()
		st.Security.MFARequired = true
		_ = tn.UpdateSettings(st)
		if _, err := h.svc.ExchangeToken(context.Background(), app.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: tn.ID().String()}); err != nil {
			t.Fatalf("federated session blocked by 2FA policy: %v", err)
		}
	})

	t.Run("enrolled user passes the gate", func(t *testing.T) {
		h := newMFAHarness(t)
		tn := newPolicyTenant(t, h.tenants, "ok-tenant", true)
		h.tenants.userMemberships = []tenant.UserMembership{{TenantID: tn.ID().String(), TenantSlug: tn.Slug(), TenantName: "Acme", Role: "member"}}
		uid := h.seedUser(t, "ok@example.com")
		secret, _ := h.enroll(t, uid)
		h.forgetLastStep(uid)
		ch := h.login(t, "ok@example.com").MFAChallenge
		res, err := h.svc.VerifyMFALogin(context.Background(), app.VerifyMFAInput{Token: ch.Token, Code: currentCode(t, secret)})
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if _, err := h.svc.ExchangeToken(context.Background(), app.ExchangeTokenInput{RefreshToken: res.RefreshToken, TenantID: tn.ID().String()}); err != nil {
			t.Fatalf("enrolled user blocked: %v", err)
		}
	})
}

// =============================================================================
// Password change and session revocation
// =============================================================================

func TestMFA_ChangePasswordKeepsCurrentSession(t *testing.T) {
	h := newMFAHarness(t)
	uid := h.seedUser(t, "pw@example.com")
	cur := h.login(t, "pw@example.com")
	other := h.login(t, "pw@example.com")

	err := h.svc.ChangePassword(context.Background(), uid.String(), app.ChangePasswordInput{
		CurrentPassword: mfaTestPassword, NewPassword: "AnotherPassword456", CurrentSessionID: cur.SessionID,
	})
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if !h.sessions.sessions[cur.SessionID].IsActive() {
		t.Error("the session that changed the password was signed out")
	}
	if h.sessions.sessions[other.SessionID].IsActive() || !h.revocations.has(other.SessionID) {
		t.Error("other session not revoked immediately")
	}
	if !h.audits.has(audit.ActionAuthPasswordChanged) || h.notifier.passwordChanged != 1 {
		t.Error("password change not audited/notified")
	}
}

func TestMFA_LogoutRecordsImmediateRevocation(t *testing.T) {
	h := newMFAHarness(t)
	h.seedUser(t, "out@example.com")
	res := h.login(t, "out@example.com")
	if err := h.svc.Logout(context.Background(), res.SessionID); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if !h.revocations.has(res.SessionID) {
		t.Fatal("logout did not record the session as revoked")
	}
}

func TestSessionService_RevocationIsImmediate(t *testing.T) {
	h := newMFAHarness(t)
	uid := h.seedUser(t, "sess@example.com")
	a := h.login(t, "sess@example.com")
	b := h.login(t, "sess@example.com")
	c := h.login(t, "sess@example.com")

	store := &fakeRevocations{}
	svc := app.NewSessionService(h.sessions, newMockAuthRefreshTokenRepo(), logger.NewNop())
	svc.SetRevocationStore(store, 16*time.Minute)

	if err := svc.RevokeSession(context.Background(), uid.String(), b.SessionID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if !store.has(b.SessionID) || store.revoked[b.SessionID] != 16*time.Minute {
		t.Fatal("single revoke not recorded with the configured TTL")
	}
	if err := svc.RevokeAllSessions(context.Background(), uid.String(), a.SessionID); err != nil {
		t.Fatalf("RevokeAllSessions: %v", err)
	}
	if !store.has(c.SessionID) || store.has(a.SessionID) {
		t.Fatal("revoke-all-others must record every other session and not the current one")
	}
	// Another user cannot revoke this user's session.
	if err := svc.RevokeSession(context.Background(), shared.NewID().String(), a.SessionID); err == nil {
		t.Fatal("revoked another user's session")
	}
}

// Enabling 2FA needs the current password, and wrong passwords count against
// the account lockout (settings audit A-M1, A-M2): a stolen session alone can
// neither bind an attacker's authenticator nor guess the password freely.
func TestEnableMFA_NeedsCurrentPassword(t *testing.T) {
	h := newMFAHarness(t)
	uid := h.seedUser(t, "pw@example.com")
	setup, err := h.svc.BeginMFASetup(context.Background(), uid.String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.svc.EnableMFA(context.Background(), app.AuditContext{}, uid.String(), "wrong", currentCode(t, setup.Secret))
	if !errors.Is(err, app.ErrPasswordMismatch) {
		t.Fatalf("enable with a wrong password: want ErrPasswordMismatch, got %v", err)
	}
	u := h.users.users[uid.String()]
	if u.FailedLoginAttempts() != 1 {
		t.Fatalf("failed attempts after a wrong password = %d, want 1", u.FailedLoginAttempts())
	}
	if _, err := h.svc.EnableMFA(context.Background(), app.AuditContext{}, uid.String(), mfaTestPassword, currentCode(t, setup.Secret)); err != nil {
		t.Fatalf("enable with the password: %v", err)
	}
}

// A stolen session cannot guess the current password through change-password
// without limit: each wrong guess counts against the account lockout, and a
// locked account takes no further guesses, even the right password.
func TestChangePassword_WrongPasswordCountsTowardLockout(t *testing.T) {
	h := newMFAHarness(t)
	uid := h.seedUser(t, "guess@example.com")
	ctx := context.Background()
	var err error
	for i := 0; i < 10; i++ {
		err = h.svc.ChangePassword(ctx, uid.String(), app.ChangePasswordInput{
			CurrentPassword: "wrong-guess", NewPassword: "AnotherPassword456",
		})
		if errors.Is(err, app.ErrAccountLocked) {
			break
		}
		if !errors.Is(err, app.ErrPasswordMismatch) {
			t.Fatalf("guess %d: want ErrPasswordMismatch, got %v", i, err)
		}
	}
	if !h.users.users[uid.String()].IsLocked() {
		t.Fatal("account not locked after repeated wrong passwords")
	}
	err = h.svc.ChangePassword(ctx, uid.String(), app.ChangePasswordInput{
		CurrentPassword: mfaTestPassword, NewPassword: "AnotherPassword456",
	})
	if !errors.Is(err, app.ErrAccountLocked) {
		t.Fatalf("locked account with the right password: want ErrAccountLocked, got %v", err)
	}
}
