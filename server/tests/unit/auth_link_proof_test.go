package unit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// linkProofSessions is a session store with step-up state: every session in
// live has just signed in (RecentAuthAt is now), and step-up stamps are
// counted so a test can assert a link proof never opens a window.
type linkProofSessions struct {
	*mfaSessionRepo
	mu    sync.Mutex
	live  map[string]bool
	marks int
}

func (s *linkProofSessions) RecentAuthAt(_ context.Context, sid, _ shared.ID) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.live[sid.String()] {
		return time.Time{}, session.ErrSessionNotFound
	}
	return time.Now(), nil
}

func (s *linkProofSessions) MarkStepUp(context.Context, shared.ID, shared.ID, time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.marks++
	return true, nil
}

func (s *linkProofSessions) signIn() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	sid := shared.NewID().String()
	s.live[sid] = true
	return sid
}

// newLinkProofHarness is newMFAHarness with a session store that has
// step-up state.
func newLinkProofHarness(t *testing.T) (*mfaHarness, *linkProofSessions) {
	t.Helper()
	users := newMockAuthUserRepo()
	inner := &mfaSessionRepo{newMockAuthSessionRepo()}
	sessions := &linkProofSessions{mfaSessionRepo: inner, live: map[string]bool{}}
	tenants := newMockAuthTenantRepo()
	audits := &capturingAuditRepo{}
	svc := authapp.NewAuthService(users, sessions, newMockAuthRefreshTokenRepo(), tenants,
		auditsvc.NewAuditService(audits, logger.NewNop()), defaultAuthTestConfig(), logger.NewNop())
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	h := &mfaHarness{
		svc: svc, users: users, sessions: inner, tenants: tenants,
		mfa: newFakeMFARepo(), revocations: &fakeRevocations{}, audits: audits, notifier: &fakeNotifier{},
	}
	svc.SetMFA(h.mfa, cipher, "OpenCTEM")
	svc.SetSessionRevocationStore(h.revocations)
	return h, sessions
}

func (c *capturingAuditRepo) count(a audit.Action) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, got := range c.actions {
		if got == a {
			n++
		}
	}
	return n
}

// Linking or unlinking a sign-in method needs a proof typed for that request
// (auth/link_proof.go): an authenticator code when the account has TOTP
// (never a recovery code, never a replayed step), else the password. A
// session that has just signed in is not a proof, and an account with
// neither factor cannot change its sign-in methods.
func TestLinkProof(t *testing.T) {
	ctx := context.Background()
	actx := auditsvc.AuditContext{}
	for _, purpose := range []string{authapp.LinkProofLinkStart, authapp.LinkProofPendingLink, authapp.LinkProofUnlink} {
		t.Run(purpose, func(t *testing.T) {
			t.Run("TOTP account: a fresh sign-in alone is refused", func(t *testing.T) {
				h, sess := newLinkProofHarness(t)
				id := h.seedUser(t, "t@example.com")
				h.enroll(t, id)
				sid := sess.signIn()
				if m, _ := h.svc.LinkProofMethod(ctx, id.String()); m != authapp.StepUpTOTP {
					t.Fatalf("method %q", m)
				}
				if _, err := h.svc.VerifyLinkProof(ctx, actx, id.String(), sid, authapp.StepUpProof{}, purpose); !errors.Is(err, authapp.ErrLinkProofRequired) {
					t.Fatalf("no code: %v", err)
				}
				if _, err := h.svc.VerifyLinkProof(ctx, actx, id.String(), sid, authapp.StepUpProof{Password: mfaTestPassword}, purpose); !errors.Is(err, authapp.ErrLinkProofRequired) {
					t.Fatalf("the password does not replace the code: %v", err)
				}
			})
			t.Run("TOTP account: valid code once; replay and recovery code refused", func(t *testing.T) {
				h, sess := newLinkProofHarness(t)
				id := h.seedUser(t, "t@example.com")
				secret, recovery := h.enroll(t, id)
				h.forgetLastStep(id)
				sid := sess.signIn()
				if _, err := h.svc.VerifyLinkProof(ctx, actx, id.String(), sid, authapp.StepUpProof{TOTP: recovery[0]}, purpose); !errors.Is(err, authapp.ErrLinkProofFailed) {
					t.Fatalf("recovery code: %v", err)
				}
				code := currentCode(t, secret)
				m, err := h.svc.VerifyLinkProof(ctx, actx, id.String(), sid, authapp.StepUpProof{TOTP: code}, purpose)
				if err != nil || m != authapp.StepUpTOTP {
					t.Fatalf("valid code: %q %v", m, err)
				}
				if _, err := h.svc.VerifyLinkProof(ctx, actx, id.String(), sid, authapp.StepUpProof{TOTP: code}, purpose); !errors.Is(err, authapp.ErrLinkProofFailed) {
					t.Fatalf("replayed code: %v", err)
				}
				if sess.marks != 0 {
					t.Fatalf("a link proof opened a step-up window (%d stamps)", sess.marks)
				}
				if h.audits.count(audit.ActionAuthStepUp) != 1 || h.audits.count(audit.ActionAuthStepUpFailed) != 2 {
					t.Fatalf("audit: %v", h.audits.actions)
				}
			})
			t.Run("password account needs the password", func(t *testing.T) {
				h, sess := newLinkProofHarness(t)
				id := h.seedUser(t, "p@example.com")
				sid := sess.signIn()
				if m, _ := h.svc.LinkProofMethod(ctx, id.String()); m != authapp.StepUpPassword {
					t.Fatalf("method %q", m)
				}
				if _, err := h.svc.VerifyLinkProof(ctx, actx, id.String(), sid, authapp.StepUpProof{}, purpose); !errors.Is(err, authapp.ErrLinkProofRequired) {
					t.Fatalf("no password: %v", err)
				}
				if _, err := h.svc.VerifyLinkProof(ctx, actx, id.String(), sid, authapp.StepUpProof{Password: "wrong-password"}, purpose); !errors.Is(err, authapp.ErrLinkProofFailed) {
					t.Fatalf("wrong password: %v", err)
				}
				m, err := h.svc.VerifyLinkProof(ctx, actx, id.String(), sid, authapp.StepUpProof{Password: mfaTestPassword}, purpose)
				if err != nil || m != authapp.StepUpPassword {
					t.Fatalf("right password: %q %v", m, err)
				}
			})
			t.Run("account with neither factor cannot change sign-in methods", func(t *testing.T) {
				h, sess := newLinkProofHarness(t)
				u, err := user.NewOAuthUser("g@example.com", "G", "", user.AuthProviderGoogle)
				if err != nil {
					t.Fatal(err)
				}
				_ = h.users.Create(ctx, u)
				sid := sess.signIn()
				if m, _ := h.svc.LinkProofMethod(ctx, u.ID().String()); m != "" {
					t.Fatalf("method %q", m)
				}
				if _, err := h.svc.VerifyLinkProof(ctx, actx, u.ID().String(), sid, authapp.StepUpProof{Password: "x"}, purpose); !errors.Is(err, authapp.ErrLinkProofUnavailable) {
					t.Fatalf("fresh session of an account without a factor: %v", err)
				}
			})
			t.Run("another or unknown session cannot spend a proof", func(t *testing.T) {
				h, _ := newLinkProofHarness(t)
				id := h.seedUser(t, "p@example.com")
				for _, sid := range []string{"", "not-an-id", shared.NewID().String()} {
					if _, err := h.svc.VerifyLinkProof(ctx, actx, id.String(), sid, authapp.StepUpProof{Password: mfaTestPassword}, purpose); !errors.Is(err, authapp.ErrLinkProofUnavailable) {
						t.Fatalf("session %q: %v", sid, err)
					}
				}
			})
			t.Run("failures lock the account", func(t *testing.T) {
				h, sess := newLinkProofHarness(t)
				id := h.seedUser(t, "l@example.com")
				sid := sess.signIn()
				var err error
				for range 20 {
					_, err = h.svc.VerifyLinkProof(ctx, actx, id.String(), sid, authapp.StepUpProof{Password: "wrong-password"}, purpose)
					if errors.Is(err, authapp.ErrAccountLocked) {
						break
					}
				}
				if !errors.Is(err, authapp.ErrAccountLocked) {
					t.Fatalf("no lockout after repeated failures: %v", err)
				}
				if _, err := h.svc.VerifyLinkProof(ctx, actx, id.String(), sid, authapp.StepUpProof{Password: mfaTestPassword}, purpose); err == nil {
					t.Fatal("a locked account changed its sign-in methods")
				}
			})
		})
	}
}
