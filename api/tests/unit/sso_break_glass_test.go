package unit

import (
	"context"
	"errors"
	"sync"
	"testing"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/mfa"
	"github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type adminNotice struct {
	mu    sync.Mutex
	calls []shared.ID
}

func (n *adminNotice) NotifyAdmins(_ context.Context, tenantID shared.ID, _, _, _ string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, tenantID)
}

type breakGlassHarness struct {
	svc    *auth.AuthService
	deps   *authTestDeps
	mfa    *fakeMFARepo
	audits *recordingAuthAuditRepo
	notice *adminNotice
}

func newBreakGlassHarness(t *testing.T) *breakGlassHarness {
	t.Helper()
	cfg := defaultAuthTestConfig()
	deps := &authTestDeps{
		userRepo: newMockAuthUserRepo(), sessionRepo: newMockAuthSessionRepo(),
		rtRepo: newMockAuthRefreshTokenRepo(), tenantRepo: newMockAuthTenantRepo(), cfg: cfg,
	}
	rec := &recordingAuthAuditRepo{}
	log := logger.NewNop()
	svc := auth.NewAuthService(deps.userRepo, deps.sessionRepo, deps.rtRepo, deps.tenantRepo,
		auditsvc.NewAuditService(rec, log), cfg, log)
	repo := newFakeMFARepo()
	n := &adminNotice{}
	svc.SetBreakGlassNotifier(n)
	return &breakGlassHarness{svc: svc, deps: deps, mfa: repo, audits: rec, notice: n}
}

// enableFactor turns two-factor on for the user after sign-in, so the sign-in
// itself stays a plain password login and the mint sees an enabled factor.
func (h *breakGlassHarness) enableFactor(t *testing.T, userID shared.ID) {
	t.Helper()
	cipher, err := crypto.NewCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	h.svc.SetMFA(h.mfa, cipher, "OpenCTEM")
	h.mfa.factors[userID.String()] = &mfa.Factor{Enabled: true}
}

// ownerOf records the user's owner membership of the organization.
func (h *breakGlassHarness) ownerOf(t *testing.T, userID, tenantID shared.ID) {
	t.Helper()
	m, err := tenant.NewMembership(userID, tenantID, tenant.RoleOwner, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h.deps.tenantRepo.membershipByTenant == nil {
		h.deps.tenantRepo.membershipByTenant = map[string]*tenant.Membership{}
	}
	h.deps.tenantRepo.membershipByTenant[tenantID.String()] = m
}

// Owner break-glass under Require SSO needs the owner's second factor too (F-20).
func TestBreakGlass_OwnerNeedsSecondFactor(t *testing.T) {
	ctx := context.Background()
	for _, op := range []string{"exchange", "refresh"} {
		t.Run(op, func(t *testing.T) {
			run := func(h *breakGlassHarness, rt, tid string) error {
				if op == "exchange" {
					_, err := h.svc.ExchangeToken(ctx, auth.ExchangeTokenInput{RefreshToken: rt, TenantID: tid})
					return err
				}
				_, err := h.svc.RefreshToken(ctx, auth.RefreshTokenInput{RefreshToken: rt, TenantID: tid})
				return err
			}

			t.Run("password alone is refused and not audited as break-glass", func(t *testing.T) {
				h := newBreakGlassHarness(t)
				tn := mustNewEnforcedTenant(t, h.deps.tenantRepo, "bg-nofactor", true)
				h.deps.tenantRepo.userMemberships = []tenant.UserMembership{{TenantID: tn.ID().String(), TenantSlug: tn.Slug(), TenantName: "Acme", Role: "owner"}}
				rt, _ := loginPassword(t, h.svc, h.deps, "owner-nofactor@acme.com")
				err := run(h, rt, tn.ID().String())
				if !errors.Is(err, auth.ErrSSOBreakGlassNeedsMFA) || !errors.Is(err, auth.ErrSSORequired) {
					t.Fatalf("want ErrSSOBreakGlassNeedsMFA, got %v", err)
				}
				if len(h.notice.calls) != 0 || len(breakGlassLogs(h.audits)) != 0 {
					t.Fatal("a refused attempt must not read as a break-glass sign-in")
				}
			})

			t.Run("password and second factor is admitted, audited and announced", func(t *testing.T) {
				h := newBreakGlassHarness(t)
				tn := mustNewEnforcedTenant(t, h.deps.tenantRepo, "bg-factor", true)
				h.deps.tenantRepo.userMemberships = []tenant.UserMembership{{TenantID: tn.ID().String(), TenantSlug: tn.Slug(), TenantName: "Acme", Role: "owner"}}
				rt, sessID := loginPassword(t, h.svc, h.deps, "owner-factor@acme.com")
				uid := h.deps.sessionRepo.sessions[sessID].UserID()
				h.ownerOf(t, uid, tn.ID())
				h.enableFactor(t, uid)
				if err := run(h, rt, tn.ID().String()); err != nil {
					t.Fatalf("owner with a second factor must get in, got %v", err)
				}
				logs := breakGlassLogs(h.audits)
				if len(logs) != 1 || logs[0].TenantID() == nil || *logs[0].TenantID() != tn.ID() {
					t.Fatalf("want one sso.break_glass_used entry for the org, got %d", len(logs))
				}
				if len(h.notice.calls) != 1 || h.notice.calls[0] != tn.ID() {
					t.Fatalf("other owners/admins were not told: %v", h.notice.calls)
				}
			})

			t.Run("no break-glass noise when the org does not enforce SSO", func(t *testing.T) {
				h := newBreakGlassHarness(t)
				tn := mustNewEnforcedTenant(t, h.deps.tenantRepo, "bg-open", false)
				h.deps.tenantRepo.userMemberships = []tenant.UserMembership{{TenantID: tn.ID().String(), TenantSlug: tn.Slug(), TenantName: "Acme", Role: "owner"}}
				rt, _ := loginPassword(t, h.svc, h.deps, "owner-open@acme.com")
				if err := run(h, rt, tn.ID().String()); err != nil {
					t.Fatal(err)
				}
				if len(h.notice.calls) != 0 || len(breakGlassLogs(h.audits)) != 0 {
					t.Fatal("an ordinary sign-in was recorded as break-glass")
				}
			})

			t.Run("owner signing in through the org's IdP is not break-glass", func(t *testing.T) {
				h := newBreakGlassHarness(t)
				tn := mustNewEnforcedTenant(t, h.deps.tenantRepo, "bg-sso", true)
				h.deps.tenantRepo.userMemberships = []tenant.UserMembership{{TenantID: tn.ID().String(), TenantSlug: tn.Slug(), TenantName: "Acme", Role: "owner"}}
				rt, sessID := loginPassword(t, h.svc, h.deps, "owner-sso@acme.com")
				federate(h.deps.sessionRepo.sessions[sessID], session.AuthMethodSAML, tn.ID())
				if err := run(h, rt, tn.ID().String()); err != nil {
					t.Fatal(err)
				}
				if len(h.notice.calls) != 0 || len(breakGlassLogs(h.audits)) != 0 {
					t.Fatal("an SSO sign-in was recorded as break-glass")
				}
			})
		})
	}
}

func breakGlassLogs(rec *recordingAuthAuditRepo) []*audit.AuditLog {
	var out []*audit.AuditLog
	for _, l := range rec.logs {
		if l.Action() == audit.ActionSSOBreakGlassUsed {
			out = append(out, l)
		}
	}
	return out
}

// fakeSSOStore is the Require SSO store with scripted answers.
type fakeSSOStore struct {
	signedIn, ownerFactor bool
	err                   error
	keys, grants          int
	revoked               bool
}

func (f *fakeSSOStore) HasAdminSSOSignIn(context.Context, shared.ID) (bool, error) {
	return f.signedIn, f.err
}
func (f *fakeSSOStore) HasOwnerWithSecondFactor(context.Context, shared.ID) (bool, error) {
	return f.ownerFactor, f.err
}
func (f *fakeSSOStore) CountCredentials(context.Context, shared.ID) (int, int, error) {
	return f.keys, f.grants, f.err
}
func (f *fakeSSOStore) RevokeCredentials(context.Context, shared.ID, shared.ID) (int, int, error) {
	f.revoked = true
	return f.keys, f.grants, f.err
}

func readySSOStore() *fakeSSOStore {
	return &fakeSSOStore{signedIn: true, ownerFactor: true, keys: 2, grants: 1}
}
