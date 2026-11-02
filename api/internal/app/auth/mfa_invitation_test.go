package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/mfa"
	sessiondom "github.com/openctemio/openctem/api/pkg/domain/session"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type mfaInvTenantRepo struct {
	tenantdom.Repository
	tenant     *tenantdom.Tenant
	role       tenantdom.Role
	membership *tenantdom.Membership
	getMemErr  error
}

func (r *mfaInvTenantRepo) GetUserMemberships(context.Context, shared.ID) ([]tenantdom.UserMembership, error) {
	return []tenantdom.UserMembership{{TenantID: r.tenant.ID().String(), Role: string(r.role)}}, nil
}
func (r *mfaInvTenantRepo) GetByID(context.Context, shared.ID) (*tenantdom.Tenant, error) {
	return r.tenant, nil
}
func (r *mfaInvTenantRepo) GetMembership(context.Context, shared.ID, shared.ID) (*tenantdom.Membership, error) {
	return r.membership, r.getMemErr
}

func policyFixture(t *testing.T, sec tenantdom.SecuritySettings, role tenantdom.Role, email string, external bool) (*AuthService, shared.ID) {
	t.Helper()
	tn, err := tenantdom.NewTenant("Acme", "acme", "creator")
	if err != nil {
		t.Fatal(err)
	}
	if err := tn.UpdateSecuritySettings(sec); err != nil {
		t.Fatal(err)
	}
	uid := shared.NewID()
	m, err := tenantdom.NewMembership(uid, tn.ID(), role, nil)
	if err != nil {
		t.Fatal(err)
	}
	if external {
		domain := email[len(email)-len("gmail.com"):]
		if err := m.Classify(tenantdom.Classification{Kind: tenantdom.MemberKindExternal, Domain: domain, Personal: true},
			tenantdom.ExternalAccess{ExpiresAt: mfaInvPtrTime(time.Now().Add(24 * time.Hour))}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	return &AuthService{
		logger:     logger.NewNop(),
		tenantRepo: &mfaInvTenantRepo{tenant: tn, role: role, membership: m},
	}, uid
}

func mfaInvPtrTime(t time.Time) *time.Time { return &t }

// The login offers enrollment exactly when the token mint would refuse with
// ErrMFAEnrollmentRequired, under each of the three policies.
func TestMFARequiredByAnyOrganization_Policies(t *testing.T) {
	none := tenantdom.SecuritySettings{PersonalAccounts: tenantdom.PersonalAccountsAllowed}
	cases := []struct {
		name     string
		sec      tenantdom.SecuritySettings
		role     tenantdom.Role
		external bool
		want     bool
	}{
		{"no policy applies", none, tenantdom.RoleMember, false, false},
		{"org 2fa for everyone", tenantdom.SecuritySettings{MFARequired: true, PersonalAccounts: tenantdom.PersonalAccountsAllowed}, tenantdom.RoleMember, false, true},
		{"org 2fa for admins, admin", tenantdom.SecuritySettings{MFARequiredForAdmins: true, PersonalAccounts: tenantdom.PersonalAccountsAllowed}, tenantdom.RoleAdmin, false, true},
		{"org 2fa for admins, member", tenantdom.SecuritySettings{MFARequiredForAdmins: true, PersonalAccounts: tenantdom.PersonalAccountsAllowed}, tenantdom.RoleMember, false, false},
		{"personal allowed_with_mfa", tenantdom.SecuritySettings{PersonalAccounts: tenantdom.PersonalAccountsAllowedWithMFA}, tenantdom.RoleMember, true, true},
		{"personal allowed", none, tenantdom.RoleMember, true, false},
		{"outside admin, no org 2fa", none, tenantdom.RoleAdmin, true, true},
		{"outside member without privileges", none, tenantdom.RoleMember, true, false},
		{"inside admin, no org 2fa", none, tenantdom.RoleAdmin, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, uid := policyFixture(t, tc.sec, tc.role, "someone@gmail.com", tc.external)
			if got := s.mfaRequiredByAnyOrganization(context.Background(), uid); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

type mfaInvGrants struct {
	above bool
	err   error
}

func (g mfaInvGrants) HoldsAboveMember(context.Context, string, string) (bool, error) {
	return g.above, g.err
}

// A member whose base role is "member" but who holds an administrator-level
// grant is an administrator for "2FA required for admins": the login offers
// enrollment and the mint gate refuses a session without a factor.
func TestMFARequiredForAdmins_UsesEffectivePrivilege(t *testing.T) {
	sec := tenantdom.SecuritySettings{MFARequiredForAdmins: true, PersonalAccounts: tenantdom.PersonalAccountsAllowed}
	for _, tc := range []struct {
		name   string
		grants mfaInvGrants
		want   bool
	}{
		{"plain member", mfaInvGrants{}, false},
		{"member with an administrator RBAC role", mfaInvGrants{above: true}, true},
		{"grants lookup fails", mfaInvGrants{err: errors.New("db down")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, uid := policyFixture(t, sec, tenantdom.RoleMember, "x@corp.example", false)
			s.grants = tc.grants
			orgs := s.mfaRequiringOrganizations(context.Background(), uid)
			if got := len(orgs) > 0; got != tc.want {
				t.Fatalf("login: got %v (%v), want %v", got, orgs, tc.want)
			}
			if tc.want && (len(orgs) != 1 || orgs[0] != "Acme") {
				t.Fatalf("organizations = %v, want [Acme]", orgs)
			}
		})
	}
}

func TestEnforceMFAPolicy_EffectivePrivilege(t *testing.T) {
	sec := tenantdom.SecuritySettings{MFARequiredForAdmins: true, PersonalAccounts: tenantdom.PersonalAccountsAllowed}
	run := func(g mfaInvGrants, factor *mfa.Factor) error {
		s, uid := policyFixture(t, sec, tenantdom.RoleMember, "x@corp.example", false)
		s.grants = g
		s.mfaRepo = &mfaInvMFARepo{factor: factor}
		s.mfaEncryptor = mfaInvEncryptor{}
		sess, err := sessiondom.New(uid, "access", "", "", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return s.enforceMFAPolicy(context.Background(), sess, uid, s.tenantRepo.(*mfaInvTenantRepo).tenant.ID().String())
	}
	if err := run(mfaInvGrants{above: true}, nil); !errors.Is(err, ErrMFAEnrollmentRequired) {
		t.Fatalf("privileged member without a factor: err = %v", err)
	}
	if err := run(mfaInvGrants{above: true}, &mfa.Factor{Enabled: true}); err != nil {
		t.Fatalf("privileged member with a factor: err = %v", err)
	}
	if err := run(mfaInvGrants{}, nil); err != nil {
		t.Fatalf("plain member: err = %v", err)
	}
	if err := run(mfaInvGrants{err: errors.New("db down")}, nil); err == nil {
		t.Fatal("a failed grants lookup must refuse the token")
	}
}

func TestMFARequiredByAnyOrganization_FailsClosedOnMembershipError(t *testing.T) {
	s, uid := policyFixture(t, tenantdom.SecuritySettings{PersonalAccounts: tenantdom.PersonalAccountsAllowed}, tenantdom.RoleMember, "a@gmail.com", false)
	s.tenantRepo.(*mfaInvTenantRepo).getMemErr = errors.New("db down")
	if !s.mfaRequiredByAnyOrganization(context.Background(), uid) {
		t.Fatal("a failed membership lookup must count as required")
	}
}

// --- SessionMFAChallenge ---------------------------------------------

type mfaInvSessionRepo struct {
	sessiondom.Repository
	sess *sessiondom.Session
}

func (r *mfaInvSessionRepo) GetByID(context.Context, shared.ID) (*sessiondom.Session, error) {
	return r.sess, nil
}

type mfaInvRefreshRepo struct {
	sessiondom.RefreshTokenRepository
	tok *sessiondom.RefreshToken
}

func (r *mfaInvRefreshRepo) GetByTokenHash(context.Context, string) (*sessiondom.RefreshToken, error) {
	return r.tok, nil
}

type mfaInvUserRepo struct {
	userdom.Repository
	u *userdom.User
}

func (r *mfaInvUserRepo) GetByID(context.Context, shared.ID) (*userdom.User, error) { return r.u, nil }

type mfaInvMFARepo struct {
	mfa.Repository
	factor     *mfa.Factor
	challenges []*mfa.Challenge
}

func (r *mfaInvMFARepo) GetFactor(context.Context, shared.ID) (*mfa.Factor, error) {
	if r.factor == nil {
		return nil, mfa.ErrFactorNotFound
	}
	return r.factor, nil
}
func (r *mfaInvMFARepo) CreateChallenge(_ context.Context, c *mfa.Challenge) error {
	r.challenges = append(r.challenges, c)
	return nil
}

func challengeFixture(t *testing.T, federated bool, factor *mfa.Factor) (*AuthService, *mfaInvMFARepo, string) {
	t.Helper()
	return challengeFixtureAged(t, federated, factor, 0)
}

// challengeFixtureAged is challengeFixture with a session signed in `age` ago.
func challengeFixtureAged(t *testing.T, federated bool, factor *mfa.Factor, age time.Duration) (*AuthService, *mfaInvMFARepo, string) {
	t.Helper()
	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "0123456789abcdef0123456789abcdef", Issuer: "t", AccessTokenDuration: time.Minute, RefreshTokenDuration: time.Hour})
	u, err := userdom.New("new@gmail.com", "New")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := sessiondom.New(u.ID(), "access", "127.0.0.1", "ua", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if age > 0 {
		then := time.Now().Add(-age)
		sess = sessiondom.Reconstitute(sess.ID(), u.ID(), "access", "127.0.0.1", "ua", "", time.Now().Add(time.Hour),
			then, sessiondom.StatusActive, sessiondom.AuthMethodPassword, "", "", "", then, then)
	}
	if federated {
		sess.SetAuthMethod(sessiondom.AuthMethodSSO)
	}
	rt, _, err := gen.GenerateGlobalRefreshToken(u.ID().String(), u.Email(), u.Name(), sess.ID().String())
	if err != nil {
		t.Fatal(err)
	}
	stored, err := sessiondom.NewRefreshToken(u.ID(), sess.ID(), rt, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mr := &mfaInvMFARepo{factor: factor}
	s := &AuthService{
		logger:           logger.NewNop(),
		tokenGenerator:   gen,
		sessionRepo:      &mfaInvSessionRepo{sess: sess},
		refreshTokenRepo: &mfaInvRefreshRepo{tok: stored},
		userRepo:         &mfaInvUserRepo{u: u},
		mfaRepo:          mr,
		mfaEncryptor:     mfaInvEncryptor{},
	}
	return s, mr, rt
}

func TestSessionMFAChallenge(t *testing.T) {
	t.Run("no factor yet gets an enrollment challenge", func(t *testing.T) {
		s, mr, rt := challengeFixture(t, false, nil)
		info, err := s.SessionMFAChallenge(context.Background(), rt, "1.2.3.4", "ua")
		if err != nil {
			t.Fatal(err)
		}
		if info.Purpose != mfa.PurposeEnroll || info.Token == "" || len(mr.challenges) != 1 {
			t.Fatalf("got %+v, %d challenges", info, len(mr.challenges))
		}
	})
	t.Run("an enabled factor gets a verify challenge", func(t *testing.T) {
		s, _, rt := challengeFixture(t, false, &mfa.Factor{Enabled: true})
		info, err := s.SessionMFAChallenge(context.Background(), rt, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if info.Purpose != mfa.PurposeVerify {
			t.Fatalf("purpose = %q", info.Purpose)
		}
	})
	t.Run("a federated session is refused and no challenge is issued", func(t *testing.T) {
		s, mr, rt := challengeFixture(t, true, nil)
		if _, err := s.SessionMFAChallenge(context.Background(), rt, "", ""); !errors.Is(err, ErrMFAFederatedSession) {
			t.Fatalf("err = %v", err)
		}
		if len(mr.challenges) != 0 {
			t.Fatal("no challenge may be issued")
		}
	})
	t.Run("an old session cannot start enrollment: reauth required, no challenge", func(t *testing.T) {
		s, mr, rt := challengeFixtureAged(t, false, nil, sessionEnrollFreshness+time.Minute)
		if _, err := s.SessionMFAChallenge(context.Background(), rt, "", ""); !errors.Is(err, ErrReauthRequired) {
			t.Fatalf("err = %v", err)
		}
		if len(mr.challenges) != 0 {
			t.Fatal("no challenge may be issued")
		}
	})
	t.Run("a session just inside the window still enrolls", func(t *testing.T) {
		s, _, rt := challengeFixtureAged(t, false, nil, sessionEnrollFreshness-time.Minute)
		info, err := s.SessionMFAChallenge(context.Background(), rt, "", "")
		if err != nil || info.Purpose != mfa.PurposeEnroll {
			t.Fatalf("info=%+v err=%v", info, err)
		}
	})
	t.Run("an old session may still get a verify challenge", func(t *testing.T) {
		s, mr, rt := challengeFixtureAged(t, false, &mfa.Factor{Enabled: true}, 24*time.Hour)
		info, err := s.SessionMFAChallenge(context.Background(), rt, "", "")
		if err != nil || info.Purpose != mfa.PurposeVerify || len(mr.challenges) != 1 {
			t.Fatalf("info=%+v err=%v", info, err)
		}
	})
	t.Run("a bad refresh token is refused", func(t *testing.T) {
		s, mr, _ := challengeFixture(t, false, nil)
		if _, err := s.SessionMFAChallenge(context.Background(), "garbage", "", ""); err == nil {
			t.Fatal("want error")
		}
		if len(mr.challenges) != 0 {
			t.Fatal("no challenge may be issued")
		}
	})
	t.Run("2fa off on the server", func(t *testing.T) {
		s, _, rt := challengeFixture(t, false, nil)
		s.mfaRepo = nil
		if _, err := s.SessionMFAChallenge(context.Background(), rt, "", ""); !errors.Is(err, ErrMFAUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
}

type mfaInvEncryptor struct{}

func (mfaInvEncryptor) EncryptString(p string) (string, error) { return p, nil }
func (mfaInvEncryptor) DecryptString(e string) (string, error) { return e, nil }

// --- RefreshToken: a policy refusal never spends the token or mints ---

type mfaInvSpendRepo struct {
	mfaInvRefreshRepo
	spent   int
	created int
}

func (r *mfaInvSpendRepo) MarkUsedIfUnused(context.Context, shared.ID) (bool, error) {
	r.spent++
	return true, nil
}
func (r *mfaInvSpendRepo) RotateIfUnused(context.Context, shared.ID, string, *sessiondom.RefreshToken) (bool, error) {
	r.spent++
	r.created++
	return true, nil
}
func (r *mfaInvSpendRepo) Create(context.Context, *sessiondom.RefreshToken) error {
	r.created++
	return nil
}

// A token refused by the 2FA policy is not spent and creates no new refresh
// token, so it can never be replayed into a session without the policy
// passing; the policy runs again on every presentation.
func TestRefreshToken_PolicyRefusalSpendsNothing(t *testing.T) {
	s, mr, rt := challengeFixture(t, false, nil)
	_ = mr
	tn, err := tenantdom.NewTenant("Acme", "acme", "creator")
	if err != nil {
		t.Fatal(err)
	}
	if err := tn.UpdateSecuritySettings(tenantdom.SecuritySettings{MFARequired: true}); err != nil {
		t.Fatal(err)
	}
	uid := s.userRepo.(*mfaInvUserRepo).u.ID()
	m, err := tenantdom.NewMembership(uid, tn.ID(), tenantdom.RoleMember, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.tenantRepo = &mfaInvTenantRepo{tenant: tn, role: tenantdom.RoleMember, membership: m}
	spend := &mfaInvSpendRepo{mfaInvRefreshRepo: *s.refreshTokenRepo.(*mfaInvRefreshRepo)}
	s.refreshTokenRepo = spend
	for i := 0; i < 2; i++ {
		_, err = s.RefreshToken(context.Background(), RefreshTokenInput{RefreshToken: rt, TenantID: tn.ID().String()})
		if !errors.Is(err, ErrMFAEnrollmentRequired) {
			t.Fatalf("attempt %d: err = %v", i, err)
		}
	}
	if spend.spent != 0 || spend.created != 0 {
		t.Fatalf("spent=%d created=%d, want 0/0", spend.spent, spend.created)
	}
}
